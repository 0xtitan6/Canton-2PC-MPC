//! Canton 2PC-MPC Service - main entry point

use crate::daml_types::*;
use crate::ledger_api::{LedgerClient, LedgerEventHandler};
use crate::{CantonConfig, CantonError, Result};
use async_trait::async_trait;
use dwallet::{DWalletConfig, DWalletManager};
use mpc_protocol::types::DWalletId;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main service that orchestrates Canton integration with 2PC-MPC
pub struct CantonMpcService {
    /// Configuration
    config: CantonConfig,
    /// Ledger API client
    ledger_client: LedgerClient,
    /// dWallet manager
    dwallet_manager: Arc<DWalletManager>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl CantonMpcService {
    /// Create a new Canton MPC service
    pub fn new(config: CantonConfig, dwallet_manager: Arc<DWalletManager>) -> Self {
        let ledger_client = LedgerClient::new(config.clone());

        Self {
            config,
            ledger_client,
            dwallet_manager,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the service
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting Canton 2PC-MPC service");

        // Connect to ledger
        self.ledger_client.connect().await?;

        // Mark as running
        *self.running.write().await = true;

        // In production, start event listener loop
        tracing::info!("Canton 2PC-MPC service started");

        Ok(())
    }

    /// Stop the service
    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping Canton 2PC-MPC service");
        *self.running.write().await = false;
        Ok(())
    }

    /// Check if service is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Create a new dWallet
    pub async fn create_dwallet(
        &self,
        signature_type: &str,
        threshold: u32,
    ) -> Result<DWalletContract> {
        // Create on Canton ledger
        let request = CreateDWalletRequest {
            owner: self.config.party_id.clone(),
            signature_type: signature_type.to_string(),
            threshold,
            metadata: std::collections::HashMap::new(),
        };

        let mut contract = self.ledger_client.create_dwallet(request).await?;

        // Create in MPC layer
        let dwallet_config = match signature_type {
            "ecdsa_secp256k1" => DWalletConfig::for_bitcoin_ethereum(threshold as u16, 3),
            "ed25519" => DWalletConfig::for_solana(threshold as u16, 3),
            "schnorr_secp256k1" => DWalletConfig::for_taproot(threshold as u16, 3),
            _ => return Err(CantonError::Config(format!("Unknown signature type: {}", signature_type))),
        };

        let dwallet_id = self.dwallet_manager.create_wallet(dwallet_config).await?;

        // Update contract with dWallet info
        if let Some(dwallet) = self.dwallet_manager.get_wallet(&dwallet_id).await {
            contract.dwallet_id = dwallet_id.0.clone();
            contract.public_key = hex::encode(&dwallet.public_key);
            contract.addresses = dwallet.addresses.clone();
            contract.status = DWalletStatus::Active;
        }

        Ok(contract)
    }

    /// Sign a message using a dWallet
    pub async fn sign(
        &self,
        dwallet_id: &str,
        chain: &str,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        // Submit sign request to Canton
        let sign_request = self
            .ledger_client
            .submit_sign_request(dwallet_id, chain, message)
            .await?;

        // Perform MPC signing
        let dwallet_id = DWalletId(dwallet_id.to_string());
        let signature = self.dwallet_manager.sign(&dwallet_id, chain, message).await?;

        // Complete the sign request on Canton
        self.ledger_client
            .complete_sign_request(&sign_request.request_id, &signature)
            .await?;

        Ok(signature)
    }

    /// Execute a cross-chain transfer
    pub async fn transfer(
        &self,
        dwallet_id: &str,
        chain: &str,
        destination: &str,
        amount: &str,
        asset: &str,
    ) -> Result<TransferRequest> {
        // Submit transfer request to Canton
        let mut request = self
            .ledger_client
            .submit_transfer(dwallet_id, chain, destination, amount, asset)
            .await?;

        // Build and sign transaction
        let dwallet_id_obj = DWalletId(dwallet_id.to_string());

        // Get chain adapter and build transaction
        let params = dwallet::manager::TransactionParams {
            chain: chain.to_string(),
            to: destination.to_string(),
            amount: amount.parse().unwrap_or(0),
            data: None,
            fee_params: None,
        };

        let chain_type = match chain {
            "bitcoin" => dwallet::ChainType::Bitcoin,
            "ethereum" => dwallet::ChainType::Ethereum,
            "solana" => dwallet::ChainType::Solana,
            _ => return Err(CantonError::Config(format!("Unsupported chain: {}", chain))),
        };

        let signed_tx = self
            .dwallet_manager
            .build_and_sign_transaction(&dwallet_id_obj, chain_type, params)
            .await?;

        // Update request with transaction hash
        request.status = TransferStatus::Complete;
        request.tx_hash = Some(signed_tx.tx_hash);

        // Update on Canton ledger
        self.ledger_client
            .update_transfer_status(
                &request.request_id,
                TransferStatus::Complete,
                request.tx_hash.as_deref(),
            )
            .await?;

        Ok(request)
    }

    /// Get dWallet details
    pub async fn get_dwallet(&self, dwallet_id: &str) -> Result<Option<DWalletContract>> {
        self.ledger_client.get_dwallet(dwallet_id).await
    }

    /// List all dWallets for the current party
    pub async fn list_dwallets(&self) -> Result<Vec<DWalletContract>> {
        self.ledger_client.list_dwallets(&self.config.party_id).await
    }
}

#[async_trait]
impl LedgerEventHandler for CantonMpcService {
    async fn on_dwallet_created(&self, contract: &DWalletContract) -> Result<()> {
        tracing::info!("dWallet created: {}", contract.dwallet_id);
        Ok(())
    }

    async fn on_sign_requested(&self, request: &SignRequest) -> Result<()> {
        tracing::info!("Sign request received: {}", request.request_id);

        // Auto-process sign requests
        let message = hex::decode(&request.message)
            .map_err(|e| CantonError::Contract(e.to_string()))?;

        let signature = self.sign(&request.dwallet_id, &request.chain, &message).await?;

        tracing::info!(
            "Sign request {} completed with signature: {}",
            request.request_id,
            hex::encode(&signature)
        );

        Ok(())
    }

    async fn on_transfer_requested(&self, request: &TransferRequest) -> Result<()> {
        tracing::info!("Transfer request received: {}", request.request_id);

        let result = self
            .transfer(
                &request.dwallet_id,
                &request.source_chain,
                &request.destination,
                &request.amount,
                &request.asset,
            )
            .await?;

        tracing::info!(
            "Transfer {} completed with tx hash: {:?}",
            request.request_id,
            result.tx_hash
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_lifecycle() {
        let config = CantonConfig::default();
        let dwallet_manager = Arc::new(DWalletManager::new());
        let service = CantonMpcService::new(config, dwallet_manager);

        assert!(!service.is_running().await);

        service.start().await.unwrap();
        assert!(service.is_running().await);

        service.stop().await.unwrap();
        assert!(!service.is_running().await);
    }
}
