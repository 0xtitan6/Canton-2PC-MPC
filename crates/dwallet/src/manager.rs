//! dWallet Manager - orchestrates wallet creation, signing, and chain interactions

use crate::chain_adapter::{ChainAdapter, ChainType};
use crate::wallet::{DWallet, DWalletConfig};
use crate::{DWalletError, Result};
use mpc_protocol::types::DWalletId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages dWallets and coordinates with the MPC protocol
pub struct DWalletManager {
    /// Active wallets
    wallets: Arc<RwLock<HashMap<DWalletId, DWallet>>>,
    /// Chain adapters for signing and transaction building
    chain_adapters: HashMap<ChainType, Box<dyn ChainAdapter>>,
    /// MPC protocol instance
    protocol: Option<Arc<mpc_protocol::TwoPcMpc>>,
}

impl DWalletManager {
    /// Create a new dWallet manager
    pub fn new() -> Self {
        Self {
            wallets: Arc::new(RwLock::new(HashMap::new())),
            chain_adapters: HashMap::new(),
            protocol: None,
        }
    }

    /// Set the MPC protocol instance
    pub fn with_protocol(mut self, protocol: Arc<mpc_protocol::TwoPcMpc>) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Register a chain adapter
    pub fn register_chain(&mut self, chain_type: ChainType, adapter: Box<dyn ChainAdapter>) {
        self.chain_adapters.insert(chain_type, adapter);
    }

    /// Create a new dWallet
    pub async fn create_wallet(&self, config: DWalletConfig) -> Result<DWalletId> {
        let protocol = self.protocol.as_ref()
            .ok_or_else(|| DWalletError::ConfigError("MPC protocol not configured".into()))?;

        // Create DKG request
        let request = mpc_protocol::types::CreateDWalletRequest {
            signature_type: config.signature_type,
            threshold: config.threshold,
            user_commitment: Vec::new(), // Will be filled by DKG
            metadata: config.metadata.clone(),
        };

        // Run DKG to create the wallet
        let dwallet_id = protocol.create_dwallet(request).await?;

        // Wait for DKG to complete and get public key
        let wallet_state = protocol.get_wallet(&dwallet_id).await
            .ok_or_else(|| DWalletError::WalletNotFound(dwallet_id.0.clone()))?;

        let public_key = wallet_state.public_key
            .ok_or_else(|| DWalletError::ProtocolError(
                mpc_protocol::MpcError::DkgFailed("Public key not generated".into())
            ))?;

        // Create the dWallet
        let dwallet = DWallet::new(
            dwallet_id.clone(),
            config,
            wallet_state.user_share,
            public_key,
        )?;

        // Store the wallet
        self.wallets.write().await.insert(dwallet_id.clone(), dwallet);

        Ok(dwallet_id)
    }

    /// Get a wallet by ID
    pub async fn get_wallet(&self, id: &DWalletId) -> Option<DWallet> {
        self.wallets.read().await.get(id).cloned()
    }

    /// List all wallets
    pub async fn list_wallets(&self) -> Vec<DWallet> {
        self.wallets.read().await.values().cloned().collect()
    }

    /// Sign a message with a dWallet
    pub async fn sign(
        &self,
        wallet_id: &DWalletId,
        chain: &str,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let protocol = self.protocol.as_ref()
            .ok_or_else(|| DWalletError::ConfigError("MPC protocol not configured".into()))?;

        // Get the wallet
        let mut wallets = self.wallets.write().await;
        let wallet = wallets.get_mut(wallet_id)
            .ok_or_else(|| DWalletError::WalletNotFound(wallet_id.0.clone()))?;

        // Verify chain support
        if !wallet.supports_chain(chain) {
            return Err(DWalletError::UnsupportedChain(chain.to_string()));
        }

        // Get user's share
        let user_share = wallet.user_share()
            .ok_or_else(|| DWalletError::SigningError("User share not available".into()))?;

        // Create signing request
        let mut user_signer = mpc_protocol::signing::UserSigner::new(user_share.clone());
        let nonce_commitment = user_signer.generate_nonce()?;

        let sign_request = mpc_protocol::types::SignRequest {
            dwallet_id: wallet_id.clone(),
            message: message.to_vec(),
            user_nonce_commitment: nonce_commitment,
            metadata: HashMap::new(),
        };

        // Initiate signing session
        let session_id = protocol.sign(sign_request).await?;

        // Wait for signing to complete
        loop {
            let status = protocol.get_session_status(&session_id).await;
            match status {
                Some(mpc_protocol::types::SigningState::Completed) => break,
                Some(mpc_protocol::types::SigningState::Failed) => {
                    return Err(DWalletError::SigningError("Signing failed".into()));
                }
                Some(mpc_protocol::types::SigningState::TimedOut) => {
                    return Err(DWalletError::SigningError("Signing timed out".into()));
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        // Get the signature
        let result = protocol.get_signing_result(&session_id).await
            .ok_or_else(|| DWalletError::SigningError("Signature not available".into()))?;

        // Mark wallet as used
        wallet.mark_used();

        Ok(result.signature)
    }

    /// Build and sign a transaction for a specific chain
    pub async fn build_and_sign_transaction(
        &self,
        wallet_id: &DWalletId,
        chain_type: ChainType,
        params: TransactionParams,
    ) -> Result<SignedTransaction> {
        // Get chain adapter
        let adapter = self.chain_adapters.get(&chain_type)
            .ok_or_else(|| DWalletError::UnsupportedChain(format!("{:?}", chain_type)))?;

        // Get wallet
        let wallet = self.get_wallet(wallet_id).await
            .ok_or_else(|| DWalletError::WalletNotFound(wallet_id.0.clone()))?;

        // Build unsigned transaction
        let unsigned_tx = adapter.build_transaction(&wallet, &params)?;

        // Get the signing hash
        let sighash = adapter.get_sighash(&unsigned_tx)?;

        // Sign
        let signature = self.sign(wallet_id, &params.chain, &sighash).await?;

        // Apply signature
        let signed_tx = adapter.apply_signature(&unsigned_tx, &signature)?;
        let tx_hash = adapter.compute_tx_hash(&signed_tx)?;

        Ok(SignedTransaction {
            chain: params.chain,
            raw_transaction: signed_tx,
            tx_hash,
        })
    }
}

impl Default for DWalletManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parameters for building a transaction
#[derive(Debug, Clone)]
pub struct TransactionParams {
    /// Target chain
    pub chain: String,
    /// Recipient address
    pub to: String,
    /// Amount to transfer (chain-specific units)
    pub amount: u128,
    /// Additional data (for contract calls, etc.)
    pub data: Option<Vec<u8>>,
    /// Gas/fee parameters
    pub fee_params: Option<FeeParams>,
}

/// Fee parameters for transactions
#[derive(Debug, Clone)]
pub struct FeeParams {
    /// Gas price (for EVM chains) or fee rate (for Bitcoin)
    pub gas_price: Option<u128>,
    /// Gas limit (for EVM chains)
    pub gas_limit: Option<u64>,
    /// Max priority fee (for EIP-1559)
    pub max_priority_fee: Option<u128>,
    /// Max fee (for EIP-1559)
    pub max_fee: Option<u128>,
}

/// A signed transaction ready for broadcast
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Chain the transaction is for
    pub chain: String,
    /// Raw signed transaction bytes
    pub raw_transaction: Vec<u8>,
    /// Transaction hash
    pub tx_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manager_creation() {
        let manager = DWalletManager::new();
        let wallets = manager.list_wallets().await;
        assert!(wallets.is_empty());
    }
}
