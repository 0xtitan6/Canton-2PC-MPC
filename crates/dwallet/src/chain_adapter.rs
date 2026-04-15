//! Chain adapters for building and signing transactions on different chains

use crate::manager::TransactionParams;
use crate::wallet::DWallet;
use crate::Result;

/// Supported chain types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainType {
    Bitcoin,
    BitcoinTaproot,
    Ethereum,
    Polygon,
    Arbitrum,
    Optimism,
    Base,
    Avalanche,
    Bsc,
    Solana,
}

impl ChainType {
    /// Get the chain identifier string
    pub fn chain_id(&self) -> &'static str {
        match self {
            ChainType::Bitcoin => "bitcoin",
            ChainType::BitcoinTaproot => "bitcoin-taproot",
            ChainType::Ethereum => "ethereum",
            ChainType::Polygon => "polygon",
            ChainType::Arbitrum => "arbitrum",
            ChainType::Optimism => "optimism",
            ChainType::Base => "base",
            ChainType::Avalanche => "avalanche",
            ChainType::Bsc => "bsc",
            ChainType::Solana => "solana",
        }
    }

    /// Get EVM chain ID (for EVM chains)
    pub fn evm_chain_id(&self) -> Option<u64> {
        match self {
            ChainType::Ethereum => Some(1),
            ChainType::Polygon => Some(137),
            ChainType::Arbitrum => Some(42161),
            ChainType::Optimism => Some(10),
            ChainType::Base => Some(8453),
            ChainType::Avalanche => Some(43114),
            ChainType::Bsc => Some(56),
            _ => None,
        }
    }

    /// Check if this is an EVM chain
    pub fn is_evm(&self) -> bool {
        self.evm_chain_id().is_some()
    }
}

/// Trait for chain-specific transaction building and signing
pub trait ChainAdapter: Send + Sync {
    /// Build an unsigned transaction
    fn build_transaction(
        &self,
        wallet: &DWallet,
        params: &TransactionParams,
    ) -> Result<Vec<u8>>;

    /// Get the hash/message to sign
    fn get_sighash(&self, unsigned_tx: &[u8]) -> Result<Vec<u8>>;

    /// Apply a signature to the transaction
    fn apply_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>>;

    /// Compute the transaction hash
    fn compute_tx_hash(&self, signed_tx: &[u8]) -> Result<String>;

    /// Get the chain type
    fn chain_type(&self) -> ChainType;
}

/// Bitcoin chain adapter
pub struct BitcoinAdapter {
    network: chain_bitcoin::Network,
    use_taproot: bool,
}

impl BitcoinAdapter {
    pub fn new(network: chain_bitcoin::Network, use_taproot: bool) -> Self {
        Self { network, use_taproot }
    }
}

impl ChainAdapter for BitcoinAdapter {
    fn build_transaction(
        &self,
        wallet: &DWallet,
        params: &TransactionParams,
    ) -> Result<Vec<u8>> {
        use chain_bitcoin::transaction::Transaction;

        // Create a simple transaction (would need UTXO inputs in production)
        let tx = Transaction::new();

        // Serialize for signing
        Ok(tx.serialize())
    }

    fn get_sighash(&self, unsigned_tx: &[u8]) -> Result<Vec<u8>> {
        // Compute sighash based on transaction type
        Ok(crypto_core::hash::hash256(unsigned_tx).to_vec())
    }

    fn apply_signature(&self, unsigned_tx: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        // Apply signature to transaction
        let mut signed = unsigned_tx.to_vec();
        signed.extend_from_slice(signature);
        Ok(signed)
    }

    fn compute_tx_hash(&self, signed_tx: &[u8]) -> Result<String> {
        let hash = crypto_core::hash::hash256(signed_tx);
        Ok(hex::encode(hash))
    }

    fn chain_type(&self) -> ChainType {
        if self.use_taproot {
            ChainType::BitcoinTaproot
        } else {
            ChainType::Bitcoin
        }
    }
}

/// Ethereum/EVM chain adapter
pub struct EthereumAdapter {
    chain_id: u64,
    chain_type: ChainType,
}

impl EthereumAdapter {
    pub fn new(chain_type: ChainType) -> Self {
        let chain_id = chain_type.evm_chain_id().unwrap_or(1);
        Self { chain_id, chain_type }
    }

    pub fn mainnet() -> Self {
        Self::new(ChainType::Ethereum)
    }

    pub fn polygon() -> Self {
        Self::new(ChainType::Polygon)
    }
}

impl ChainAdapter for EthereumAdapter {
    fn build_transaction(
        &self,
        wallet: &DWallet,
        params: &TransactionParams,
    ) -> Result<Vec<u8>> {
        use chain_ethereum::address::Address;
        use chain_ethereum::transaction::Transaction;
        use chain_ethereum::Wei;

        let to = Address::from_hex(&params.to)
            .map_err(|e| crate::DWalletError::ConfigError(e.to_string()))?;

        // Build EIP-1559 transaction
        let fee = params.fee_params.as_ref();
        let tx = Transaction::eip1559(
            self.chain_id,
            0, // nonce - would be fetched from chain
            Wei::from_gwei(fee.and_then(|f| f.max_priority_fee).unwrap_or(2) as u64),
            Wei::from_gwei(fee.and_then(|f| f.max_fee).unwrap_or(100) as u64),
            fee.and_then(|f| f.gas_limit).unwrap_or(21000),
            Some(to),
            Wei::from_wei(params.amount),
            params.data.clone().unwrap_or_default(),
        );

        Ok(tx.signing_hash().to_vec())
    }

    fn get_sighash(&self, unsigned_tx: &[u8]) -> Result<Vec<u8>> {
        // For EVM, build_transaction already returns the hash
        Ok(unsigned_tx.to_vec())
    }

    fn apply_signature(&self, _unsigned_tx: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        // In production, would properly encode the signed transaction
        Ok(signature.to_vec())
    }

    fn compute_tx_hash(&self, signed_tx: &[u8]) -> Result<String> {
        let hash = crypto_core::hash::keccak256(signed_tx);
        Ok(format!("0x{}", hex::encode(hash)))
    }

    fn chain_type(&self) -> ChainType {
        self.chain_type
    }
}

/// Solana chain adapter
pub struct SolanaAdapter {
    network: chain_solana::Network,
}

impl SolanaAdapter {
    pub fn new(network: chain_solana::Network) -> Self {
        Self { network }
    }

    pub fn mainnet() -> Self {
        Self::new(chain_solana::Network::Mainnet)
    }

    pub fn devnet() -> Self {
        Self::new(chain_solana::Network::Devnet)
    }
}

impl ChainAdapter for SolanaAdapter {
    fn build_transaction(
        &self,
        wallet: &DWallet,
        params: &TransactionParams,
    ) -> Result<Vec<u8>> {
        use chain_solana::address::Pubkey;
        use chain_solana::transaction::{system_instruction, Transaction};
        use chain_solana::Lamports;

        let from_addr = wallet.address("solana")
            .ok_or_else(|| crate::DWalletError::UnsupportedChain("solana".into()))?;

        let from = Pubkey::from_base58(from_addr)
            .map_err(|e| crate::DWalletError::ConfigError(e.to_string()))?;

        let to = Pubkey::from_base58(&params.to)
            .map_err(|e| crate::DWalletError::ConfigError(e.to_string()))?;

        let instruction = system_instruction::transfer(
            &from,
            &to,
            Lamports::from_lamports(params.amount as u64),
        );

        let blockhash = [0u8; 32]; // Would be fetched from chain
        let tx = Transaction::new(&[instruction], &from, blockhash);

        Ok(tx.message_data())
    }

    fn get_sighash(&self, unsigned_tx: &[u8]) -> Result<Vec<u8>> {
        // Solana signs the message directly (no hashing)
        Ok(unsigned_tx.to_vec())
    }

    fn apply_signature(&self, unsigned_tx: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        // Number of signatures
        result.push(1);
        // Signature
        result.extend_from_slice(signature);
        // Message
        result.extend_from_slice(unsigned_tx);
        Ok(result)
    }

    fn compute_tx_hash(&self, signed_tx: &[u8]) -> Result<String> {
        // Solana uses the first signature as the transaction ID
        if signed_tx.len() > 65 {
            Ok(bs58::encode(&signed_tx[1..65]).into_string())
        } else {
            Ok(bs58::encode(signed_tx).into_string())
        }
    }

    fn chain_type(&self) -> ChainType {
        ChainType::Solana
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_types() {
        assert!(ChainType::Ethereum.is_evm());
        assert!(ChainType::Polygon.is_evm());
        assert!(!ChainType::Bitcoin.is_evm());
        assert!(!ChainType::Solana.is_evm());
    }

    #[test]
    fn test_evm_chain_ids() {
        assert_eq!(ChainType::Ethereum.evm_chain_id(), Some(1));
        assert_eq!(ChainType::Polygon.evm_chain_id(), Some(137));
        assert_eq!(ChainType::Bitcoin.evm_chain_id(), None);
    }
}
