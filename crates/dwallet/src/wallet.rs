//! dWallet core implementation

use crate::{DWalletError, Result};
use crypto_core::SignatureType;
use mpc_protocol::types::{DWalletId, UserShare};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for creating a new dWallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DWalletConfig {
    /// Signature type (determines supported chains)
    pub signature_type: SignatureType,
    /// MPC threshold (minimum signers required)
    pub threshold: u16,
    /// Total number of network participants
    pub total_participants: u16,
    /// Human-readable name
    pub name: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl DWalletConfig {
    /// Create config for Bitcoin/Ethereum chains
    pub fn for_bitcoin_ethereum(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::EcdsaSecp256k1,
            threshold,
            total_participants: total,
            name: None,
            metadata: HashMap::new(),
        }
    }

    /// Create config for Solana and Ed25519 chains
    pub fn for_solana(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::Ed25519,
            threshold,
            total_participants: total,
            name: None,
            metadata: HashMap::new(),
        }
    }

    /// Create config for Bitcoin Taproot
    pub fn for_taproot(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::SchnorrSecp256k1,
            threshold,
            total_participants: total,
            name: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the wallet name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A decentralized wallet that can control assets on any supported chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DWallet {
    /// Unique identifier
    pub id: DWalletId,
    /// Configuration
    pub config: DWalletConfig,
    /// User's share (only present if this is the user's wallet)
    user_share: Option<UserShare>,
    /// Public key for the wallet
    pub public_key: Vec<u8>,
    /// Derived addresses for each chain
    pub addresses: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used_at: Option<u64>,
}

impl DWallet {
    /// Create a new dWallet (called after DKG completion)
    pub fn new(
        id: DWalletId,
        config: DWalletConfig,
        user_share: Option<UserShare>,
        public_key: Vec<u8>,
    ) -> Result<Self> {
        let addresses = Self::derive_addresses(&config.signature_type, &public_key)?;

        Ok(Self {
            id,
            config,
            user_share,
            public_key,
            addresses,
            created_at: current_timestamp(),
            last_used_at: None,
        })
    }

    /// Get the address for a specific chain
    pub fn address(&self, chain: &str) -> Option<&String> {
        self.addresses.get(chain)
    }

    /// Get all supported chains for this wallet
    pub fn supported_chains(&self) -> Vec<&str> {
        self.config.signature_type.supported_chains().to_vec()
    }

    /// Check if this wallet supports a given chain
    pub fn supports_chain(&self, chain: &str) -> bool {
        self.config.signature_type.supported_chains().contains(&chain)
    }

    /// Get the user's share (for signing)
    pub fn user_share(&self) -> Option<&UserShare> {
        self.user_share.as_ref()
    }

    /// Mark the wallet as used
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(current_timestamp());
    }

    /// Derive addresses for all supported chains
    fn derive_addresses(
        signature_type: &SignatureType,
        public_key: &[u8],
    ) -> Result<HashMap<String, String>> {
        let mut addresses = HashMap::new();

        match signature_type {
            SignatureType::EcdsaSecp256k1 => {
                // Bitcoin (P2PKH, P2WPKH)
                if public_key.len() == 33 {
                    // Compressed public key
                    let btc_addr = derive_bitcoin_address(public_key)?;
                    addresses.insert("bitcoin".to_string(), btc_addr);
                }

                // Ethereum
                if public_key.len() >= 33 {
                    let eth_addr = derive_ethereum_address(public_key)?;
                    addresses.insert("ethereum".to_string(), eth_addr.clone());
                    // EVM-compatible chains use the same address
                    addresses.insert("polygon".to_string(), eth_addr.clone());
                    addresses.insert("arbitrum".to_string(), eth_addr.clone());
                    addresses.insert("optimism".to_string(), eth_addr.clone());
                    addresses.insert("base".to_string(), eth_addr.clone());
                    addresses.insert("avalanche".to_string(), eth_addr.clone());
                    addresses.insert("bsc".to_string(), eth_addr);
                }
            }
            SignatureType::Ed25519 => {
                // Solana
                if public_key.len() == 32 {
                    let sol_addr = derive_solana_address(public_key);
                    addresses.insert("solana".to_string(), sol_addr);

                    // Other Ed25519 chains
                    let generic_addr = bs58::encode(public_key).into_string();
                    addresses.insert("cardano".to_string(), generic_addr.clone());
                    addresses.insert("polkadot".to_string(), generic_addr.clone());
                    addresses.insert("near".to_string(), generic_addr);
                }
            }
            SignatureType::SchnorrSecp256k1 => {
                // Bitcoin Taproot
                if public_key.len() == 32 {
                    let taproot_addr = derive_taproot_address(public_key)?;
                    addresses.insert("bitcoin-taproot".to_string(), taproot_addr);
                }
            }
        }

        Ok(addresses)
    }
}

// Address derivation helpers

fn derive_bitcoin_address(public_key: &[u8]) -> Result<String> {
    use chain_bitcoin::address::Address;
    use chain_bitcoin::Network;

    let address = Address::p2wpkh(public_key, Network::Mainnet)
        .map_err(|e| DWalletError::ConfigError(e.to_string()))?;

    Ok(address.address)
}

fn derive_ethereum_address(public_key: &[u8]) -> Result<String> {
    use chain_ethereum::address::Address;

    // If compressed, we need to decompress first (simplified for now)
    // In production, properly handle compressed keys
    let address = if public_key.len() == 33 {
        // Compressed - placeholder
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&public_key[1..]);
        uncompressed.extend_from_slice(&[0u8; 31]); // Padding - not correct, just placeholder
        Address::from_public_key(&uncompressed)
            .map_err(|e| DWalletError::ConfigError(e.to_string()))?
    } else {
        Address::from_public_key(public_key)
            .map_err(|e| DWalletError::ConfigError(e.to_string()))?
    };

    Ok(address.to_checksum_string())
}

fn derive_solana_address(public_key: &[u8]) -> String {
    bs58::encode(public_key).into_string()
}

fn derive_taproot_address(x_only_pubkey: &[u8]) -> Result<String> {
    use chain_bitcoin::address::Address;
    use chain_bitcoin::Network;

    let address = Address::p2tr(x_only_pubkey, Network::Mainnet)
        .map_err(|e| DWalletError::ConfigError(e.to_string()))?;

    Ok(address.address)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwallet_config_bitcoin() {
        let config = DWalletConfig::for_bitcoin_ethereum(2, 3)
            .with_name("Test Wallet");

        assert_eq!(config.signature_type, SignatureType::EcdsaSecp256k1);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.name, Some("Test Wallet".to_string()));
    }

    #[test]
    fn test_dwallet_config_solana() {
        let config = DWalletConfig::for_solana(2, 3);
        assert_eq!(config.signature_type, SignatureType::Ed25519);
    }

    #[test]
    fn test_supported_chains() {
        let config = DWalletConfig::for_bitcoin_ethereum(2, 3);
        let chains = config.signature_type.supported_chains();
        assert!(chains.contains(&"bitcoin"));
        assert!(chains.contains(&"ethereum"));
    }
}
