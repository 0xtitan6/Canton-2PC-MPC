//! # Bitcoin Chain Support
//!
//! This module provides Bitcoin-specific functionality for the Canton 2PC-MPC system,
//! enabling native Bitcoin to be controlled by Canton smart contracts.
//!
//! ## Features
//!
//! - **Legacy addresses**: P2PKH, P2SH support via ECDSA
//! - **SegWit addresses**: P2WPKH, P2WSH support
//! - **Taproot addresses**: P2TR support via Schnorr signatures
//! - **Transaction building**: Construct and serialize Bitcoin transactions
//! - **PSBT support**: Partially Signed Bitcoin Transactions for MPC signing

pub mod address;
pub mod transaction;
pub mod psbt;
pub mod signer;

use crypto_core::SignatureType;
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Bitcoin-specific errors
#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto_core::CryptoError),
}

pub type Result<T> = std::result::Result<T, BitcoinError>;

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Local regtest
    Regtest,
}

impl Network {
    /// Get the address prefix for P2PKH addresses
    pub fn p2pkh_prefix(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Signet | Network::Regtest => 0x6F,
        }
    }

    /// Get the address prefix for P2SH addresses
    pub fn p2sh_prefix(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Signet | Network::Regtest => 0xC4,
        }
    }

    /// Get the bech32 HRP for SegWit addresses
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Signet => "tb",
            Network::Regtest => "bcrt",
        }
    }
}

/// Signature type to use for Bitcoin transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinSignatureType {
    /// ECDSA for legacy and SegWit v0
    Ecdsa,
    /// Schnorr for Taproot (SegWit v1)
    Schnorr,
}

impl From<BitcoinSignatureType> for SignatureType {
    fn from(bst: BitcoinSignatureType) -> Self {
        match bst {
            BitcoinSignatureType::Ecdsa => SignatureType::EcdsaSecp256k1,
            BitcoinSignatureType::Schnorr => SignatureType::SchnorrSecp256k1,
        }
    }
}

/// Bitcoin amount in satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// Create amount from satoshis
    pub fn from_sat(sat: u64) -> Self {
        Self(sat)
    }

    /// Create amount from BTC
    pub fn from_btc(btc: f64) -> Self {
        Self((btc * 100_000_000.0) as u64)
    }

    /// Get amount in satoshis
    pub fn as_sat(&self) -> u64 {
        self.0
    }

    /// Get amount in BTC
    pub fn as_btc(&self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }
}

impl std::ops::Add for Amount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Amount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}
