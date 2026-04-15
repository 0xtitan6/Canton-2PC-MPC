//! # Ethereum Chain Support
//!
//! This module provides Ethereum and EVM-compatible chain functionality
//! for the Canton 2PC-MPC system, enabling native ETH and ERC-20 tokens
//! to be controlled by Canton smart contracts.
//!
//! ## Features
//!
//! - **Address derivation**: From ECDSA public keys
//! - **Transaction building**: Legacy, EIP-1559, and EIP-2930 transactions
//! - **Message signing**: EIP-191 personal sign and EIP-712 typed data
//! - **Contract interaction**: ABI encoding/decoding for ERC-20, etc.

pub mod address;
pub mod transaction;
pub mod signer;
pub mod erc20;

use crypto_core::SignatureType;
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Ethereum-specific errors
#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("ABI encoding error: {0}")]
    AbiError(String),

    #[error("RLP encoding error: {0}")]
    RlpError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto_core::CryptoError),
}

pub type Result<T> = std::result::Result<T, EthereumError>;

/// Ethereum network/chain IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Ethereum mainnet
    Mainnet = 1,
    /// Goerli testnet
    Goerli = 5,
    /// Sepolia testnet
    Sepolia = 11155111,
    /// Polygon mainnet
    Polygon = 137,
    /// Arbitrum One
    Arbitrum = 42161,
    /// Optimism
    Optimism = 10,
    /// Base
    Base = 8453,
    /// Avalanche C-Chain
    Avalanche = 43114,
    /// BNB Smart Chain
    Bsc = 56,
}

impl Network {
    pub fn chain_id(&self) -> u64 {
        *self as u64
    }

    pub fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "Ethereum Mainnet",
            Network::Goerli => "Goerli Testnet",
            Network::Sepolia => "Sepolia Testnet",
            Network::Polygon => "Polygon",
            Network::Arbitrum => "Arbitrum One",
            Network::Optimism => "Optimism",
            Network::Base => "Base",
            Network::Avalanche => "Avalanche C-Chain",
            Network::Bsc => "BNB Smart Chain",
        }
    }

    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Network::Mainnet),
            5 => Some(Network::Goerli),
            11155111 => Some(Network::Sepolia),
            137 => Some(Network::Polygon),
            42161 => Some(Network::Arbitrum),
            10 => Some(Network::Optimism),
            8453 => Some(Network::Base),
            43114 => Some(Network::Avalanche),
            56 => Some(Network::Bsc),
            _ => None,
        }
    }
}

/// Wei amount (smallest unit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Wei(pub u128);

impl Wei {
    pub fn from_wei(wei: u128) -> Self {
        Self(wei)
    }

    pub fn from_gwei(gwei: u64) -> Self {
        Self(gwei as u128 * 1_000_000_000)
    }

    pub fn from_eth(eth: f64) -> Self {
        Self((eth * 1e18) as u128)
    }

    pub fn as_wei(&self) -> u128 {
        self.0
    }

    pub fn as_gwei(&self) -> u64 {
        (self.0 / 1_000_000_000) as u64
    }

    pub fn as_eth(&self) -> f64 {
        self.0 as f64 / 1e18
    }
}

impl std::ops::Add for Wei {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Wei {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::Mul<u64> for Wei {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        Self(self.0 * rhs as u128)
    }
}

/// Ethereum always uses ECDSA secp256k1
pub const SIGNATURE_TYPE: SignatureType = SignatureType::EcdsaSecp256k1;
