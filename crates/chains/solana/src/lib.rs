//! # Solana Chain Support
//!
//! This module provides Solana-specific functionality for the Canton 2PC-MPC system,
//! enabling native SOL and SPL tokens to be controlled by Canton smart contracts.
//!
//! ## Features
//!
//! - **Address derivation**: Ed25519 public keys as base58 addresses
//! - **Transaction building**: Solana transaction construction
//! - **SPL Token support**: Transfer, approve, and other token operations
//! - **Program interaction**: Calling Solana programs

pub mod address;
pub mod transaction;
pub mod signer;
pub mod spl_token;

use crypto_core::SignatureType;
use thiserror::Error;

/// Solana-specific errors
#[derive(Error, Debug)]
pub enum SolanaError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto_core::CryptoError),
}

pub type Result<T> = std::result::Result<T, SolanaError>;

/// Solana networks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Mainnet Beta
    Mainnet,
    /// Testnet
    Testnet,
    /// Devnet
    Devnet,
    /// Localhost
    Localnet,
}

impl Network {
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Network::Mainnet => "https://api.mainnet-beta.solana.com",
            Network::Testnet => "https://api.testnet.solana.com",
            Network::Devnet => "https://api.devnet.solana.com",
            Network::Localnet => "http://localhost:8899",
        }
    }
}

/// Lamport amount (smallest unit, 1 SOL = 1e9 lamports)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Lamports(pub u64);

impl Lamports {
    pub fn from_lamports(lamports: u64) -> Self {
        Self(lamports)
    }

    pub fn from_sol(sol: f64) -> Self {
        Self((sol * 1e9) as u64)
    }

    pub fn as_lamports(&self) -> u64 {
        self.0
    }

    pub fn as_sol(&self) -> f64 {
        self.0 as f64 / 1e9
    }
}

impl std::ops::Add for Lamports {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Lamports {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// Solana always uses Ed25519
pub const SIGNATURE_TYPE: SignatureType = SignatureType::Ed25519;

/// Well-known Solana program IDs
pub mod programs {
    use super::address::Pubkey;

    /// System Program
    pub fn system_program() -> Pubkey {
        Pubkey::from_bytes(&[0u8; 32]).unwrap()
    }

    /// Token Program (SPL)
    pub fn token_program() -> Pubkey {
        // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
    }

    /// Token 2022 Program
    pub fn token_2022_program() -> Pubkey {
        // TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
        Pubkey::from_base58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
    }

    /// Associated Token Account Program
    pub fn associated_token_program() -> Pubkey {
        // ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
        Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
    }

    /// Memo Program
    pub fn memo_program() -> Pubkey {
        // MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
        Pubkey::from_base58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap()
    }

    /// Compute Budget Program
    pub fn compute_budget_program() -> Pubkey {
        // ComputeBudget111111111111111111111111111111
        Pubkey::from_base58("ComputeBudget111111111111111111111111111111").unwrap()
    }
}
