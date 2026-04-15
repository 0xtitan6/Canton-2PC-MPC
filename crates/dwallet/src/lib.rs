//! # dWallet Management
//!
//! This crate provides the dWallet abstraction for Canton 2PC-MPC, enabling
//! Canton smart contracts to control native assets on any blockchain.
//!
//! ## What is a dWallet?
//!
//! A dWallet (decentralized wallet) is a key management unit that:
//! - Has keys distributed across user and network using 2PC-MPC
//! - Can sign transactions on any supported blockchain
//! - Is controlled by Canton/Daml smart contracts
//! - Provides zero-trust security (neither party can sign alone)

pub mod wallet;
pub mod manager;
pub mod chain_adapter;

pub use wallet::{DWallet, DWalletConfig};
pub use manager::DWalletManager;
pub use chain_adapter::{ChainAdapter, ChainType};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DWalletError {
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("Chain not supported: {0}")]
    UnsupportedChain(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(#[from] mpc_protocol::MpcError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto_core::CryptoError),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, DWalletError>;
