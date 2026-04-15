//! # Canton Network Integration
//!
//! This crate provides the integration layer between the 2PC-MPC protocol and
//! Canton Network, enabling Daml smart contracts to control native assets on
//! Bitcoin, Ethereum, Solana, and other blockchains.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Canton Network                          │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              Daml Smart Contracts                    │   │
//! │  │   (DeFi, Custody, Tokenization, Trading)            │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                           │                                 │
//! │                           ▼                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │          Canton Integration Layer (this crate)       │   │
//! │  │  - Ledger API client                                │   │
//! │  │  - dWallet Daml templates                           │   │
//! │  │  - Cross-chain transaction coordination             │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                           │                                 │
//! └───────────────────────────┼─────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │              2PC-MPC Protocol + dWallet Manager             │
//! └─────────────────────────────────────────────────────────────┘
//!                             │
//!         ┌───────────────────┼───────────────────┐
//!         ▼                   ▼                   ▼
//!    ┌─────────┐        ┌──────────┐        ┌─────────┐
//!    │ Bitcoin │        │ Ethereum │        │ Solana  │
//!    └─────────┘        └──────────┘        └─────────┘
//! ```

pub mod ledger_api;
pub mod daml_types;
pub mod service;
pub mod events;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CantonError {
    #[error("Ledger API error: {0}")]
    LedgerApi(String),

    #[error("Contract error: {0}")]
    Contract(String),

    #[error("dWallet error: {0}")]
    DWallet(#[from] dwallet::DWalletError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] mpc_protocol::MpcError),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, CantonError>;

/// Canton network configuration
#[derive(Debug, Clone)]
pub struct CantonConfig {
    /// Ledger API host
    pub ledger_host: String,
    /// Ledger API port
    pub ledger_port: u16,
    /// Party ID for this participant
    pub party_id: String,
    /// Application ID
    pub application_id: String,
    /// Use TLS
    pub use_tls: bool,
}

impl Default for CantonConfig {
    fn default() -> Self {
        Self {
            ledger_host: "localhost".to_string(),
            ledger_port: 6865,
            party_id: "participant1".to_string(),
            application_id: "canton-2pc-mpc".to_string(),
            use_tls: false,
        }
    }
}
