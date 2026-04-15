//! # MPC Protocol
//!
//! Implementation of the 2PC-MPC protocol for threshold signatures on Canton Network.
//!
//! ## Architecture
//!
//! The 2PC-MPC protocol creates a "nested" MPC structure:
//!
//! 1. **2PC Layer**: User + Network are always required (two-party computation)
//! 2. **MPC Layer**: Network participation is managed by threshold MPC among nodes
//!
//! This ensures:
//! - **Non-collusive security**: Neither user nor network alone can sign
//! - **Scalability**: Supports hundreds/thousands of signer nodes
//! - **User locality**: User computation is O(1) regardless of network size
//!
//! ## Supported Signature Schemes
//!
//! - **FROST-secp256k1**: For Bitcoin (legacy), Ethereum, and EVM chains
//! - **FROST-Ed25519**: For Solana, Cardano, and Ed25519-based chains
//! - **FROST-Schnorr**: For Bitcoin Taproot

pub mod protocol;
pub mod dkg;
pub mod signing;
pub mod participant;
pub mod network;
pub mod types;
pub mod error;

pub use error::MpcError;
pub use types::*;
pub use protocol::TwoPcMpc;
pub use participant::Participant;

/// Result type for MPC operations
pub type Result<T> = std::result::Result<T, MpcError>;
