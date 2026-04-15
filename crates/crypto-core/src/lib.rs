//! # Crypto Core
//!
//! Core cryptographic primitives for Canton 2PC-MPC.
//!
//! This crate provides the foundational cryptographic operations needed for
//! threshold signatures across multiple blockchain networks:
//!
//! - **ECDSA (secp256k1)**: Bitcoin, Ethereum, and EVM-compatible chains
//! - **EdDSA (Ed25519)**: Solana, Cardano, and other Ed25519-based chains
//! - **Schnorr (secp256k1)**: Bitcoin Taproot
//!
//! ## Architecture
//!
//! The crate is organized around signature schemes, each implementing a common
//! trait interface for key generation, signing, and verification.

pub mod ecdsa;
pub mod eddsa;
pub mod schnorr;
pub mod hash;
pub mod error;
pub mod traits;

pub use error::CryptoError;
pub use traits::{SignatureScheme, ThresholdScheme, KeyPair};

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Supported signature schemes for cross-chain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SignatureType {
    /// ECDSA over secp256k1 (Bitcoin, Ethereum)
    EcdsaSecp256k1,
    /// EdDSA over Ed25519 (Solana, Cardano)
    Ed25519,
    /// Schnorr over secp256k1 (Bitcoin Taproot)
    SchnorrSecp256k1,
}

impl SignatureType {
    /// Returns the chains that use this signature type
    pub fn supported_chains(&self) -> &'static [&'static str] {
        match self {
            SignatureType::EcdsaSecp256k1 => &["bitcoin", "ethereum", "polygon", "avalanche", "bsc"],
            SignatureType::Ed25519 => &["solana", "cardano", "polkadot", "near", "aptos"],
            SignatureType::SchnorrSecp256k1 => &["bitcoin-taproot"],
        }
    }

    /// Returns the key size in bytes
    pub fn key_size(&self) -> usize {
        match self {
            SignatureType::EcdsaSecp256k1 => 32,
            SignatureType::Ed25519 => 32,
            SignatureType::SchnorrSecp256k1 => 32,
        }
    }

    /// Returns the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureType::EcdsaSecp256k1 => 64, // r + s
            SignatureType::Ed25519 => 64,        // R + s
            SignatureType::SchnorrSecp256k1 => 64, // r + s
        }
    }
}
