//! Error types for cryptographic operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key format or length
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid signature format or verification failed
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid message format
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Hash computation failed
    #[error("Hash computation failed: {0}")]
    HashFailed(String),

    /// Encryption/decryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Serialization/deserialization failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Random number generation failed
    #[error("RNG failed: {0}")]
    RngFailed(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Threshold-specific errors
    #[error("Threshold error: {0}")]
    ThresholdError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<k256::ecdsa::Error> for CryptoError {
    fn from(e: k256::ecdsa::Error) -> Self {
        CryptoError::SigningFailed(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        CryptoError::SigningFailed(e.to_string())
    }
}
