//! Error types for MPC protocol operations

use thiserror::Error;

/// Errors that can occur during MPC protocol execution
#[derive(Error, Debug)]
pub enum MpcError {
    /// Distributed Key Generation failed
    #[error("DKG failed: {0}")]
    DkgFailed(String),

    /// Signing protocol failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid participant
    #[error("Invalid participant: {0}")]
    InvalidParticipant(String),

    /// Threshold not met
    #[error("Threshold not met: need {required}, have {actual}")]
    ThresholdNotMet { required: u16, actual: u16 },

    /// Invalid share
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    /// Invalid commitment
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Invalid signature share
    #[error("Invalid signature share: {0}")]
    InvalidSignatureShare(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Protocol state error
    #[error("Protocol state error: {0}")]
    ProtocolState(String),

    /// Timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// User abort
    #[error("User aborted operation")]
    UserAbort,

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crypto_core::CryptoError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
