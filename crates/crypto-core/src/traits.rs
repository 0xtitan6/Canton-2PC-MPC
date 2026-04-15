//! Common traits for cryptographic operations
//!
//! These traits define the interface for all signature schemes used in the
//! Canton 2PC-MPC system, enabling uniform handling of different cryptographic
//! algorithms across various blockchain networks.

use crate::{Result, SignatureType};
use serde::{Deserialize, Serialize};

/// A cryptographic key pair consisting of a private and public key
pub trait KeyPair: Clone + Send + Sync {
    /// The type of the public key
    type PublicKey: PublicKey;
    /// The type of the private key
    type PrivateKey: PrivateKey;

    /// Generate a new random key pair
    fn generate() -> Result<Self>;

    /// Get the public key
    fn public_key(&self) -> &Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> &Self::PrivateKey;

    /// Create a key pair from a private key
    fn from_private_key(private_key: Self::PrivateKey) -> Result<Self>;

    /// Returns the signature type for this key pair
    fn signature_type() -> SignatureType;
}

/// A public key that can be used for signature verification
pub trait PublicKey: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    /// Serialize the public key to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a public key from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Get the compressed representation (if applicable)
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Get the uncompressed representation (if applicable)
    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// A private key that can be used for signing
pub trait PrivateKey: Clone + Send + Sync {
    /// Serialize the private key to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a private key from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Securely zeroize the private key material
    fn zeroize(&mut self);
}

/// A digital signature
pub trait Signature: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    /// Serialize the signature to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a signature from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Get the DER encoding (for ECDSA signatures)
    fn to_der(&self) -> Option<Vec<u8>> {
        None
    }
}

/// A signature scheme that can sign and verify messages
pub trait SignatureScheme {
    /// The key pair type
    type KeyPair: KeyPair;
    /// The signature type
    type Signature: Signature;

    /// Sign a message with the given key pair
    fn sign(
        key_pair: &Self::KeyPair,
        message: &[u8],
    ) -> Result<Self::Signature>;

    /// Verify a signature against a public key and message
    fn verify(
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool>;

    /// Returns the signature type
    fn signature_type() -> SignatureType;
}

/// A threshold signature scheme supporting distributed key generation and signing
pub trait ThresholdScheme: SignatureScheme {
    /// Share of a private key held by a participant
    type KeyShare: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;
    /// Share of a signature produced by a participant
    type SignatureShare: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;
    /// Commitment used in the DKG protocol
    type Commitment: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;
    /// Nonce used in the signing protocol
    type Nonce: Clone + Send + Sync;
    /// Nonce commitment for the signing protocol
    type NonceCommitment: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// Parameters for the threshold scheme
    fn threshold_params(threshold: u16, total: u16) -> ThresholdParams;

    /// Generate key shares using distributed key generation
    fn generate_key_shares(
        params: &ThresholdParams,
    ) -> Result<(Vec<Self::KeyShare>, <Self::KeyPair as KeyPair>::PublicKey, Vec<Self::Commitment>)>;

    /// Verify a key share against commitments
    fn verify_key_share(
        share: &Self::KeyShare,
        commitments: &[Self::Commitment],
        participant_index: u16,
    ) -> Result<bool>;

    /// Generate a signing nonce and commitment
    fn generate_nonce(
        key_share: &Self::KeyShare,
    ) -> Result<(Self::Nonce, Self::NonceCommitment)>;

    /// Create a signature share
    fn sign_share(
        key_share: &Self::KeyShare,
        nonce: &Self::Nonce,
        message: &[u8],
        nonce_commitments: &[Self::NonceCommitment],
        participant_indices: &[u16],
    ) -> Result<Self::SignatureShare>;

    /// Aggregate signature shares into a complete signature
    fn aggregate_signatures(
        signature_shares: &[Self::SignatureShare],
        nonce_commitments: &[Self::NonceCommitment],
        participant_indices: &[u16],
        message: &[u8],
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> Result<Self::Signature>;
}

/// Parameters for a threshold signature scheme
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Minimum number of participants required to sign (t)
    pub threshold: u16,
    /// Total number of participants (n)
    pub total_participants: u16,
}

impl ThresholdParams {
    /// Create new threshold parameters
    pub fn new(threshold: u16, total_participants: u16) -> Result<Self> {
        if threshold == 0 {
            return Err(crate::CryptoError::ThresholdError(
                "Threshold must be at least 1".into(),
            ));
        }
        if threshold > total_participants {
            return Err(crate::CryptoError::ThresholdError(
                "Threshold cannot exceed total participants".into(),
            ));
        }
        Ok(Self {
            threshold,
            total_participants,
        })
    }

    /// Check if we have enough participants
    pub fn has_quorum(&self, participant_count: u16) -> bool {
        participant_count >= self.threshold
    }
}

/// Participant identifier in the threshold scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

impl ParticipantId {
    /// Create a new participant ID (1-indexed)
    pub fn new(id: u16) -> Result<Self> {
        if id == 0 {
            return Err(crate::CryptoError::ThresholdError(
                "Participant ID must be non-zero".into(),
            ));
        }
        Ok(Self(id))
    }

    /// Get the raw ID value
    pub fn value(&self) -> u16 {
        self.0
    }
}
