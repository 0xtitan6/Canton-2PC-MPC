//! Core types for the 2PC-MPC protocol

use crypto_core::SignatureType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a dWallet
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DWalletId(pub String);

impl DWalletId {
    /// Create a new dWallet ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random dWallet ID
    pub fn generate() -> Self {
        use rand::Rng;
        let id: [u8; 16] = rand::thread_rng().gen();
        Self(hex::encode(id))
    }
}

/// Unique identifier for a participant in the MPC protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

impl ParticipantId {
    /// Create a new participant ID (must be > 0)
    pub fn new(id: u16) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Get the raw ID value
    pub fn value(&self) -> u16 {
        self.0
    }
}

/// Session identifier for a signing session
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    /// Create a new session ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random session ID
    pub fn generate() -> Self {
        use rand::Rng;
        let id: [u8; 16] = rand::thread_rng().gen();
        Self(hex::encode(id))
    }
}

/// Configuration for the 2PC-MPC protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Signature type (determines which curve/scheme to use)
    pub signature_type: SignatureType,

    /// Threshold for signing (minimum participants required)
    pub threshold: u16,

    /// Total number of participants in the network
    pub total_participants: u16,

    /// Timeout for protocol rounds (in milliseconds)
    pub round_timeout_ms: u64,

    /// Maximum number of concurrent signing sessions
    pub max_concurrent_sessions: usize,

    /// Whether to use proactive security (key refresh)
    pub proactive_security: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            signature_type: SignatureType::EcdsaSecp256k1,
            threshold: 2,
            total_participants: 3,
            round_timeout_ms: 30_000,
            max_concurrent_sessions: 100,
            proactive_security: false,
        }
    }
}

impl ProtocolConfig {
    /// Create config for Bitcoin/Ethereum (ECDSA secp256k1)
    pub fn for_bitcoin_ethereum(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::EcdsaSecp256k1,
            threshold,
            total_participants: total,
            ..Default::default()
        }
    }

    /// Create config for Bitcoin Taproot (Schnorr)
    pub fn for_taproot(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::SchnorrSecp256k1,
            threshold,
            total_participants: total,
            ..Default::default()
        }
    }

    /// Create config for Solana (Ed25519)
    pub fn for_solana(threshold: u16, total: u16) -> Self {
        Self {
            signature_type: SignatureType::Ed25519,
            threshold,
            total_participants: total,
            ..Default::default()
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.threshold == 0 {
            return Err("Threshold must be at least 1".into());
        }
        if self.threshold > self.total_participants {
            return Err("Threshold cannot exceed total participants".into());
        }
        if self.total_participants == 0 {
            return Err("Must have at least one participant".into());
        }
        Ok(())
    }
}

/// State of the DKG protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkgState {
    /// Not started
    NotStarted,
    /// Round 1: Generating commitments
    Round1Commitments,
    /// Round 2: Distributing shares
    Round2Shares,
    /// Round 3: Verifying shares
    Round3Verification,
    /// DKG completed successfully
    Completed,
    /// DKG failed
    Failed,
}

/// State of a signing session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningState {
    /// Waiting for participants to join
    WaitingForParticipants,
    /// Round 1: Generating nonce commitments
    Round1NonceCommitments,
    /// Round 2: Creating signature shares
    Round2SignatureShares,
    /// Aggregating shares
    Aggregating,
    /// Signing completed
    Completed,
    /// Signing failed
    Failed,
    /// Session timed out
    TimedOut,
}

/// Represents a key share held by a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Participant ID
    pub participant_id: ParticipantId,

    /// The secret share value (encrypted for storage)
    pub share: Vec<u8>,

    /// Public verification share
    pub verification_share: Vec<u8>,

    /// Signature type this share is for
    pub signature_type: SignatureType,
}

/// Commitment during DKG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// Participant ID
    pub participant_id: ParticipantId,

    /// Commitment value
    pub value: Vec<u8>,

    /// Round number
    pub round: u8,
}

/// Nonce commitment for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCommitment {
    /// Participant ID
    pub participant_id: ParticipantId,

    /// Session ID
    pub session_id: SessionId,

    /// Hiding nonce commitment
    pub hiding: Vec<u8>,

    /// Binding nonce commitment
    pub binding: Vec<u8>,
}

/// Signature share from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    /// Participant ID
    pub participant_id: ParticipantId,

    /// Session ID
    pub session_id: SessionId,

    /// The signature share value
    pub share: Vec<u8>,
}

/// Result of a signing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    /// Session ID
    pub session_id: SessionId,

    /// dWallet ID
    pub dwallet_id: DWalletId,

    /// The final aggregated signature
    pub signature: Vec<u8>,

    /// Message that was signed
    pub message: Vec<u8>,

    /// Participants who contributed
    pub participants: Vec<ParticipantId>,

    /// Signature type
    pub signature_type: SignatureType,
}

/// User's share in the 2PC-MPC protocol
/// The user is always one party in the 2PC structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserShare {
    /// dWallet ID
    pub dwallet_id: DWalletId,

    /// User's secret share (encrypted)
    pub secret_share: Vec<u8>,

    /// User's public share
    pub public_share: Vec<u8>,

    /// Combined public key for the dWallet
    pub public_key: Vec<u8>,

    /// Signature type
    pub signature_type: SignatureType,

    /// Chain addresses derived from this wallet
    pub addresses: HashMap<String, String>,
}

impl UserShare {
    /// Get the address for a specific chain
    pub fn address_for_chain(&self, chain: &str) -> Option<&String> {
        self.addresses.get(chain)
    }
}

/// Network's combined share in the 2PC-MPC protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkShare {
    /// dWallet ID
    pub dwallet_id: DWalletId,

    /// Combined network public share
    pub public_share: Vec<u8>,

    /// Threshold required for network participation
    pub threshold: u16,

    /// Total participants in the network
    pub total_participants: u16,
}

/// Request to create a new dWallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDWalletRequest {
    /// Signature type for the wallet
    pub signature_type: SignatureType,

    /// Requested threshold
    pub threshold: u16,

    /// User's initial contribution to DKG
    pub user_commitment: Vec<u8>,

    /// Metadata for the wallet
    pub metadata: HashMap<String, String>,
}

/// Request to sign a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// dWallet ID
    pub dwallet_id: DWalletId,

    /// Message to sign
    pub message: Vec<u8>,

    /// User's nonce commitment
    pub user_nonce_commitment: NonceCommitment,

    /// Additional signing metadata
    pub metadata: HashMap<String, String>,
}
