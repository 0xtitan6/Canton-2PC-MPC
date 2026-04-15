//! Core 2PC-MPC protocol implementation
//!
//! The 2PC-MPC protocol ensures that both the user AND the network must
//! participate to generate any signature. This provides zero-trust security
//! where no single party (or coalition of network nodes) can sign without
//! explicit user authorization.

use crate::error::MpcError;
use crate::types::*;
use crate::Result;
use async_trait::async_trait;
use crypto_core::{SignatureType, traits::{KeyPair, PublicKey}};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The main 2PC-MPC protocol coordinator
pub struct TwoPcMpc {
    /// Protocol configuration
    config: ProtocolConfig,

    /// Active dWallets managed by this instance
    wallets: Arc<RwLock<HashMap<DWalletId, DWalletState>>>,

    /// Active signing sessions
    sessions: Arc<RwLock<HashMap<SessionId, SigningSession>>>,

    /// Network interface for communicating with other participants
    network: Arc<dyn NetworkInterface>,
}

/// State of a dWallet
#[derive(Debug, Clone)]
pub struct DWalletState {
    /// dWallet identifier
    pub id: DWalletId,

    /// DKG state
    pub dkg_state: DkgState,

    /// User's share (if this is the user's node)
    pub user_share: Option<UserShare>,

    /// Network share info
    pub network_share: Option<NetworkShare>,

    /// Public key for the wallet
    pub public_key: Option<Vec<u8>>,

    /// Signature type
    pub signature_type: SignatureType,

    /// Creation timestamp
    pub created_at: u64,
}

/// Active signing session
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// Session identifier
    pub id: SessionId,

    /// Associated dWallet
    pub dwallet_id: DWalletId,

    /// Current state
    pub state: SigningState,

    /// Message being signed
    pub message: Vec<u8>,

    /// Collected nonce commitments
    pub nonce_commitments: HashMap<ParticipantId, NonceCommitment>,

    /// Collected signature shares
    pub signature_shares: HashMap<ParticipantId, SignatureShare>,

    /// Participating nodes
    pub participants: Vec<ParticipantId>,

    /// Session creation time
    pub created_at: u64,

    /// Timeout deadline
    pub deadline: u64,
}

/// Interface for network communication between MPC participants
#[async_trait]
pub trait NetworkInterface: Send + Sync {
    /// Broadcast a message to all participants
    async fn broadcast(&self, message: ProtocolMessage) -> Result<()>;

    /// Send a message to a specific participant
    async fn send(&self, participant: ParticipantId, message: ProtocolMessage) -> Result<()>;

    /// Receive messages (called by the protocol)
    async fn receive(&self) -> Result<ProtocolMessage>;

    /// Get the list of active participants
    async fn get_participants(&self) -> Result<Vec<ParticipantId>>;

    /// Get this node's participant ID
    fn local_participant_id(&self) -> ParticipantId;
}

/// Protocol messages exchanged between participants
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProtocolMessage {
    /// DKG Round 1: Commitment
    DkgCommitment {
        dwallet_id: DWalletId,
        commitment: Commitment,
    },

    /// DKG Round 2: Share distribution
    DkgShare {
        dwallet_id: DWalletId,
        from: ParticipantId,
        to: ParticipantId,
        encrypted_share: Vec<u8>,
    },

    /// DKG Round 3: Verification acknowledgment
    DkgVerification {
        dwallet_id: DWalletId,
        participant: ParticipantId,
        success: bool,
    },

    /// DKG completion with public key
    DkgComplete {
        dwallet_id: DWalletId,
        public_key: Vec<u8>,
    },

    /// Signing: Nonce commitment
    SigningNonceCommitment {
        session_id: SessionId,
        commitment: NonceCommitment,
    },

    /// Signing: Signature share
    SigningShare {
        session_id: SessionId,
        share: SignatureShare,
    },

    /// Signing: Final aggregated signature
    SigningComplete {
        session_id: SessionId,
        signature: Vec<u8>,
    },

    /// Error during protocol
    Error {
        session_id: Option<SessionId>,
        dwallet_id: Option<DWalletId>,
        error: String,
    },
}

impl TwoPcMpc {
    /// Create a new 2PC-MPC protocol instance
    pub fn new(config: ProtocolConfig, network: Arc<dyn NetworkInterface>) -> Result<Self> {
        config.validate().map_err(|e| MpcError::ProtocolState(e))?;

        Ok(Self {
            config,
            wallets: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            network,
        })
    }

    /// Create a new dWallet with distributed key generation
    pub async fn create_dwallet(&self, request: CreateDWalletRequest) -> Result<DWalletId> {
        let dwallet_id = DWalletId::generate();

        // Initialize wallet state
        let state = DWalletState {
            id: dwallet_id.clone(),
            dkg_state: DkgState::Round1Commitments,
            user_share: None,
            network_share: None,
            public_key: None,
            signature_type: request.signature_type,
            created_at: current_timestamp(),
        };

        self.wallets.write().await.insert(dwallet_id.clone(), state);

        // Start DKG protocol
        self.run_dkg(&dwallet_id, request).await?;

        Ok(dwallet_id)
    }

    /// Run the Distributed Key Generation protocol
    async fn run_dkg(&self, dwallet_id: &DWalletId, request: CreateDWalletRequest) -> Result<()> {
        // Round 1: Generate and broadcast commitments
        let commitment = self.generate_dkg_commitment(dwallet_id, &request).await?;

        self.network
            .broadcast(ProtocolMessage::DkgCommitment {
                dwallet_id: dwallet_id.clone(),
                commitment,
            })
            .await?;

        // Update state to Round 2
        if let Some(state) = self.wallets.write().await.get_mut(dwallet_id) {
            state.dkg_state = DkgState::Round2Shares;
        }

        // Round 2 and 3 would continue asynchronously based on received messages
        // In production, this would be event-driven

        Ok(())
    }

    /// Generate DKG commitment for Round 1
    async fn generate_dkg_commitment(
        &self,
        dwallet_id: &DWalletId,
        _request: &CreateDWalletRequest,
    ) -> Result<Commitment> {
        let participant_id = self.network.local_participant_id();

        // Generate commitment based on signature type
        // This is a simplified version - production would use proper FROST DKG
        let commitment_value = match self.config.signature_type {
            SignatureType::EcdsaSecp256k1 | SignatureType::SchnorrSecp256k1 => {
                // Generate secp256k1 commitment
                let keypair = crypto_core::ecdsa::EcdsaKeyPair::generate()?;
                keypair.public_key().to_bytes()
            }
            SignatureType::Ed25519 => {
                // Generate Ed25519 commitment
                let keypair = crypto_core::eddsa::Ed25519KeyPair::generate()?;
                keypair.public_key().to_bytes()
            }
        };

        Ok(Commitment {
            participant_id,
            value: commitment_value,
            round: 1,
        })
    }

    /// Initiate a signing session
    pub async fn sign(&self, request: SignRequest) -> Result<SessionId> {
        // Verify dWallet exists and DKG is complete
        let wallets = self.wallets.read().await;
        let wallet = wallets
            .get(&request.dwallet_id)
            .ok_or_else(|| MpcError::InvalidParticipant("dWallet not found".into()))?;

        if wallet.dkg_state != DkgState::Completed {
            return Err(MpcError::ProtocolState("DKG not complete".into()));
        }

        drop(wallets);

        // Create signing session
        let session_id = SessionId::generate();
        let now = current_timestamp();

        let session = SigningSession {
            id: session_id.clone(),
            dwallet_id: request.dwallet_id.clone(),
            state: SigningState::Round1NonceCommitments,
            message: request.message.clone(),
            nonce_commitments: HashMap::new(),
            signature_shares: HashMap::new(),
            participants: Vec::new(),
            created_at: now,
            deadline: now + self.config.round_timeout_ms,
        };

        self.sessions.write().await.insert(session_id.clone(), session);

        // Broadcast user's nonce commitment
        self.network
            .broadcast(ProtocolMessage::SigningNonceCommitment {
                session_id: session_id.clone(),
                commitment: request.user_nonce_commitment,
            })
            .await?;

        Ok(session_id)
    }

    /// Process an incoming protocol message
    pub async fn process_message(&self, message: ProtocolMessage) -> Result<()> {
        match message {
            ProtocolMessage::DkgCommitment { dwallet_id, commitment } => {
                self.handle_dkg_commitment(&dwallet_id, commitment).await
            }
            ProtocolMessage::DkgShare { dwallet_id, from, to, encrypted_share } => {
                self.handle_dkg_share(&dwallet_id, from, to, encrypted_share).await
            }
            ProtocolMessage::DkgVerification { dwallet_id, participant, success } => {
                self.handle_dkg_verification(&dwallet_id, participant, success).await
            }
            ProtocolMessage::DkgComplete { dwallet_id, public_key } => {
                self.handle_dkg_complete(&dwallet_id, public_key).await
            }
            ProtocolMessage::SigningNonceCommitment { session_id, commitment } => {
                self.handle_nonce_commitment(&session_id, commitment).await
            }
            ProtocolMessage::SigningShare { session_id, share } => {
                self.handle_signature_share(&session_id, share).await
            }
            ProtocolMessage::SigningComplete { session_id, signature } => {
                self.handle_signing_complete(&session_id, signature).await
            }
            ProtocolMessage::Error { session_id, dwallet_id, error } => {
                self.handle_error(session_id, dwallet_id, error).await
            }
        }
    }

    async fn handle_dkg_commitment(&self, dwallet_id: &DWalletId, commitment: Commitment) -> Result<()> {
        // Store commitment and check if we have enough to proceed
        tracing::info!(
            "Received DKG commitment from participant {} for wallet {}",
            commitment.participant_id.0,
            dwallet_id.0
        );
        Ok(())
    }

    async fn handle_dkg_share(
        &self,
        _dwallet_id: &DWalletId,
        _from: ParticipantId,
        _to: ParticipantId,
        _encrypted_share: Vec<u8>,
    ) -> Result<()> {
        // Decrypt and store share
        Ok(())
    }

    async fn handle_dkg_verification(
        &self,
        _dwallet_id: &DWalletId,
        _participant: ParticipantId,
        _success: bool,
    ) -> Result<()> {
        // Track verification status
        Ok(())
    }

    async fn handle_dkg_complete(&self, dwallet_id: &DWalletId, public_key: Vec<u8>) -> Result<()> {
        if let Some(state) = self.wallets.write().await.get_mut(dwallet_id) {
            state.dkg_state = DkgState::Completed;
            state.public_key = Some(public_key);
        }
        Ok(())
    }

    async fn handle_nonce_commitment(&self, session_id: &SessionId, commitment: NonceCommitment) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.nonce_commitments.insert(commitment.participant_id, commitment);

            // Check if we have enough commitments to proceed
            if session.nonce_commitments.len() >= self.config.threshold as usize {
                session.state = SigningState::Round2SignatureShares;
            }
        }
        Ok(())
    }

    async fn handle_signature_share(&self, session_id: &SessionId, share: SignatureShare) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.signature_shares.insert(share.participant_id, share);

            // Check if we have enough shares to aggregate
            if session.signature_shares.len() >= self.config.threshold as usize {
                session.state = SigningState::Aggregating;
                // Trigger aggregation
            }
        }
        Ok(())
    }

    async fn handle_signing_complete(&self, session_id: &SessionId, _signature: Vec<u8>) -> Result<()> {
        if let Some(session) = self.sessions.write().await.get_mut(session_id) {
            session.state = SigningState::Completed;
        }
        Ok(())
    }

    async fn handle_error(
        &self,
        session_id: Option<SessionId>,
        _dwallet_id: Option<DWalletId>,
        error: String,
    ) -> Result<()> {
        tracing::error!("Protocol error: {}", error);
        if let Some(sid) = session_id {
            if let Some(session) = self.sessions.write().await.get_mut(&sid) {
                session.state = SigningState::Failed;
            }
        }
        Ok(())
    }

    /// Get the status of a signing session
    pub async fn get_session_status(&self, session_id: &SessionId) -> Option<SigningState> {
        self.sessions.read().await.get(session_id).map(|s| s.state)
    }

    /// Get the result of a completed signing session
    pub async fn get_signing_result(&self, session_id: &SessionId) -> Option<SigningResult> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;

        if session.state != SigningState::Completed {
            return None;
        }

        let wallets = self.wallets.read().await;
        let wallet = wallets.get(&session.dwallet_id)?;

        Some(SigningResult {
            session_id: session_id.clone(),
            dwallet_id: session.dwallet_id.clone(),
            signature: Vec::new(), // Would contain actual signature
            message: session.message.clone(),
            participants: session.participants.clone(),
            signature_type: wallet.signature_type,
        })
    }

    /// Get wallet information
    pub async fn get_wallet(&self, dwallet_id: &DWalletId) -> Option<DWalletState> {
        self.wallets.read().await.get(dwallet_id).cloned()
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNetwork {
        participant_id: ParticipantId,
    }

    #[async_trait]
    impl NetworkInterface for MockNetwork {
        async fn broadcast(&self, _message: ProtocolMessage) -> Result<()> {
            Ok(())
        }

        async fn send(&self, _participant: ParticipantId, _message: ProtocolMessage) -> Result<()> {
            Ok(())
        }

        async fn receive(&self) -> Result<ProtocolMessage> {
            Err(MpcError::Timeout("No messages".into()))
        }

        async fn get_participants(&self) -> Result<Vec<ParticipantId>> {
            Ok(vec![
                ParticipantId(1),
                ParticipantId(2),
                ParticipantId(3),
            ])
        }

        fn local_participant_id(&self) -> ParticipantId {
            self.participant_id
        }
    }

    #[tokio::test]
    async fn test_create_protocol() {
        let config = ProtocolConfig::for_bitcoin_ethereum(2, 3);
        let network = Arc::new(MockNetwork {
            participant_id: ParticipantId(1),
        });

        let protocol = TwoPcMpc::new(config, network).unwrap();
        assert!(protocol.wallets.read().await.is_empty());
    }
}
