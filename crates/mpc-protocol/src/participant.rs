//! MPC Participant implementation
//!
//! A participant in the 2PC-MPC network holds key shares and participates
//! in DKG and signing protocols.

use crate::dkg::{DkgCoordinator, DkgRound1Data};
use crate::error::MpcError;
use crate::signing::{SigningCoordinator, UserSigner};
use crate::types::*;
use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A participant in the 2PC-MPC protocol
pub struct Participant {
    /// Participant's unique identifier
    id: ParticipantId,

    /// Whether this is the user (participant 0) or a network node
    is_user: bool,

    /// Key shares for each dWallet
    key_shares: Arc<RwLock<HashMap<DWalletId, KeyShare>>>,

    /// Active DKG sessions
    dkg_sessions: Arc<RwLock<HashMap<DWalletId, DkgCoordinator>>>,

    /// Active signing sessions
    signing_sessions: Arc<RwLock<HashMap<SessionId, SigningCoordinator>>>,

    /// User signers (for user participant)
    user_signers: Arc<RwLock<HashMap<DWalletId, UserSigner>>>,

    /// Protocol configuration
    config: ProtocolConfig,
}

impl Participant {
    /// Create a new network participant
    pub fn new_network_node(id: u16, config: ProtocolConfig) -> Result<Self> {
        let participant_id = ParticipantId::new(id)
            .ok_or_else(|| MpcError::InvalidParticipant("ID must be > 0".into()))?;

        Ok(Self {
            id: participant_id,
            is_user: false,
            key_shares: Arc::new(RwLock::new(HashMap::new())),
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            signing_sessions: Arc::new(RwLock::new(HashMap::new())),
            user_signers: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Create a new user participant
    pub fn new_user(config: ProtocolConfig) -> Self {
        Self {
            id: ParticipantId(0),
            is_user: true,
            key_shares: Arc::new(RwLock::new(HashMap::new())),
            dkg_sessions: Arc::new(RwLock::new(HashMap::new())),
            signing_sessions: Arc::new(RwLock::new(HashMap::new())),
            user_signers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get this participant's ID
    pub fn id(&self) -> ParticipantId {
        self.id
    }

    /// Check if this is the user participant
    pub fn is_user(&self) -> bool {
        self.is_user
    }

    // ========== DKG Operations ==========

    /// Start participating in a DKG session
    pub async fn start_dkg(&self, dwallet_id: DWalletId) -> Result<DkgRound1Data> {
        let mut coordinator = DkgCoordinator::new(
            dwallet_id.clone(),
            self.config.signature_type,
            self.config.threshold,
            self.config.total_participants,
        );

        coordinator.start()?;
        let round1_data = coordinator.generate_round1()?;

        self.dkg_sessions.write().await.insert(dwallet_id, coordinator);

        Ok(round1_data)
    }

    /// Process DKG round 1 data from another participant
    pub async fn process_dkg_round1(
        &self,
        dwallet_id: &DWalletId,
        from: ParticipantId,
        data: DkgRound1Data,
    ) -> Result<bool> {
        let mut sessions = self.dkg_sessions.write().await;
        let coordinator = sessions.get_mut(dwallet_id)
            .ok_or_else(|| MpcError::ProtocolState("DKG session not found".into()))?;

        coordinator.add_round1_commitment(from, data)
    }

    /// Generate and get round 2 data
    pub async fn get_dkg_round2(&self, dwallet_id: &DWalletId) -> Result<HashMap<ParticipantId, Vec<u8>>> {
        let sessions = self.dkg_sessions.read().await;
        let coordinator = sessions.get(dwallet_id)
            .ok_or_else(|| MpcError::ProtocolState("DKG session not found".into()))?;

        let round2 = coordinator.generate_round2(self.id)?;
        Ok(round2.encrypted_shares)
    }

    /// Verify shares and complete DKG
    pub async fn complete_dkg(&self, dwallet_id: &DWalletId) -> Result<Vec<u8>> {
        let mut sessions = self.dkg_sessions.write().await;
        let coordinator = sessions.get_mut(dwallet_id)
            .ok_or_else(|| MpcError::ProtocolState("DKG session not found".into()))?;

        coordinator.verify_shares(self.id)?;

        coordinator.public_key()
            .map(|pk| pk.to_vec())
            .ok_or_else(|| MpcError::DkgFailed("Public key not computed".into()))
    }

    /// Store a key share for a dWallet
    pub async fn store_key_share(&self, dwallet_id: DWalletId, share: KeyShare) {
        self.key_shares.write().await.insert(dwallet_id, share);
    }

    // ========== Signing Operations ==========

    /// Start a signing session
    pub async fn start_signing(
        &self,
        session_id: SessionId,
        dwallet_id: DWalletId,
        message: Vec<u8>,
    ) -> Result<NonceCommitment> {
        // Check we have the key share
        let shares = self.key_shares.read().await;
        let key_share = shares.get(&dwallet_id)
            .ok_or_else(|| MpcError::InvalidParticipant("No key share for dWallet".into()))?;

        // Create signing coordinator
        let mut coordinator = SigningCoordinator::new(
            session_id.clone(),
            dwallet_id.clone(),
            key_share.signature_type,
            message,
            self.config.threshold,
        );
        coordinator.start()?;

        // Generate nonce commitment
        let (hiding, binding) = self.generate_nonce_pair(key_share.signature_type)?;

        let commitment = NonceCommitment {
            participant_id: self.id,
            session_id: session_id.clone(),
            hiding,
            binding,
        };

        // Add our own commitment
        coordinator.add_nonce_commitment(
            self.id,
            commitment.hiding.clone(),
            commitment.binding.clone(),
        )?;

        self.signing_sessions.write().await.insert(session_id, coordinator);

        Ok(commitment)
    }

    fn generate_nonce_pair(&self, signature_type: SignatureType) -> Result<(Vec<u8>, Vec<u8>)> {
        match signature_type {
            SignatureType::EcdsaSecp256k1 | SignatureType::SchnorrSecp256k1 => {
                use crypto_core::ecdsa::EcdsaKeyPair;
                use crypto_core::traits::{KeyPair, PublicKey};
                let kp = EcdsaKeyPair::generate()?;
                Ok((kp.public_key().to_bytes(), kp.public_key().to_bytes()))
            }
            SignatureType::Ed25519 => {
                use crypto_core::eddsa::Ed25519KeyPair;
                use crypto_core::traits::{KeyPair, PublicKey};
                let kp = Ed25519KeyPair::generate()?;
                Ok((kp.public_key().to_bytes(), kp.public_key().to_bytes()))
            }
        }
    }

    /// Process a nonce commitment from another participant
    pub async fn process_nonce_commitment(
        &self,
        session_id: &SessionId,
        commitment: NonceCommitment,
    ) -> Result<bool> {
        let mut sessions = self.signing_sessions.write().await;
        let coordinator = sessions.get_mut(session_id)
            .ok_or_else(|| MpcError::ProtocolState("Signing session not found".into()))?;

        coordinator.add_nonce_commitment(
            commitment.participant_id,
            commitment.hiding,
            commitment.binding,
        )
    }

    /// Generate a signature share
    pub async fn generate_signature_share(
        &self,
        session_id: &SessionId,
    ) -> Result<SignatureShare> {
        let sessions = self.signing_sessions.read().await;
        let coordinator = sessions.get(session_id)
            .ok_or_else(|| MpcError::ProtocolState("Signing session not found".into()))?;

        let package = coordinator.get_signing_package()?;

        // Get key share for this dWallet
        let shares = self.key_shares.read().await;
        let key_share = shares.get(&coordinator.session_id().clone().into())
            .ok_or_else(|| MpcError::InvalidParticipant("No key share".into()))?;

        // Compute signature share
        let share = self.compute_signature_share(&package, key_share)?;

        Ok(SignatureShare {
            participant_id: self.id,
            session_id: session_id.clone(),
            share,
        })
    }

    fn compute_signature_share(
        &self,
        package: &crate::signing::SigningPackage,
        key_share: &KeyShare,
    ) -> Result<Vec<u8>> {
        // Compute challenge
        let challenge = crypto_core::hash::sha256(&package.message);

        // Compute share: s_i = k_i + e * x_i (simplified)
        let mut share = vec![0u8; 64];
        for i in 0..32 {
            share[i] = challenge[i];
            share[32 + i] = key_share.share[i % key_share.share.len()]
                .wrapping_mul(challenge[i]);
        }

        Ok(share)
    }

    /// Process a signature share from another participant
    pub async fn process_signature_share(
        &self,
        session_id: &SessionId,
        share: SignatureShare,
    ) -> Result<bool> {
        let mut sessions = self.signing_sessions.write().await;
        let coordinator = sessions.get_mut(session_id)
            .ok_or_else(|| MpcError::ProtocolState("Signing session not found".into()))?;

        coordinator.add_signature_share(share.participant_id, share.share)
    }

    /// Aggregate signature shares into final signature
    pub async fn aggregate_signature(&self, session_id: &SessionId) -> Result<Vec<u8>> {
        let mut sessions = self.signing_sessions.write().await;
        let coordinator = sessions.get_mut(session_id)
            .ok_or_else(|| MpcError::ProtocolState("Signing session not found".into()))?;

        coordinator.aggregate()
    }

    /// Get the final signature for a completed session
    pub async fn get_signature(&self, session_id: &SessionId) -> Option<Vec<u8>> {
        let sessions = self.signing_sessions.read().await;
        sessions.get(session_id)
            .and_then(|c| c.signature().map(|s| s.to_vec()))
    }

    // ========== User-specific Operations ==========

    /// Store a user share (only for user participant)
    pub async fn store_user_share(&self, user_share: UserShare) -> Result<()> {
        if !self.is_user {
            return Err(MpcError::InvalidParticipant("Not a user participant".into()));
        }

        let dwallet_id = user_share.dwallet_id.clone();
        let signer = UserSigner::new(user_share);
        self.user_signers.write().await.insert(dwallet_id, signer);

        Ok(())
    }

    /// Generate a user nonce commitment for signing
    pub async fn user_generate_nonce(
        &self,
        dwallet_id: &DWalletId,
    ) -> Result<NonceCommitment> {
        if !self.is_user {
            return Err(MpcError::InvalidParticipant("Not a user participant".into()));
        }

        let mut signers = self.user_signers.write().await;
        let signer = signers.get_mut(dwallet_id)
            .ok_or_else(|| MpcError::InvalidParticipant("No signer for dWallet".into()))?;

        signer.generate_nonce()
    }

    /// User signs with their share
    pub async fn user_sign(
        &self,
        dwallet_id: &DWalletId,
        package: &crate::signing::SigningPackage,
    ) -> Result<Vec<u8>> {
        if !self.is_user {
            return Err(MpcError::InvalidParticipant("Not a user participant".into()));
        }

        let signers = self.user_signers.read().await;
        let signer = signers.get(dwallet_id)
            .ok_or_else(|| MpcError::InvalidParticipant("No signer for dWallet".into()))?;

        signer.sign(package)
    }
}

// Convert SessionId to DWalletId for lookup (placeholder)
impl From<SessionId> for DWalletId {
    fn from(session_id: SessionId) -> Self {
        DWalletId(session_id.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_network_participant() {
        let config = ProtocolConfig::for_bitcoin_ethereum(2, 3);
        let participant = Participant::new_network_node(1, config).unwrap();
        assert_eq!(participant.id().value(), 1);
        assert!(!participant.is_user());
    }

    #[tokio::test]
    async fn test_create_user_participant() {
        let config = ProtocolConfig::for_solana(2, 3);
        let participant = Participant::new_user(config);
        assert_eq!(participant.id().value(), 0);
        assert!(participant.is_user());
    }

    #[tokio::test]
    async fn test_start_dkg() {
        let config = ProtocolConfig::for_bitcoin_ethereum(2, 3);
        let participant = Participant::new_network_node(1, config).unwrap();

        let dwallet_id = DWalletId::generate();
        let round1 = participant.start_dkg(dwallet_id).await.unwrap();

        assert!(!round1.commitment.is_empty());
    }
}
