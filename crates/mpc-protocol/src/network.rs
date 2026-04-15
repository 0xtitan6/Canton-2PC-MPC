//! Network layer for MPC protocol communication
//!
//! This module provides the networking abstractions for participants to
//! communicate during DKG and signing protocols.

use crate::error::MpcError;
use crate::protocol::{NetworkInterface, ProtocolMessage};
use crate::types::ParticipantId;
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// In-memory network for testing and local development
pub struct InMemoryNetwork {
    /// This node's participant ID
    local_id: ParticipantId,

    /// Channels for each participant
    channels: Arc<RwLock<HashMap<ParticipantId, mpsc::Sender<ProtocolMessage>>>>,

    /// Receiver for this participant
    receiver: Arc<RwLock<mpsc::Receiver<ProtocolMessage>>>,

    /// All known participants
    participants: Arc<RwLock<Vec<ParticipantId>>>,
}

impl InMemoryNetwork {
    /// Create a new in-memory network node
    pub fn new(local_id: ParticipantId) -> (Self, mpsc::Sender<ProtocolMessage>) {
        let (tx, rx) = mpsc::channel(1000);

        let network = Self {
            local_id,
            channels: Arc::new(RwLock::new(HashMap::new())),
            receiver: Arc::new(RwLock::new(rx)),
            participants: Arc::new(RwLock::new(vec![local_id])),
        };

        (network, tx)
    }

    /// Register another participant's channel
    pub async fn register_participant(
        &self,
        participant: ParticipantId,
        sender: mpsc::Sender<ProtocolMessage>,
    ) {
        self.channels.write().await.insert(participant, sender);
        self.participants.write().await.push(participant);
    }

    /// Create a fully connected network of participants
    pub fn create_network(count: u16) -> Vec<(Self, mpsc::Sender<ProtocolMessage>)> {
        let mut nodes: Vec<(Self, mpsc::Sender<ProtocolMessage>)> = (1..=count)
            .map(|id| Self::new(ParticipantId(id)))
            .collect();

        // Connect all nodes to each other
        let senders: Vec<_> = nodes.iter().map(|(_, tx)| tx.clone()).collect();
        let ids: Vec<_> = nodes.iter().map(|(n, _)| n.local_id).collect();

        for (network, _) in &mut nodes {
            for (id, sender) in ids.iter().zip(senders.iter()) {
                if *id != network.local_id {
                    let channels = network.channels.clone();
                    let participants = network.participants.clone();
                    let sender_clone = sender.clone();
                    let id_clone = *id;

                    tokio::spawn(async move {
                        channels.write().await.insert(id_clone, sender_clone);
                        participants.write().await.push(id_clone);
                    });
                }
            }
        }

        nodes
    }
}

#[async_trait]
impl NetworkInterface for InMemoryNetwork {
    async fn broadcast(&self, message: ProtocolMessage) -> Result<()> {
        let channels = self.channels.read().await;

        for (id, sender) in channels.iter() {
            if *id != self.local_id {
                sender.send(message.clone()).await
                    .map_err(|e| MpcError::NetworkError(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn send(&self, participant: ParticipantId, message: ProtocolMessage) -> Result<()> {
        let channels = self.channels.read().await;

        let sender = channels.get(&participant)
            .ok_or_else(|| MpcError::NetworkError(format!("Unknown participant: {}", participant.0)))?;

        sender.send(message).await
            .map_err(|e| MpcError::NetworkError(e.to_string()))
    }

    async fn receive(&self) -> Result<ProtocolMessage> {
        let mut receiver = self.receiver.write().await;

        receiver.recv().await
            .ok_or_else(|| MpcError::NetworkError("Channel closed".into()))
    }

    async fn get_participants(&self) -> Result<Vec<ParticipantId>> {
        Ok(self.participants.read().await.clone())
    }

    fn local_participant_id(&self) -> ParticipantId {
        self.local_id
    }
}

/// gRPC-based network for production use
#[cfg(feature = "grpc")]
pub mod grpc {
    use super::*;
    use tonic::{transport::Server, Request, Response, Status};

    // gRPC service definitions would go here
    // This would use tonic-build to generate from proto files
}

/// Message router for handling incoming protocol messages
pub struct MessageRouter {
    /// Handler functions for each message type
    handlers: HashMap<String, Box<dyn Fn(ProtocolMessage) -> Result<()> + Send + Sync>>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a message type
    pub fn register_handler<F>(&mut self, message_type: &str, handler: F)
    where
        F: Fn(ProtocolMessage) -> Result<()> + Send + Sync + 'static,
    {
        self.handlers.insert(message_type.to_string(), Box::new(handler));
    }

    /// Route a message to its handler
    pub fn route(&self, message: ProtocolMessage) -> Result<()> {
        let message_type = match &message {
            ProtocolMessage::DkgCommitment { .. } => "dkg_commitment",
            ProtocolMessage::DkgShare { .. } => "dkg_share",
            ProtocolMessage::DkgVerification { .. } => "dkg_verification",
            ProtocolMessage::DkgComplete { .. } => "dkg_complete",
            ProtocolMessage::SigningNonceCommitment { .. } => "signing_nonce",
            ProtocolMessage::SigningShare { .. } => "signing_share",
            ProtocolMessage::SigningComplete { .. } => "signing_complete",
            ProtocolMessage::Error { .. } => "error",
        };

        if let Some(handler) = self.handlers.get(message_type) {
            handler(message)
        } else {
            Err(MpcError::NetworkError(format!("No handler for message type: {}", message_type)))
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DWalletId;

    #[tokio::test]
    async fn test_in_memory_network_creation() {
        let (network, _sender) = InMemoryNetwork::new(ParticipantId(1));
        assert_eq!(network.local_participant_id().value(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_network_send_receive() {
        let (network1, sender1) = InMemoryNetwork::new(ParticipantId(1));
        let (network2, sender2) = InMemoryNetwork::new(ParticipantId(2));

        // Register each other
        network1.register_participant(ParticipantId(2), sender2).await;
        network2.register_participant(ParticipantId(1), sender1).await;

        // Send a message
        let message = ProtocolMessage::DkgComplete {
            dwallet_id: DWalletId::generate(),
            public_key: vec![1, 2, 3],
        };

        network1.send(ParticipantId(2), message.clone()).await.unwrap();

        // Receive the message
        let received = network2.receive().await.unwrap();

        match received {
            ProtocolMessage::DkgComplete { public_key, .. } => {
                assert_eq!(public_key, vec![1, 2, 3]);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_broadcast() {
        let (network1, sender1) = InMemoryNetwork::new(ParticipantId(1));
        let (network2, sender2) = InMemoryNetwork::new(ParticipantId(2));
        let (network3, sender3) = InMemoryNetwork::new(ParticipantId(3));

        // Connect all networks
        network1.register_participant(ParticipantId(2), sender2.clone()).await;
        network1.register_participant(ParticipantId(3), sender3.clone()).await;
        network2.register_participant(ParticipantId(1), sender1.clone()).await;
        network2.register_participant(ParticipantId(3), sender3).await;
        network3.register_participant(ParticipantId(1), sender1).await;
        network3.register_participant(ParticipantId(2), sender2).await;

        // Broadcast from network1
        let message = ProtocolMessage::DkgComplete {
            dwallet_id: DWalletId::generate(),
            public_key: vec![1, 2, 3],
        };

        network1.broadcast(message).await.unwrap();

        // Both network2 and network3 should receive
        let received2 = network2.receive().await.unwrap();
        let received3 = network3.receive().await.unwrap();

        match (received2, received3) {
            (
                ProtocolMessage::DkgComplete { public_key: pk2, .. },
                ProtocolMessage::DkgComplete { public_key: pk3, .. },
            ) => {
                assert_eq!(pk2, vec![1, 2, 3]);
                assert_eq!(pk3, vec![1, 2, 3]);
            }
            _ => panic!("Wrong message types"),
        }
    }
}
