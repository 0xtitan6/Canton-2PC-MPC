//! Event handling for Canton ledger events

use crate::daml_types::*;
use crate::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Events emitted by the Canton integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CantonEvent {
    /// New dWallet created
    DWalletCreated {
        dwallet_id: String,
        owner: String,
        signature_type: String,
    },

    /// dWallet is ready (DKG complete)
    DWalletReady {
        dwallet_id: String,
        public_key: String,
        addresses: Vec<(String, String)>,
    },

    /// Sign request submitted
    SignRequested {
        request_id: String,
        dwallet_id: String,
        chain: String,
    },

    /// Sign request completed
    SignCompleted {
        request_id: String,
        dwallet_id: String,
        signature: String,
    },

    /// Transfer initiated
    TransferInitiated {
        request_id: String,
        dwallet_id: String,
        chain: String,
        destination: String,
        amount: String,
    },

    /// Transfer completed
    TransferCompleted {
        request_id: String,
        tx_hash: String,
    },

    /// Error occurred
    Error {
        context: String,
        message: String,
    },
}

/// Event publisher for Canton events
pub struct EventPublisher {
    sender: mpsc::Sender<CantonEvent>,
}

impl EventPublisher {
    pub fn new(sender: mpsc::Sender<CantonEvent>) -> Self {
        Self { sender }
    }

    pub async fn publish(&self, event: CantonEvent) -> Result<()> {
        self.sender
            .send(event)
            .await
            .map_err(|e| crate::CantonError::LedgerApi(e.to_string()))
    }

    pub async fn dwallet_created(&self, dwallet_id: &str, owner: &str, sig_type: &str) -> Result<()> {
        self.publish(CantonEvent::DWalletCreated {
            dwallet_id: dwallet_id.to_string(),
            owner: owner.to_string(),
            signature_type: sig_type.to_string(),
        })
        .await
    }

    pub async fn sign_completed(&self, request_id: &str, dwallet_id: &str, signature: &[u8]) -> Result<()> {
        self.publish(CantonEvent::SignCompleted {
            request_id: request_id.to_string(),
            dwallet_id: dwallet_id.to_string(),
            signature: hex::encode(signature),
        })
        .await
    }

    pub async fn transfer_completed(&self, request_id: &str, tx_hash: &str) -> Result<()> {
        self.publish(CantonEvent::TransferCompleted {
            request_id: request_id.to_string(),
            tx_hash: tx_hash.to_string(),
        })
        .await
    }

    pub async fn error(&self, context: &str, message: &str) -> Result<()> {
        self.publish(CantonEvent::Error {
            context: context.to_string(),
            message: message.to_string(),
        })
        .await
    }
}

/// Event subscriber for Canton events
pub struct EventSubscriber {
    receiver: mpsc::Receiver<CantonEvent>,
}

impl EventSubscriber {
    pub fn new(receiver: mpsc::Receiver<CantonEvent>) -> Self {
        Self { receiver }
    }

    pub async fn recv(&mut self) -> Option<CantonEvent> {
        self.receiver.recv().await
    }
}

/// Create a new event channel
pub fn event_channel(buffer: usize) -> (EventPublisher, EventSubscriber) {
    let (sender, receiver) = mpsc::channel(buffer);
    (EventPublisher::new(sender), EventSubscriber::new(receiver))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_channel() {
        let (publisher, mut subscriber) = event_channel(100);

        publisher
            .dwallet_created("wallet1", "party1", "ecdsa")
            .await
            .unwrap();

        let event = subscriber.recv().await.unwrap();
        match event {
            CantonEvent::DWalletCreated { dwallet_id, .. } => {
                assert_eq!(dwallet_id, "wallet1");
            }
            _ => panic!("Wrong event type"),
        }
    }
}
