//! Minimal message bus abstraction for multi-party ceremonies.
//!
//! Phase 1 ships a single in-process impl backed by `tokio::sync::broadcast`.
//! Phase 2 will add a `CantonBus` that submits commands to the Ledger API and
//! streams transactions back — the [`MessageBus`] trait is deliberately kept
//! narrow so that swap is mechanical.
//!
//! **Subscription ordering matters.** A `broadcast` channel only delivers
//! messages to receivers that exist at publish time. Callers must obtain all
//! [`Subscription`] handles *before* the first `publish` call, or early
//! messages will be lost. [`crate::session`] takes care of this sequencing.

use commitment::CommitmentSizedNumber;
use group::PartyID;
use tokio::sync::broadcast;

/// The three phases in which network (decentralized) parties exchange messages.
/// Centralized/client rounds are local and never hit the bus.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Dkg,
    Presign,
    Sign,
}

/// A wire-framed protocol message. The `payload` is a `bcs`-serialized
/// `P::Message` (where `P` is one of inkrypto's `AsynchronouslyAdvanceable`
/// party types) so the actor on the other side can round-trip it.
#[derive(Clone, Debug)]
pub struct WireMessage {
    pub session_id: CommitmentSizedNumber,
    pub stage: Stage,
    pub round: u64,
    pub sender: PartyID,
    pub payload: Vec<u8>,
}

/// A subscriber handle for one consumer. Hand one of these to each actor
/// *before* any `publish` is issued.
pub struct Subscription {
    rx: broadcast::Receiver<WireMessage>,
}

impl Subscription {
    /// Receive the next message, skipping any the receiver lagged past.
    pub async fn recv(&mut self) -> Option<WireMessage> {
        loop {
            match self.rx.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// In-process broadcast bus backed by `tokio::sync::broadcast`.
///
/// Every publish fans out to every currently-subscribed [`Subscription`].
/// `capacity` is the per-receiver backlog; pick something larger than the
/// maximum number of messages one party can fall behind by (for a 4-round
/// presign over ~10 parties, 256 is plenty).
pub struct InProcessBus {
    tx: broadcast::Sender<WireMessage>,
}

impl InProcessBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Register a new subscriber. Must be called before any [`Self::publish`]
    /// whose messages this subscriber needs to see.
    pub fn subscribe(&self) -> Subscription {
        Subscription {
            rx: self.tx.subscribe(),
        }
    }

    /// Fan a message out to every current subscriber. Returns the number of
    /// subscribers it reached (0 is fine; it means nobody is listening yet).
    pub fn publish(&self, msg: WireMessage) -> usize {
        self.tx.send(msg).unwrap_or(0)
    }
}
