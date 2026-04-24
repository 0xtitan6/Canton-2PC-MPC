//! Per-party actor that drives one inkrypto `AsynchronouslyAdvanceable` state
//! machine by reading messages from a [`Subscription`] and publishing its own
//! outgoing messages to an [`InProcessBus`].
//!
//! The actor runs in its own `tokio` task. Within one ceremony stage (DKG /
//! presign / sign-decentralized) every participating party spawns one of these;
//! together they replace the synchronous `mpc::test_helpers` round-driver loop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use commitment::CommitmentSizedNumber;
use group::{OsCsRng, PartyID};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::bus::{InProcessBus, Stage, Subscription, WireMessage};

#[derive(Debug, thiserror::Error)]
pub enum ActorError {
    #[error("bus closed before round {0} could gather a quorum")]
    BusClosed(u64),
    #[error("bcs serialization failed: {0}")]
    Serialization(#[from] bcs::Error),
    #[error("party {party} advance failed at round {round}: {detail}")]
    Protocol {
        party: PartyID,
        round: u64,
        detail: String,
    },
}

/// Drive one party's state machine to completion.
///
/// `all_parties` is the set of party IDs that this round expects messages
/// from. For the 2-of-2 unit-weight topology Phase 1 targets, that's simply
/// the full tangible-party set, so every party publishes in every round and
/// awaits messages from every other party. Weighted topologies with per-round
/// subsets are Phase 1.5 — the actor assumes uniform participation for now.
///
/// Returns the party's `PublicOutput` once it yields `Finalize`.
pub async fn run_async_party<P>(
    session_id: CommitmentSizedNumber,
    stage: Stage,
    party_id: PartyID,
    access_structure: Arc<WeightedThresholdAccessStructure>,
    private_input: P::PrivateInput,
    public_input: P::PublicInput,
    all_parties: HashSet<PartyID>,
    bus: Arc<InProcessBus>,
    mut inbox: Subscription,
) -> Result<P::PublicOutput, ActorError>
where
    P: mpc::Party + AsynchronouslyAdvanceable,
    P::Message: serde::Serialize + for<'de> serde::Deserialize<'de>,
    P::PrivateInput: Clone,
{
    let mut collected: Vec<HashMap<PartyID, P::Message>> = Vec::new();

    loop {
        let current_round = (collected.len() + 1) as u64;

        let res = P::advance(
            session_id,
            party_id,
            access_structure.as_ref(),
            collected.clone(),
            Some(private_input.clone()),
            &public_input,
            &mut OsCsRng,
        )
        .map_err(|e| ActorError::Protocol {
            party: party_id,
            round: current_round,
            detail: format!("{e:?}"),
        })?;

        match res {
            AsynchronousRoundResult::Advance { message, .. } => {
                // Publish our outgoing message to the bus.
                let payload = bcs::to_bytes(&message)?;
                bus.publish(WireMessage {
                    session_id,
                    stage,
                    round: current_round,
                    sender: party_id,
                    payload,
                });

                // Gather a full round: one message per participating party,
                // including our own (inkrypto expects all parties' messages
                // in its `collected` slot for the next round).
                let mut round_msgs: HashMap<PartyID, P::Message> = HashMap::new();
                round_msgs.insert(party_id, message);
                while round_msgs.len() < all_parties.len() {
                    let bm = inbox
                        .recv()
                        .await
                        .ok_or(ActorError::BusClosed(current_round))?;
                    if bm.session_id == session_id
                        && bm.stage == stage
                        && bm.round == current_round
                        && all_parties.contains(&bm.sender)
                        && !round_msgs.contains_key(&bm.sender)
                    {
                        let msg: P::Message = bcs::from_bytes(&bm.payload)?;
                        round_msgs.insert(bm.sender, msg);
                    }
                }
                collected.push(round_msgs);
            }
            AsynchronousRoundResult::Finalize { public_output, .. } => {
                return Ok(public_output);
            }
        }
    }
}
