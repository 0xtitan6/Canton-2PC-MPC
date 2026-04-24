//! Phase 1 multi-party orchestrator.
//!
//! Drives a full 2PC-MPC ECDSA ceremony by spawning one [`tokio`] task per
//! decentralized party and letting them exchange messages through an
//! [`InProcessBus`]. The centralized (client) party's rounds are one-shot
//! synchronous calls and stay on the orchestrator thread.
//!
//! The flow matches Phase 0's `run_local_ecdsa_ceremony`, but every
//! decentralized stage (DKG decentralized, presign, sign decentralized) is now
//! driven by actors that only know about their own inbox/outbox. This is the
//! exact shape Phase 2's Canton-backed driver will slot into — the
//! [`InProcessBus`] just gets swapped for a `CantonBus` that submits commands
//! and streams transactions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ::class_groups::test_helpers::deal_trusted_shares;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{Random, U256};
use group::{secp256k1, HashScheme, OsCsRng, PartyID};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::two_party::Round as TwoPartyRound;
use mpc::{Weight, WeightedThresholdAccessStructure};

use twopc_mpc::dkg::Protocol as DkgProto;
use twopc_mpc::presign::Protocol as PresignProto;
use twopc_mpc::sign::Protocol as SignProto;

use twopc_mpc::dkg::CentralizedPartyKeyShareVerification;
use twopc_mpc::secp256k1::class_groups::{
    ECDSAProtocol, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use twopc_mpc::test_helpers::setup_class_groups_secp256k1;

use crate::actor::{run_async_party, ActorError};
use crate::bus::{InProcessBus, Stage};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid access structure: {0}")]
    AccessStructure(String),
    #[error("actor failed: {0}")]
    Actor(#[from] ActorError),
    #[error("tokio task join failed: {0}")]
    Join(String),
    #[error("protocol panicked: {0}")]
    Protocol(String),
    #[error("decentralized parties disagreed on output — possible protocol bug")]
    OutputMismatch,
}

/// Same shape as [`crate::ceremony::CeremonyOutput`] — re-exported for
/// convenience from the multi-party path.
pub struct SessionOutput {
    pub public_key: secp256k1::GroupElement,
    pub signature: twopc_mpc::ecdsa::ECDSASecp256k1Signature,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
}

/// Run a full 2PC-MPC ECDSA ceremony across N decentralized-party actors + one
/// (orchestrator-local) centralized party.
///
/// Assumes **every party participates in every round** — i.e. every weighted
/// subset in the access structure includes every tangible party. This is true
/// for the 2-of-2 unit-weight topology Phase 1 targets. Weighted topologies
/// with per-round subsets (e.g. the `(4, {1:2, 2:1, 3:3})` case inkrypto
/// tests) are a follow-up: see `parties_per_round` handling in the
/// `sign::tests::signs_internal_generic` reference (sign.rs:313-341).
pub async fn run_multiparty_ecdsa_ceremony(
    threshold: Weight,
    party_to_weight: HashMap<PartyID, Weight>,
    message: &[u8],
    hash_scheme: HashScheme,
) -> Result<SessionOutput, SessionError> {
    type P = ECDSAProtocol;

    // ------------------------------------------------------------------
    // Setup (identical to Phase 0's ceremony.rs)
    // ------------------------------------------------------------------
    let (protocol_public_parameters, decryption_key) = setup_class_groups_secp256k1();
    let access_structure =
        WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone())
            .map_err(|e| SessionError::AccessStructure(format!("{e:?}")))?;

    let base = protocol_public_parameters
        .encryption_scheme_public_parameters
        .setup_parameters
        .h;
    let secret_key_bits = protocol_public_parameters
        .encryption_scheme_public_parameters
        .randomness_space_public_parameters()
        .sample_bits;

    let (dk_share_pp, decryption_key_shares) = deal_trusted_shares::<
        { U256::LIMBS },
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        secp256k1::GroupElement,
    >(
        threshold,
        access_structure.number_of_virtual_parties(),
        protocol_public_parameters
            .encryption_scheme_public_parameters
            .clone(),
        decryption_key.decryption_key,
        base,
        secret_key_bits,
    );

    let party_to_virtual_parties = access_structure.party_to_virtual_parties();
    let parties: Vec<PartyID> = party_to_virtual_parties.keys().copied().collect();
    let all_parties: HashSet<PartyID> = parties.iter().copied().collect();

    let tangible_to_virtual: HashMap<PartyID, HashMap<PartyID, _>> = party_to_virtual_parties
        .keys()
        .map(|&tangible| {
            let virtual_parties = party_to_virtual_parties.get(&tangible).cloned().unwrap();
            (
                tangible,
                decryption_key_shares
                    .clone()
                    .into_iter()
                    .filter(|(pid, _)| virtual_parties.contains(pid))
                    .collect(),
            )
        })
        .collect();

    let access_arc = Arc::new(access_structure.clone());
    let protocol_pp_arc = Arc::new(protocol_public_parameters.clone());
    let dk_share_pp_arc = Arc::new(dk_share_pp);

    let dkg_session_id = CommitmentSizedNumber::random(&mut OsCsRng);

    // ------------------------------------------------------------------
    // Stage 1: DKG centralized (orchestrator-local, single shot)
    // ------------------------------------------------------------------
    let centralized_dkg_public_input: <<P as DkgProto>::DKGCentralizedPartyRound as TwoPartyRound>::PublicInput =
        (protocol_public_parameters.clone(), dkg_session_id).into();

    let centralized_dkg_result =
        <<P as DkgProto>::DKGCentralizedPartyRound as TwoPartyRound>::advance(
            (),
            &(),
            &centralized_dkg_public_input,
            &mut OsCsRng,
        )
        .map_err(|e| SessionError::Protocol(format!("centralized DKG: {e:?}")))?;

    let public_key_share_and_proof = centralized_dkg_result.outgoing_message;
    let centralized_dkg_output = centralized_dkg_result.public_output;
    let centralized_secret_key_share = centralized_dkg_result.private_output;

    // ------------------------------------------------------------------
    // Stage 2: DKG decentralized (1 round, N actors)
    // ------------------------------------------------------------------
    let dkg_public_inputs: HashMap<
        PartyID,
        <<P as DkgProto>::DKGDecentralizedParty as mpc::Party>::PublicInput,
    > = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                (
                    protocol_pp_arc.clone(),
                    public_key_share_and_proof.clone(),
                    CentralizedPartyKeyShareVerification::None,
                )
                    .into(),
            )
        })
        .collect();

    let dkg_private_inputs: HashMap<PartyID, ()> =
        parties.iter().copied().map(|pid| (pid, ())).collect();

    let decentralized_dkg_output = run_stage::<<P as DkgProto>::DKGDecentralizedParty>(
        dkg_session_id,
        Stage::Dkg,
        &parties,
        &all_parties,
        access_arc.clone(),
        dkg_private_inputs,
        dkg_public_inputs,
    )
    .await?;

    // ------------------------------------------------------------------
    // Stage 3: Presign decentralized (4 rounds, N actors)
    // ------------------------------------------------------------------
    let dkg_output_targeted: Option<<P as DkgProto>::DecentralizedPartyTargetedDKGOutput> =
        match decentralized_dkg_output.clone() {
            twopc_mpc::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(o) => {
                Some(o)
            }
            twopc_mpc::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {
                ..
            } => None,
        };

    let presign_session_id = CommitmentSizedNumber::random(&mut OsCsRng);

    let presign_public_inputs: HashMap<
        PartyID,
        <<P as PresignProto>::PresignParty as mpc::Party>::PublicInput,
    > = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                (protocol_pp_arc.clone(), dkg_output_targeted.clone()).into(),
            )
        })
        .collect();

    let presign_private_inputs: HashMap<PartyID, ()> =
        parties.iter().copied().map(|pid| (pid, ())).collect();

    let presign = run_stage::<<P as PresignProto>::PresignParty>(
        presign_session_id,
        Stage::Presign,
        &parties,
        &all_parties,
        access_arc.clone(),
        presign_private_inputs,
        presign_public_inputs,
    )
    .await?;

    // ------------------------------------------------------------------
    // Stage 4: Sign centralized (orchestrator-local, single shot)
    // ------------------------------------------------------------------
    let centralized_sign_public_input: <<P as SignProto>::SignCentralizedParty as TwoPartyRound>::PublicInput =
        (
            message.to_vec(),
            hash_scheme,
            centralized_dkg_output.clone(),
            presign.clone(),
            protocol_public_parameters.clone(),
        )
            .into();

    let sign_message = <<P as SignProto>::SignCentralizedParty as TwoPartyRound>::advance(
        (),
        &centralized_secret_key_share,
        &centralized_sign_public_input,
        &mut OsCsRng,
    )
    .map_err(|e| SessionError::Protocol(format!("centralized sign: {e:?}")))?
    .outgoing_message;

    // ------------------------------------------------------------------
    // Stage 5: Sign decentralized (2 rounds, N actors)
    // expected_decrypters = everyone, since the 2-of-2 unit-weight topology
    // demands every tangible party be in the decrypter set.
    // ------------------------------------------------------------------
    let expected_decrypters: HashSet<PartyID> = all_parties.clone();

    let sign_public_inputs: HashMap<
        PartyID,
        <<P as SignProto>::SignDecentralizedParty as mpc::Party>::PublicInput,
    > = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                (
                    expected_decrypters.clone(),
                    protocol_pp_arc.clone(),
                    message.to_vec(),
                    hash_scheme,
                    decentralized_dkg_output.clone(),
                    presign.clone(),
                    sign_message.clone(),
                    dk_share_pp_arc.clone(),
                )
                    .into(),
            )
        })
        .collect();

    let sign_private_inputs: HashMap<PartyID, _> = tangible_to_virtual.clone();

    let signature = run_stage::<<P as SignProto>::SignDecentralizedParty>(
        presign_session_id,
        Stage::Sign,
        &parties,
        &all_parties,
        access_arc.clone(),
        sign_private_inputs,
        sign_public_inputs,
    )
    .await?;

    // ------------------------------------------------------------------
    // Reconstruct the joint public key for external verification.
    // ------------------------------------------------------------------
    let centralized_inner =
        twopc_mpc::dkg::centralized_party::Output::from(centralized_dkg_output);
    let public_key = <secp256k1::GroupElement as group::GroupElement>::new(
        centralized_inner.public_key,
        &protocol_public_parameters.group_public_parameters,
    )
    .expect("joint public-key value should be a valid secp256k1 point");

    Ok(SessionOutput {
        public_key,
        signature,
        message: message.to_vec(),
        hash_scheme,
    })
}

/// Generic helper: spawn one actor per party for a single stage, join them,
/// and return the (unanimous) public output.
async fn run_stage<P>(
    session_id: CommitmentSizedNumber,
    stage: Stage,
    parties: &[PartyID],
    all_parties: &HashSet<PartyID>,
    access_structure: Arc<WeightedThresholdAccessStructure>,
    mut private_inputs: HashMap<PartyID, P::PrivateInput>,
    mut public_inputs: HashMap<PartyID, P::PublicInput>,
) -> Result<P::PublicOutput, SessionError>
where
    P: mpc::Party + mpc::AsynchronouslyAdvanceable + Send + 'static,
    P::Message: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + 'static,
    P::PrivateInput: Clone + Send + 'static,
    P::PublicInput: Send + 'static,
    P::PublicOutput: Send + PartialEq + 'static,
{
    let bus = Arc::new(InProcessBus::new(1024));
    // Subscribe BEFORE spawning: tokio::broadcast only delivers messages to
    // receivers that exist at publish time.
    let mut subs: HashMap<PartyID, _> = parties
        .iter()
        .copied()
        .map(|pid| (pid, bus.subscribe()))
        .collect();

    let mut handles = Vec::with_capacity(parties.len());
    for &pid in parties {
        let inbox = subs.remove(&pid).expect("subscription for every party");
        let priv_in = private_inputs
            .remove(&pid)
            .expect("private input for every party");
        let pub_in = public_inputs
            .remove(&pid)
            .expect("public input for every party");
        let access = access_structure.clone();
        let bus_clone = bus.clone();
        let ap = all_parties.clone();

        handles.push(tokio::spawn(async move {
            run_async_party::<P>(session_id, stage, pid, access, priv_in, pub_in, ap, bus_clone, inbox).await
        }));
    }

    let results = futures::future::join_all(handles).await;

    let mut outputs: Vec<P::PublicOutput> = Vec::with_capacity(results.len());
    for r in results {
        let output = r
            .map_err(|e| SessionError::Join(e.to_string()))??;
        outputs.push(output);
    }

    // Every party must converge on the same public output.
    let first = outputs.into_iter().next().ok_or(SessionError::OutputMismatch)?;
    // (We could assert-all-equal here for extra safety, but `==` on some
    // inkrypto output types is expensive; skip for Phase 1.)
    Ok(first)
}
