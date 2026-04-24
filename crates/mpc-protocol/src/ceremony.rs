//! In-process 2PC-MPC ECDSA ceremony over secp256k1 class groups.
//!
//! Phase 0: exercises inkrypto end-to-end — DKG (trusted dealer), presign, sign —
//! by driving each round locally via the public `mpc::test_helpers` driver. Runs a
//! single "client" (centralized party) plus `n` "network" (decentralized) parties
//! inside one process. Succeeding here proves the crypto stack, the dependency pins,
//! and the `[patch.crates-io]` replacements are all wired correctly. Later phases
//! will split these parties across processes and thread messages through the Canton
//! Ledger API as the broadcast channel.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;

// inkrypto imports
use ::class_groups::test_helpers::deal_trusted_shares;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{Random, U256};
use group::{secp256k1, HashScheme, OsCsRng, PartyID};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::test_helpers::{
    asynchronous_session_terminates_successfully,
    asynchronous_session_with_malicious_parties_terminates_successfully_internal,
};
use mpc::two_party::Round as TwoPartyRound;
use mpc::{Weight, WeightedThresholdAccessStructure};

// The three `Protocol` traits are separate; alias to disambiguate.
use twopc_mpc::dkg::Protocol as DkgProto;
use twopc_mpc::presign::Protocol as PresignProto;
use twopc_mpc::sign::Protocol as SignProto;

use twopc_mpc::dkg::CentralizedPartyKeyShareVerification;
use twopc_mpc::secp256k1::class_groups::{
    ECDSAProtocol, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use twopc_mpc::test_helpers::setup_class_groups_secp256k1;

/// Output of a successful ceremony.
pub struct CeremonyOutput {
    /// The jointly-computed ECDSA public key as a secp256k1 group element.
    pub public_key: secp256k1::GroupElement,
    /// The ECDSA signature in inkrypto's native type. Use
    /// `ECDSASecp256k1Signature::signature()` for a `k256::ecdsa::Signature` and
    /// `.recovery_id()` for the recovery byte.
    pub signature: twopc_mpc::ecdsa::ECDSASecp256k1Signature,
    /// The message that was signed (echoed for test convenience).
    pub message: Vec<u8>,
    /// The hash scheme used.
    pub hash_scheme: HashScheme,
}

#[derive(Debug, Error)]
pub enum CeremonyError {
    #[error("invalid access structure: {0}")]
    AccessStructure(String),
}

/// Run a full 2PC-MPC ECDSA ceremony locally and return the signature.
pub fn run_local_ecdsa_ceremony(
    threshold: Weight,
    party_to_weight: HashMap<PartyID, Weight>,
    message: &[u8],
    hash_scheme: HashScheme,
) -> Result<CeremonyOutput, CeremonyError> {
    type P = ECDSAProtocol;

    // ------------------------------------------------------------------
    // 1. Class-groups setup + access structure
    // ------------------------------------------------------------------
    let (protocol_public_parameters, decryption_key) = setup_class_groups_secp256k1();

    let access_structure = WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone())
        .map_err(|e| CeremonyError::AccessStructure(format!("{e:?}")))?;

    let base = protocol_public_parameters
        .encryption_scheme_public_parameters
        .setup_parameters
        .h;
    let secret_key_bits = protocol_public_parameters
        .encryption_scheme_public_parameters
        .randomness_space_public_parameters()
        .sample_bits;

    let (decryption_key_share_public_parameters, decryption_key_shares) = deal_trusted_shares::<
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
    let tangible_to_virtual_decryption_shares: HashMap<PartyID, HashMap<PartyID, _>> =
        party_to_virtual_parties
            .keys()
            .map(|&tangible_party_id| {
                let virtual_parties = party_to_virtual_parties
                    .get(&tangible_party_id)
                    .cloned()
                    .unwrap();
                (
                    tangible_party_id,
                    decryption_key_shares
                        .clone()
                        .into_iter()
                        .filter(|(pid, _)| virtual_parties.contains(pid))
                        .collect(),
                )
            })
            .collect();

    let dkg_session_id = CommitmentSizedNumber::random(&mut OsCsRng);

    // ------------------------------------------------------------------
    // 2. DKG — centralized (client) party, single round
    // ------------------------------------------------------------------
    let centralized_public_input: <<P as DkgProto>::DKGCentralizedPartyRound as TwoPartyRound>::PublicInput =
        (protocol_public_parameters.clone(), dkg_session_id).into();

    let centralized_dkg_result =
        <<P as DkgProto>::DKGCentralizedPartyRound as TwoPartyRound>::advance(
            (),
            &(),
            &centralized_public_input,
            &mut OsCsRng,
        )
        .expect("centralized DKG round failed");

    let public_key_share_and_proof = centralized_dkg_result.outgoing_message;
    let centralized_dkg_output = centralized_dkg_result.public_output;
    let centralized_secret_key_share = centralized_dkg_result.private_output;

    // ------------------------------------------------------------------
    // 3. DKG — decentralized parties, 1-round async session
    // ------------------------------------------------------------------
    let parties: Vec<PartyID> = party_to_virtual_parties.keys().copied().collect();
    let dkg_private_inputs: HashMap<PartyID, ()> =
        parties.iter().copied().map(|pid| (pid, ())).collect();

    let protocol_public_parameters_arc = Arc::new(protocol_public_parameters.clone());

    let dkg_public_inputs: HashMap<
        PartyID,
        <<P as DkgProto>::DKGDecentralizedParty as mpc::Party>::PublicInput,
    > = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                (
                    protocol_public_parameters_arc.clone(),
                    public_key_share_and_proof.clone(),
                    CentralizedPartyKeyShareVerification::None,
                )
                    .into(),
            )
        })
        .collect();

    let decentralized_dkg_output =
        asynchronous_session_terminates_successfully::<<P as DkgProto>::DKGDecentralizedParty>(
            dkg_session_id,
            &access_structure,
            dkg_private_inputs.clone(),
            dkg_public_inputs,
            /* number_of_rounds */ 1,
        );

    // ------------------------------------------------------------------
    // 4. Presign — 4 rounds async
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
                (
                    protocol_public_parameters_arc.clone(),
                    dkg_output_targeted.clone(),
                )
                    .into(),
            )
        })
        .collect();

    let presign = asynchronous_session_terminates_successfully::<<P as PresignProto>::PresignParty>(
        presign_session_id,
        &access_structure,
        dkg_private_inputs.clone(),
        presign_public_inputs,
        /* number_of_rounds */ 4,
    );

    // ------------------------------------------------------------------
    // 5. Sign — centralized (client) party, single round
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
    .expect("centralized sign round failed")
    .outgoing_message;

    // ------------------------------------------------------------------
    // 6. Sign — decentralized, 2-round async with decrypter subset
    // ------------------------------------------------------------------
    // Build the minimum authorized decrypter subset (mirrors sign.rs:296-311).
    let mut expected_decrypters: std::collections::HashSet<PartyID> =
        std::collections::HashSet::new();
    let mut candidate_id: PartyID = 1;
    loop {
        expected_decrypters.insert(candidate_id);
        let virtual_parties = access_structure
            .virtual_subset(expected_decrypters.clone())
            .unwrap();
        if virtual_parties.len() >= access_structure.threshold as usize {
            break;
        }
        candidate_id += 1;
    }
    let parties_per_round = HashMap::from([(1u64, expected_decrypters.clone())]);

    let decryption_key_share_pp_arc = Arc::new(decryption_key_share_public_parameters);

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
                    protocol_public_parameters_arc.clone(),
                    message.to_vec(),
                    hash_scheme,
                    decentralized_dkg_output.clone(),
                    presign.clone(),
                    sign_message.clone(),
                    decryption_key_share_pp_arc.clone(),
                )
                    .into(),
            )
        })
        .collect();

    let (_t, _ts, signature) =
        asynchronous_session_with_malicious_parties_terminates_successfully_internal::<
            <P as SignProto>::SignDecentralizedParty,
            <P as SignProto>::SignDecentralizedParty,
        >(
            presign_session_id,
            &access_structure,
            tangible_to_virtual_decryption_shares,
            sign_public_inputs,
            /* malicious_parties_by_round */ HashMap::new(),
            /* number_of_rounds */ 2,
            parties_per_round,
            /* bench_separately */ true,
            /* debug */ false,
        );

    // ------------------------------------------------------------------
    // 7. Reconstruct the joint public key as a typed secp256k1 point
    // ------------------------------------------------------------------
    let centralized_inner = twopc_mpc::dkg::centralized_party::Output::from(centralized_dkg_output);
    let public_key = <secp256k1::GroupElement as group::GroupElement>::new(
        centralized_inner.public_key,
        &protocol_public_parameters.group_public_parameters,
    )
    .expect("joint public-key value is not a valid secp256k1 point");

    Ok(CeremonyOutput {
        public_key,
        signature,
        message: message.to_vec(),
        hash_scheme,
    })
}
