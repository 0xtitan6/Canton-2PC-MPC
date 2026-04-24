//! Phase 1 end-to-end test:
//!   1. Run the DKG → presign → sign ceremony with **one tokio task per
//!      decentralized party** exchanging messages over an in-process broadcast bus.
//!   2. Verify the resulting signature two ways — once through inkrypto's own
//!      verifier, once through stock `k256`. Both must agree.

use std::collections::HashMap;

use group::HashScheme;
use mpc_protocol::run_multiparty_ecdsa_ceremony;

#[tokio::test]
async fn phase1_multiparty_ecdsa_ceremony_produces_valid_signature() {
    let _ = tracing_subscriber::fmt::try_init();

    // Same 2-of-2 unit-weight topology as Phase 0 so the two paths are
    // directly comparable. Every party participates in every round.
    let threshold = 2u16;
    let party_to_weight: HashMap<u16, u16> = HashMap::from([(1, 1), (2, 1)]);
    let message = b"canton 2pc-mpc phase 1 multi-actor";

    let out = run_multiparty_ecdsa_ceremony(threshold, party_to_weight, message, HashScheme::SHA256)
        .await
        .expect("multi-party ceremony should succeed");

    // --- native inkrypto verification ---
    use twopc_mpc::ecdsa::VerifyingKey;
    VerifyingKey::<{ group::secp256k1::SCALAR_LIMBS }>::verify(
        &out.public_key,
        &out.message,
        out.hash_scheme,
        &out.signature,
    )
    .expect("inkrypto's own verifier rejected a signature it produced");

    // --- external k256 verification ---
    let k256_sig = out
        .signature
        .signature()
        .expect("inkrypto signature should round-trip to k256::ecdsa::Signature");

    let sec1_compressed: Vec<u8> = bcs::to_bytes(&group::GroupElement::value(&out.public_key))
        .expect("group-element value serializes");
    let k256_vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(trim_bcs_len_prefix(&sec1_compressed))
        .expect("joint public key should decode as a k256 verifying key");

    use sha2::Digest;
    let digest = sha2::Sha256::digest(&out.message);
    ecdsa::signature::hazmat::PrehashVerifier::verify_prehash(&k256_vk, &digest, &k256_sig)
        .expect("stock k256 verifier rejected the multi-party 2PC-MPC signature");

    println!(
        "Phase 1 multi-actor ceremony OK: public_key (SEC1) = {}, signature r||s = {}",
        hex::encode(trim_bcs_len_prefix(&sec1_compressed)),
        hex::encode(k256_sig.to_bytes())
    );
}

fn trim_bcs_len_prefix(bytes: &[u8]) -> &[u8] {
    if bytes.first().copied() == Some(33) && bytes.len() == 34 {
        &bytes[1..]
    } else if bytes.first().copied() == Some(65) && bytes.len() == 66 {
        &bytes[1..]
    } else {
        bytes
    }
}
