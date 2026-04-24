//! Phase 0 end-to-end test:
//!   1. Run the full DKG → presign → sign ceremony locally via inkrypto.
//!   2. Verify the resulting signature two ways — once through inkrypto's own
//!      verifier (native 2PC-MPC verification path) and once through stock `k256`
//!      (the verifier every external chain will actually use). Both must agree.

use std::collections::HashMap;

use group::HashScheme;
use mpc_protocol::run_local_ecdsa_ceremony;

#[test]
fn phase0_local_ecdsa_ceremony_produces_valid_signature() {
    // Init a simple tracing subscriber so inkrypto's println! / tracing output
    // is visible when running with `cargo test -- --nocapture`.
    let _ = tracing_subscriber::fmt::try_init();

    // Smallest non-trivial topology: 2-of-2 weighted threshold, unit weights.
    let threshold = 2u16;
    let party_to_weight: HashMap<u16, u16> = HashMap::from([(1, 1), (2, 1)]);
    let message = b"canton 2pc-mpc phase 0 rides again";

    let out = run_local_ecdsa_ceremony(threshold, party_to_weight, message, HashScheme::SHA256)
        .expect("ceremony should succeed");

    // --- native inkrypto verification ---
    // Every `secp256k1::GroupElement` impls `ecdsa::VerifyingKey<SCALAR_LIMBS>`,
    // which is the trait the ceremony outputs against.
    use twopc_mpc::ecdsa::VerifyingKey;
    VerifyingKey::<{ group::secp256k1::SCALAR_LIMBS }>::verify(
        &out.public_key,
        &out.message,
        out.hash_scheme,
        &out.signature,
    )
    .expect("inkrypto's own verifier rejected a signature that inkrypto produced");

    // --- external k256 verification ---
    // Pull the raw signature + recovery id from inkrypto's wrapper, then
    // reconstruct a stock k256::ecdsa::VerifyingKey from the joint public key.
    // If k256 accepts this, any downstream chain that uses standard secp256k1
    // ECDSA (Bitcoin, Ethereum, any EVM) will too.
    let k256_sig = out
        .signature
        .signature()
        .expect("inkrypto signature should round-trip to k256::ecdsa::Signature");

    // inkrypto's secp256k1::GroupElement wraps k256 affine points internally.
    // We go via SEC1-compressed bytes because that's the one encoding both
    // sides publicly agree on.
    let sec1_compressed: Vec<u8> = bcs::to_bytes(&group::GroupElement::value(&out.public_key))
        .expect("group-element value serializes");
    // The bcs encoding of `secp256k1::GroupElement::Value` is the SEC1 affine
    // encoding. k256 accepts it via `VerifyingKey::from_sec1_bytes`.
    let k256_vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(trim_bcs_len_prefix(&sec1_compressed))
        .expect("joint public key should decode as a k256 verifying key");

    // The protocol signs H(message) according to `hash_scheme` — SHA256 here.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(&out.message);
    ecdsa::signature::hazmat::PrehashVerifier::verify_prehash(&k256_vk, &digest, &k256_sig)
        .expect("stock k256 verifier rejected the 2PC-MPC signature");

    println!(
        "Phase 0 ceremony OK: public_key (SEC1) = {}, signature r||s = {}",
        hex::encode(trim_bcs_len_prefix(&sec1_compressed)),
        hex::encode(k256_sig.to_bytes())
    );
}

/// bcs prefixes variable-length byte sequences with a ULEB128 length. For a
/// fixed-size SEC1 compressed point (33 bytes) the prefix is exactly one byte
/// equal to 33 (0x21). Strip it to get the raw SEC1 bytes that k256 expects.
fn trim_bcs_len_prefix(bytes: &[u8]) -> &[u8] {
    if bytes.first().copied() == Some(33) && bytes.len() == 34 {
        &bytes[1..]
    } else if bytes.first().copied() == Some(65) && bytes.len() == 66 {
        &bytes[1..]
    } else {
        bytes
    }
}
