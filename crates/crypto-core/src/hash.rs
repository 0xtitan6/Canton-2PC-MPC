//! Hash functions used across different blockchain networks
//!
//! Different chains use different hash functions:
//! - Bitcoin: SHA256, HASH256 (double SHA256), HASH160 (SHA256 + RIPEMD160)
//! - Ethereum: Keccak256
//! - Solana: SHA256

use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Keccak256;

/// SHA256 hash (used by Bitcoin, Solana)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA256 (HASH256) - used by Bitcoin for transaction hashing
pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Keccak256 hash - used by Ethereum
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Tagged hash as per BIP-340 (Schnorr/Taproot)
/// hash = SHA256(SHA256(tag) || SHA256(tag) || data)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// BIP-340 challenge hash for Schnorr signatures
pub fn schnorr_challenge(r: &[u8; 32], p: &[u8; 32], m: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64 + m.len());
    data.extend_from_slice(r);
    data.extend_from_slice(p);
    data.extend_from_slice(m);
    tagged_hash("BIP0340/challenge", &data)
}

/// Ethereum message hash with prefix
pub fn eth_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = Vec::with_capacity(prefix.len() + message.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(message);
    keccak256(&data)
}

/// Bitcoin message hash with prefix
pub fn btc_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let msg_len = message.len() as u8;
    let mut data = Vec::with_capacity(prefix.len() + 1 + message.len());
    data.extend_from_slice(prefix);
    data.push(msg_len);
    data.extend_from_slice(message);
    hash256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = sha256(b"hello");
        let expected = hex::decode(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ).unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_keccak256() {
        let result = keccak256(b"hello");
        let expected = hex::decode(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        ).unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hash256() {
        let result = hash256(b"hello");
        // Double SHA256
        let single = sha256(b"hello");
        let expected = sha256(&single);
        assert_eq!(result, expected);
    }
}
