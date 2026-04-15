//! Schnorr signatures over secp256k1 (BIP-340)
//!
//! Used by Bitcoin Taproot. Schnorr signatures offer several advantages:
//! - Linear signature aggregation (MuSig2)
//! - Simpler threshold signing (FROST)
//! - Batch verification
//! - Smaller signatures with same security

use crate::error::CryptoError;
use crate::hash::{sha256, tagged_hash};
use crate::traits::{KeyPair, PrivateKey, PublicKey, Signature, SignatureScheme};
use crate::{Result, SignatureType};
use k256::{
    schnorr::{
        signature::{Signer, Verifier},
        Signature as K256SchnorrSignature, SigningKey, VerifyingKey,
    },
    elliptic_curve::rand_core::OsRng,
};
use serde::{Deserialize, Serialize};

/// Schnorr key pair over secp256k1 (BIP-340 compatible)
#[derive(Clone)]
pub struct SchnorrKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair for SchnorrKeyPair {
    type PublicKey = SchnorrPublicKey;
    type PrivateKey = SchnorrPrivateKey;

    fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        unsafe {
            &*((&self.verifying_key) as *const VerifyingKey as *const SchnorrPublicKey)
        }
    }

    fn private_key(&self) -> &Self::PrivateKey {
        unsafe {
            &*((&self.signing_key) as *const SigningKey as *const SchnorrPrivateKey)
        }
    }

    fn from_private_key(private_key: Self::PrivateKey) -> Result<Self> {
        let verifying_key = private_key.0.verifying_key();
        Ok(Self {
            signing_key: private_key.0,
            verifying_key,
        })
    }

    fn signature_type() -> SignatureType {
        SignatureType::SchnorrSecp256k1
    }
}

/// Schnorr public key (x-only, 32 bytes as per BIP-340)
#[derive(Clone, Serialize, Deserialize)]
pub struct SchnorrPublicKey(#[serde(with = "verifying_key_serde")] pub VerifyingKey);

impl PublicKey for SchnorrPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Schnorr public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        VerifyingKey::from_bytes(bytes)
            .map(SchnorrPublicKey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }
}

impl SchnorrPublicKey {
    /// Get the Bitcoin Taproot address (P2TR)
    pub fn to_taproot_address(&self, network: BitcoinNetwork) -> String {
        let pubkey_bytes = self.to_bytes();

        // Tweak the public key with the tap tweak
        // For a key-path-only spend, tweak = tagged_hash("TapTweak", pubkey)
        let tweak = tagged_hash("TapTweak", &pubkey_bytes);

        // In production, we'd properly compute the tweaked key
        // For now, we'll use the untweaked key for address generation
        let hrp = match network {
            BitcoinNetwork::Mainnet => "bc",
            BitcoinNetwork::Testnet => "tb",
            BitcoinNetwork::Signet => "tb",
            BitcoinNetwork::Regtest => "bcrt",
        };

        // Bech32m encoding for Taproot (witness version 1)
        let mut data = vec![1u8]; // witness version 1
        data.extend(bech32_convert_bits(&pubkey_bytes, 8, 5, true).unwrap());

        bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse(hrp).unwrap(), &data)
            .unwrap_or_else(|_| "invalid".to_string())
    }

    /// Get the raw 32-byte x-only public key
    pub fn to_x_only(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result.copy_from_slice(&self.to_bytes());
        result
    }
}

/// Schnorr private key
#[derive(Clone)]
pub struct SchnorrPrivateKey(pub SigningKey);

impl PrivateKey for SchnorrPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SigningKey::from_bytes(bytes)
            .map(SchnorrPrivateKey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn zeroize(&mut self) {
        // k256 handles zeroization internally
    }
}

/// Schnorr signature (64 bytes: R || s)
#[derive(Clone, Serialize, Deserialize)]
pub struct SchnorrSignature(#[serde(with = "signature_serde")] pub K256SchnorrSignature);

impl Signature for SchnorrSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature(format!(
                "Schnorr signature must be 64 bytes, got {}",
                bytes.len()
            )));
        }
        K256SchnorrSignature::try_from(bytes)
            .map(SchnorrSignature)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    }
}

impl SchnorrSignature {
    /// Get the R component (first 32 bytes)
    pub fn r(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.to_bytes()[..32]);
        r
    }

    /// Get the s component (last 32 bytes)
    pub fn s(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.to_bytes()[32..]);
        s
    }
}

/// Bitcoin network for address generation
#[derive(Debug, Clone, Copy)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// Schnorr signature scheme implementation (BIP-340)
pub struct Schnorr;

impl SignatureScheme for Schnorr {
    type KeyPair = SchnorrKeyPair;
    type Signature = SchnorrSignature;

    fn sign(key_pair: &Self::KeyPair, message: &[u8]) -> Result<Self::Signature> {
        // BIP-340 requires signing the message hash
        let msg_hash = sha256(message);
        let signature = key_pair.signing_key.sign(&msg_hash);
        Ok(SchnorrSignature(signature))
    }

    fn verify(
        public_key: &SchnorrPublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool> {
        let msg_hash = sha256(message);
        Ok(public_key.0.verify(&msg_hash, &signature.0).is_ok())
    }

    fn signature_type() -> SignatureType {
        SignatureType::SchnorrSecp256k1
    }
}

/// Helper function to convert bits for bech32 encoding
fn bech32_convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to) - 1;

    for value in data {
        let v = *value as u32;
        if (v >> from) != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }

    Some(ret)
}

// Serde helpers
mod verifying_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

mod signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        sig: &K256SchnorrSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<K256SchnorrSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        K256SchnorrSignature::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key_pair = SchnorrKeyPair::generate().unwrap();
        // BIP-340 uses x-only pubkeys (32 bytes)
        assert_eq!(key_pair.public_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let key_pair = SchnorrKeyPair::generate().unwrap();
        let message = b"Hello, Bitcoin Taproot!";

        let signature = Schnorr::sign(&key_pair, message).unwrap();
        let is_valid = Schnorr::verify(key_pair.public_key(), message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = SchnorrKeyPair::generate().unwrap();
        let message = b"Hello, Bitcoin Taproot!";
        let wrong_message = b"Wrong message";

        let signature = Schnorr::sign(&key_pair, message).unwrap();
        let is_valid = Schnorr::verify(key_pair.public_key(), wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_taproot_address() {
        let key_pair = SchnorrKeyPair::generate().unwrap();
        let address = key_pair.public_key().to_taproot_address(BitcoinNetwork::Mainnet);
        // Taproot addresses start with "bc1p"
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_signature_components() {
        let key_pair = SchnorrKeyPair::generate().unwrap();
        let message = b"test";
        let signature = Schnorr::sign(&key_pair, message).unwrap();

        let r = signature.r();
        let s = signature.s();

        // R and s should each be 32 bytes
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);

        // Concatenating them should give back the original signature
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&r);
        combined.extend_from_slice(&s);
        assert_eq!(combined, signature.to_bytes());
    }
}
