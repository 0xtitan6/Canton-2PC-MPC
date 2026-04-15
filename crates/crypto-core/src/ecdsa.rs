//! ECDSA over secp256k1 implementation
//!
//! Used by Bitcoin, Ethereum, and most EVM-compatible chains.
//! This module provides both standard signing and the foundation for
//! threshold ECDSA (used in 2PC-MPC).

use crate::error::CryptoError;
use crate::traits::{KeyPair, PrivateKey, PublicKey, Signature, SignatureScheme};
use crate::{Result, SignatureType};
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as K256Signature, SigningKey, VerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// ECDSA key pair over secp256k1
#[derive(Clone)]
pub struct EcdsaKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = EcdsaPublicKey;
    type PrivateKey = EcdsaPrivateKey;

    fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        // This is a bit of a hack - we create a wrapper on the fly
        // In production, we'd store this properly
        unsafe {
            &*((&self.verifying_key) as *const VerifyingKey as *const EcdsaPublicKey)
        }
    }

    fn private_key(&self) -> &Self::PrivateKey {
        unsafe {
            &*((&self.signing_key) as *const SigningKey as *const EcdsaPrivateKey)
        }
    }

    fn from_private_key(private_key: Self::PrivateKey) -> Result<Self> {
        let verifying_key = *private_key.0.verifying_key();
        Ok(Self {
            signing_key: private_key.0,
            verifying_key,
        })
    }

    fn signature_type() -> SignatureType {
        SignatureType::EcdsaSecp256k1
    }
}

/// ECDSA public key (secp256k1)
#[derive(Clone, Serialize, Deserialize)]
pub struct EcdsaPublicKey(#[serde(with = "verifying_key_serde")] pub VerifyingKey);

impl PublicKey for EcdsaPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(EcdsaPublicKey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn to_compressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    fn to_uncompressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
}

impl EcdsaPublicKey {
    /// Get the Ethereum address derived from this public key
    pub fn to_eth_address(&self) -> [u8; 20] {
        let uncompressed = self.to_uncompressed();
        // Skip the 0x04 prefix for uncompressed points
        let hash = crate::hash::keccak256(&uncompressed[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Get the Bitcoin P2PKH address (mainnet)
    pub fn to_btc_p2pkh_address(&self) -> String {
        use crate::hash::sha256;

        let compressed = self.to_compressed();
        let sha = sha256(&compressed);

        // RIPEMD160 - simplified for now, use proper impl in production
        // For now, just return a placeholder
        let hash160 = &sha[..20]; // Simplified - should be RIPEMD160(SHA256(pubkey))

        let mut payload = vec![0x00]; // mainnet prefix
        payload.extend_from_slice(hash160);

        // Add checksum
        let checksum = &crate::hash::hash256(&payload)[..4];
        payload.extend_from_slice(checksum);

        bs58::encode(payload).into_string()
    }
}

/// ECDSA private key (secp256k1)
#[derive(Clone)]
pub struct EcdsaPrivateKey(pub SigningKey);

impl PrivateKey for EcdsaPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SigningKey::from_bytes(bytes.into())
            .map(EcdsaPrivateKey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn zeroize(&mut self) {
        // k256 handles zeroization internally
    }
}

/// ECDSA signature
#[derive(Clone, Serialize, Deserialize)]
pub struct EcdsaSignature(#[serde(with = "signature_serde")] pub K256Signature);

impl Signature for EcdsaSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        K256Signature::from_slice(bytes)
            .map(EcdsaSignature)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    }

    fn to_der(&self) -> Option<Vec<u8>> {
        Some(self.0.to_der().as_bytes().to_vec())
    }
}

impl EcdsaSignature {
    /// Get the r component
    pub fn r(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        r
    }

    /// Get the s component
    pub fn s(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        s
    }

    /// Normalize the signature to low-S form (required by Bitcoin/Ethereum)
    pub fn normalize(&self) -> Self {
        EcdsaSignature(self.0.normalize_s().unwrap_or(self.0))
    }
}

/// ECDSA signature scheme implementation
pub struct Ecdsa;

impl SignatureScheme for Ecdsa {
    type KeyPair = EcdsaKeyPair;
    type Signature = EcdsaSignature;

    fn sign(key_pair: &Self::KeyPair, message: &[u8]) -> Result<Self::Signature> {
        let signature: K256Signature = key_pair.signing_key.sign(message);
        Ok(EcdsaSignature(signature.normalize_s().unwrap_or(signature)))
    }

    fn verify(
        public_key: &EcdsaPublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool> {
        Ok(public_key.0.verify(message, &signature.0).is_ok())
    }

    fn signature_type() -> SignatureType {
        SignatureType::EcdsaSecp256k1
    }
}

// Serde helpers for k256 types
mod verifying_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_encoded_point(true);
        serializer.serialize_bytes(bytes.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        VerifyingKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

mod signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &K256Signature, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<K256Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        K256Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key_pair = EcdsaKeyPair::generate().unwrap();
        assert_eq!(key_pair.public_key().to_compressed().len(), 33);
    }

    #[test]
    fn test_sign_verify() {
        let key_pair = EcdsaKeyPair::generate().unwrap();
        let message = b"Hello, Canton Network!";

        let signature = Ecdsa::sign(&key_pair, message).unwrap();
        let is_valid = Ecdsa::verify(key_pair.public_key(), message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = EcdsaKeyPair::generate().unwrap();
        let message = b"Hello, Canton Network!";
        let wrong_message = b"Wrong message";

        let signature = Ecdsa::sign(&key_pair, message).unwrap();
        let is_valid = Ecdsa::verify(key_pair.public_key(), wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_eth_address() {
        let key_pair = EcdsaKeyPair::generate().unwrap();
        let address = key_pair.public_key().to_eth_address();
        assert_eq!(address.len(), 20);
    }
}
