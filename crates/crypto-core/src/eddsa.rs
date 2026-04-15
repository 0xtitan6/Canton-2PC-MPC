//! EdDSA over Ed25519 implementation
//!
//! Used by Solana, Cardano, Polkadot, NEAR, Aptos, and other modern chains.
//! Ed25519 offers faster verification and simpler implementation compared to ECDSA.
//! This module provides both standard signing and the foundation for threshold
//! EdDSA using FROST.

use crate::error::CryptoError;
use crate::traits::{KeyPair, PrivateKey, PublicKey, Signature, SignatureScheme};
use crate::{Result, SignatureType};
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// EdDSA key pair over Ed25519
#[derive(Clone)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;

    fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        unsafe {
            &*((&self.verifying_key) as *const VerifyingKey as *const Ed25519PublicKey)
        }
    }

    fn private_key(&self) -> &Self::PrivateKey {
        unsafe {
            &*((&self.signing_key) as *const SigningKey as *const Ed25519PrivateKey)
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
        SignatureType::Ed25519
    }
}

/// Ed25519 public key
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519PublicKey(#[serde(with = "verifying_key_serde")] pub VerifyingKey);

impl PublicKey for Ed25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        VerifyingKey::from_bytes(&arr)
            .map(Ed25519PublicKey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }
}

impl Ed25519PublicKey {
    /// Get the Solana address (base58 encoded public key)
    pub fn to_solana_address(&self) -> String {
        bs58::encode(self.0.to_bytes()).into_string()
    }

    /// Get the raw 32-byte public key
    pub fn to_raw(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Ed25519 private key
#[derive(Clone)]
pub struct Ed25519PrivateKey(pub SigningKey);

impl PrivateKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Ed25519 private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Ed25519PrivateKey(SigningKey::from_bytes(&arr)))
    }

    fn zeroize(&mut self) {
        // ed25519-dalek handles zeroization internally
    }
}

impl Ed25519PrivateKey {
    /// Get the Solana keypair bytes (64 bytes: private key || public key)
    pub fn to_solana_keypair(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.0.to_bytes());
        result[32..].copy_from_slice(&self.0.verifying_key().to_bytes());
        result
    }
}

/// Ed25519 signature
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519Signature(#[serde(with = "signature_serde")] pub DalekSignature);

impl Signature for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Ed25519Signature(DalekSignature::from_bytes(&arr)))
    }
}

impl Ed25519Signature {
    /// Get the R component (first 32 bytes)
    pub fn r(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        r
    }

    /// Get the s component (last 32 bytes)
    pub fn s(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        s
    }
}

/// EdDSA signature scheme implementation (Ed25519)
pub struct EdDsa;

impl SignatureScheme for EdDsa {
    type KeyPair = Ed25519KeyPair;
    type Signature = Ed25519Signature;

    fn sign(key_pair: &Self::KeyPair, message: &[u8]) -> Result<Self::Signature> {
        let signature = key_pair.signing_key.sign(message);
        Ok(Ed25519Signature(signature))
    }

    fn verify(
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool> {
        Ok(public_key.0.verify(message, &signature.0).is_ok())
    }

    fn signature_type() -> SignatureType {
        SignatureType::Ed25519
    }
}

// Serde helpers for ed25519-dalek types
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
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid Ed25519 public key length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

mod signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &DalekSignature, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<DalekSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid Ed25519 signature length"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(DalekSignature::from_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        assert_eq!(key_pair.public_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let message = b"Hello, Solana!";

        let signature = EdDsa::sign(&key_pair, message).unwrap();
        let is_valid = EdDsa::verify(key_pair.public_key(), message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let message = b"Hello, Solana!";
        let wrong_message = b"Wrong message";

        let signature = EdDsa::sign(&key_pair, message).unwrap();
        let is_valid = EdDsa::verify(key_pair.public_key(), wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_solana_address() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let address = key_pair.public_key().to_solana_address();
        // Solana addresses are base58-encoded 32-byte public keys
        // Should be between 32-44 characters
        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_serialization() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Test serialization round-trip
        let bytes = public_key.to_bytes();
        let recovered = Ed25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), recovered.to_bytes());
    }
}
