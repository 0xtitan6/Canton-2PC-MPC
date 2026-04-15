//! Ethereum transaction and message signing

use crate::address::Address;
use crate::transaction::Transaction;
use crate::{EthereumError, Result};
use crypto_core::hash::keccak256;

/// Ethereum message signing utilities
pub struct EthereumSigner;

impl EthereumSigner {
    /// Compute the hash to sign for a transaction
    pub fn transaction_hash(tx: &Transaction) -> [u8; 32] {
        tx.signing_hash()
    }

    /// Hash a message with the Ethereum signed message prefix (EIP-191)
    pub fn personal_sign_hash(message: &[u8]) -> [u8; 32] {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        keccak256(&data)
    }

    /// Hash typed structured data (EIP-712)
    pub fn typed_data_hash(
        domain_separator: &[u8; 32],
        struct_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut data = Vec::with_capacity(66);
        data.extend_from_slice(b"\x19\x01");
        data.extend_from_slice(domain_separator);
        data.extend_from_slice(struct_hash);
        keccak256(&data)
    }

    /// Compute the EIP-712 domain separator
    pub fn domain_separator(
        name: &str,
        version: &str,
        chain_id: u64,
        verifying_contract: &Address,
    ) -> [u8; 32] {
        // EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

        let name_hash = keccak256(name.as_bytes());
        let version_hash = keccak256(version.as_bytes());

        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&type_hash);
        data.extend_from_slice(&name_hash);
        data.extend_from_slice(&version_hash);

        // uint256 chainId (32 bytes, big-endian)
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
        data.extend_from_slice(&chain_id_bytes);

        // address (32 bytes, left-padded)
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..].copy_from_slice(verifying_contract.as_bytes());
        data.extend_from_slice(&addr_bytes);

        keccak256(&data)
    }

    /// Recover the signer address from a signature
    pub fn recover_signer(
        message_hash: &[u8; 32],
        signature: &[u8],
        recovery_id: u8,
    ) -> Result<Address> {
        if signature.len() != 64 {
            return Err(EthereumError::SigningError(
                "Signature must be 64 bytes".into()
            ));
        }

        // In production, use k256's recovery functionality
        // This is a placeholder that returns zero address
        // let verifying_key = k256::ecdsa::VerifyingKey::recover_from_prehash(...)

        Ok(Address::ZERO)
    }

    /// Encode a signature in the format expected by Ethereum (r || s || v)
    pub fn encode_signature(signature: &[u8], recovery_id: u8, chain_id: Option<u64>) -> Vec<u8> {
        if signature.len() != 64 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(65);
        result.extend_from_slice(signature);

        // Calculate v
        let v = match chain_id {
            Some(chain_id) => {
                // EIP-155: v = chainId * 2 + 35 + recovery_id
                (chain_id * 2 + 35 + recovery_id as u64) as u8
            }
            None => {
                // Pre-EIP-155: v = 27 + recovery_id
                27 + recovery_id
            }
        };
        result.push(v);

        result
    }

    /// Parse a signature from the Ethereum format
    pub fn parse_signature(sig: &[u8]) -> Result<([u8; 32], [u8; 32], u8)> {
        if sig.len() != 65 {
            return Err(EthereumError::SigningError(
                "Signature must be 65 bytes".into()
            ));
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..64]);

        // Extract recovery id from v
        let v = sig[64];
        let recovery_id = if v >= 35 {
            // EIP-155
            ((v - 35) % 2) as u8
        } else {
            // Pre-EIP-155
            (v - 27) as u8
        };

        Ok((r, s, recovery_id))
    }
}

/// MPC signing interface for Ethereum
pub trait MpcEthereumSigner {
    /// Sign a message hash using the 2PC-MPC protocol
    fn mpc_sign(&self, message_hash: &[u8; 32]) -> Result<(Vec<u8>, u8)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_personal_sign_hash() {
        let message = b"Hello, Ethereum!";
        let hash = EthereumSigner::personal_sign_hash(message);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_domain_separator() {
        let contract = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let separator = EthereumSigner::domain_separator(
            "Test App",
            "1",
            1,
            &contract,
        );
        assert_eq!(separator.len(), 32);
    }

    #[test]
    fn test_signature_encoding() {
        let signature = [0u8; 64];

        // Without chain ID (pre-EIP-155)
        let encoded = EthereumSigner::encode_signature(&signature, 0, None);
        assert_eq!(encoded.len(), 65);
        assert_eq!(encoded[64], 27); // v = 27 + 0

        // With chain ID (EIP-155)
        let encoded = EthereumSigner::encode_signature(&signature, 1, Some(1));
        assert_eq!(encoded.len(), 65);
        assert_eq!(encoded[64] as u64, 1 * 2 + 35 + 1); // v = chainId * 2 + 35 + recovery_id
    }

    #[test]
    fn test_signature_parsing() {
        let mut sig = vec![0u8; 65];
        sig[64] = 28; // v = 28 (pre-EIP-155, recovery_id = 1)

        let (r, s, recovery_id) = EthereumSigner::parse_signature(&sig).unwrap();
        assert_eq!(r, [0u8; 32]);
        assert_eq!(s, [0u8; 32]);
        assert_eq!(recovery_id, 1);
    }
}
