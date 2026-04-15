//! Ethereum address handling

use crate::{EthereumError, Result};
use crypto_core::hash::keccak256;
use serde::{Deserialize, Serialize};

/// An Ethereum address (20 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Create an address from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 20 {
            return Err(EthereumError::InvalidAddress(
                format!("Address must be 20 bytes, got {}", bytes.len())
            ));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }

    /// Create an address from a hex string (with or without 0x prefix)
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| EthereumError::InvalidAddress(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Derive an address from a public key
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        // Public key should be 65 bytes (uncompressed) or 33 bytes (compressed)
        let uncompressed = if public_key.len() == 65 {
            // Skip the 0x04 prefix
            &public_key[1..]
        } else if public_key.len() == 64 {
            // Already without prefix
            public_key
        } else if public_key.len() == 33 {
            // Compressed - need to decompress
            // For now, return error - production code would decompress
            return Err(EthereumError::InvalidAddress(
                "Compressed public keys not yet supported".into()
            ));
        } else {
            return Err(EthereumError::InvalidAddress(
                format!("Invalid public key length: {}", public_key.len())
            ));
        };

        // Keccak256 hash of the public key
        let hash = keccak256(uncompressed);

        // Take the last 20 bytes
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);

        Ok(Self(addr))
    }

    /// Get the address as bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get the checksummed hex representation (EIP-55)
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = hex::encode(self.0);
        let hash = keccak256(hex_addr.as_bytes());

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                // Check the corresponding nibble in the hash
                let hash_byte = hash[i / 2];
                let hash_nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0f
                };

                if hash_nibble >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Get the lowercase hex representation
    pub fn to_hex_string(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Check if the address is the zero address
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// The zero address
    pub const ZERO: Self = Self([0u8; 20]);
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

impl std::str::FromStr for Address {
    type Err = EthereumError;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

/// Verify an EIP-55 checksum address
pub fn verify_checksum(address: &str) -> bool {
    let address = address.strip_prefix("0x").unwrap_or(address);
    if address.len() != 40 {
        return false;
    }

    let lower = address.to_lowercase();
    let hash = keccak256(lower.as_bytes());

    for (i, c) in address.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            let should_be_upper = hash_nibble >= 8;
            let is_upper = c.is_ascii_uppercase();

            if should_be_upper != is_upper {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_hex() {
        let addr = Address::from_hex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        assert!(!addr.is_zero());
    }

    #[test]
    fn test_address_checksum() {
        let addr = Address::from_hex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        let checksummed = addr.to_checksum_string();
        // Vitalik's address
        assert_eq!(checksummed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    }

    #[test]
    fn test_address_from_public_key() {
        // Known test vector
        let pubkey = hex::decode(
            "04\
             50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
             2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
        ).unwrap();

        let addr = Address::from_public_key(&pubkey).unwrap();
        assert_eq!(
            addr.to_hex_string().to_lowercase(),
            "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
        );
    }

    #[test]
    fn test_zero_address() {
        assert!(Address::ZERO.is_zero());
        assert_eq!(
            Address::ZERO.to_hex_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }
}
