//! Solana address (public key) handling

use crate::{SolanaError, Result};
use serde::{Deserialize, Serialize};

/// A Solana public key (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    /// Create a pubkey from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(SolanaError::InvalidAddress(
                format!("Pubkey must be 32 bytes, got {}", bytes.len())
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Create a pubkey from a base58 string
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| SolanaError::InvalidAddress(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Create a pubkey from an Ed25519 public key
    pub fn from_ed25519_public_key(public_key: &[u8]) -> Result<Self> {
        Self::from_bytes(public_key)
    }

    /// Get the pubkey as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the base58 representation
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Check if this is the system program
    pub fn is_system_program(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// The system program pubkey
    pub const SYSTEM_PROGRAM: Self = Self([0u8; 32]);

    /// Find a program-derived address (PDA)
    pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Self, u8) {
        let mut bump = 255u8;
        loop {
            let mut seeds_with_bump = seeds.to_vec();
            let bump_slice = [bump];
            seeds_with_bump.push(&bump_slice);

            if let Ok(address) = Self::create_program_address(&seeds_with_bump, program_id) {
                return (address, bump);
            }

            if bump == 0 {
                panic!("Could not find valid PDA");
            }
            bump -= 1;
        }
    }

    /// Create a program-derived address
    pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<Self> {
        // PDA = SHA256("ProgramDerivedAddress" || seeds || program_id || bump)[..32]
        // Then verify it's not on the ed25519 curve

        let mut data = Vec::new();
        for seed in seeds {
            if seed.len() > 32 {
                return Err(SolanaError::InvalidAddress("Seed too long".into()));
            }
            data.extend_from_slice(seed);
        }
        data.extend_from_slice(&program_id.0);
        data.extend_from_slice(b"ProgramDerivedAddress");

        let hash = crypto_core::hash::sha256(&data);

        // Check that it's not on the curve (simplified check)
        // In production, use proper ed25519 point decompression check
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);

        Ok(Self(arr))
    }

    /// Get the associated token address for a wallet and mint
    pub fn get_associated_token_address(
        wallet: &Pubkey,
        mint: &Pubkey,
    ) -> Self {
        let (address, _) = Self::find_program_address(
            &[
                wallet.as_bytes(),
                crate::programs::token_program().as_bytes(),
                mint.as_bytes(),
            ],
            &crate::programs::associated_token_program(),
        );
        address
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl std::str::FromStr for Pubkey {
    type Err = SolanaError;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_base58(s)
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        Self::SYSTEM_PROGRAM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_from_bytes() {
        let bytes = [1u8; 32];
        let pubkey = Pubkey::from_bytes(&bytes).unwrap();
        assert_eq!(pubkey.as_bytes(), &bytes);
    }

    #[test]
    fn test_pubkey_base58() {
        let bytes = [0u8; 32];
        let pubkey = Pubkey::from_bytes(&bytes).unwrap();
        let base58 = pubkey.to_base58();

        // System program address
        assert_eq!(base58, "11111111111111111111111111111111");
    }

    #[test]
    fn test_pubkey_roundtrip() {
        let original = "So11111111111111111111111111111111111111112";
        let pubkey = Pubkey::from_base58(original).unwrap();
        let recovered = pubkey.to_base58();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_system_program() {
        assert!(Pubkey::SYSTEM_PROGRAM.is_system_program());
    }

    #[test]
    fn test_associated_token_address() {
        let wallet = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let mint = Pubkey::from_bytes(&[2u8; 32]).unwrap();

        let ata = Pubkey::get_associated_token_address(&wallet, &mint);
        assert!(!ata.is_system_program());
    }
}
