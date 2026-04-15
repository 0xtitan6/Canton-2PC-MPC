//! Solana transaction signing with MPC support

use crate::address::Pubkey;
use crate::transaction::Transaction;
use crate::{SolanaError, Result};

/// Solana transaction signing utilities
pub struct SolanaSigner;

impl SolanaSigner {
    /// Get the message to sign from a transaction
    pub fn get_message_to_sign(tx: &Transaction) -> Vec<u8> {
        tx.message_data()
    }

    /// Apply a signature to a transaction
    pub fn apply_signature(
        tx: &mut Transaction,
        pubkey: &Pubkey,
        signature: &[u8],
    ) -> Result<()> {
        if signature.len() != 64 {
            return Err(SolanaError::SigningError(
                "Signature must be 64 bytes".into()
            ));
        }

        // Find the signer index
        let signer_index = tx.message.account_keys
            .iter()
            .take(tx.message.header.num_required_signatures as usize)
            .position(|k| k == pubkey)
            .ok_or_else(|| SolanaError::SigningError(
                "Pubkey is not a signer".into()
            ))?;

        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);
        tx.apply_signature(signer_index, sig);

        Ok(())
    }

    /// Verify a signature
    pub fn verify_signature(
        message: &[u8],
        signature: &[u8],
        pubkey: &Pubkey,
    ) -> Result<bool> {
        if signature.len() != 64 {
            return Err(SolanaError::SigningError(
                "Signature must be 64 bytes".into()
            ));
        }

        // Use ed25519-dalek for verification
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(pubkey.as_bytes())
            .map_err(|e| SolanaError::SigningError(e.to_string()))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}

/// MPC signing interface for Solana
pub trait MpcSolanaSigner {
    /// Sign a message using the 2PC-MPC protocol
    fn mpc_sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// Compute the hash for signing (Solana doesn't hash the message before signing)
pub fn compute_signing_data(tx: &Transaction) -> Vec<u8> {
    tx.message_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::system_instruction;
    use crate::Lamports;

    #[test]
    fn test_get_message_to_sign() {
        let payer = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let to = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let blockhash = [0u8; 32];

        let ix = system_instruction::transfer(&payer, &to, Lamports::from_sol(1.0));
        let tx = Transaction::new(&[ix], &payer, blockhash);

        let message = SolanaSigner::get_message_to_sign(&tx);
        assert!(!message.is_empty());
    }

    #[test]
    fn test_apply_signature() {
        let payer = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let to = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let blockhash = [0u8; 32];

        let ix = system_instruction::transfer(&payer, &to, Lamports::from_sol(1.0));
        let mut tx = Transaction::new(&[ix], &payer, blockhash);

        let signature = [42u8; 64];
        SolanaSigner::apply_signature(&mut tx, &payer, &signature).unwrap();

        assert!(tx.is_signed());
    }
}
