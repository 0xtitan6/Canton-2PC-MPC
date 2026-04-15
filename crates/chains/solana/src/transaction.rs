//! Solana transaction building and serialization

use crate::address::Pubkey;
use crate::{Lamports, SolanaError, Result};
use serde::{Deserialize, Serialize};

/// A Solana transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Signatures (one per signer)
    pub signatures: Vec<[u8; 64]>,
    /// The message containing instructions
    pub message: Message,
}

/// Transaction message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message header
    pub header: MessageHeader,
    /// Account keys used in the transaction
    pub account_keys: Vec<Pubkey>,
    /// Recent blockhash
    pub recent_blockhash: [u8; 32],
    /// Instructions
    pub instructions: Vec<CompiledInstruction>,
}

/// Message header
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Number of required signatures
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts
    pub num_readonly_signed_accounts: u8,
    /// Number of read-only unsigned accounts
    pub num_readonly_unsigned_accounts: u8,
}

/// A compiled instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledInstruction {
    /// Index into account_keys for the program
    pub program_id_index: u8,
    /// Indices into account_keys for accounts
    pub accounts: Vec<u8>,
    /// Instruction data
    pub data: Vec<u8>,
}

/// Instruction builder
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Program ID
    pub program_id: Pubkey,
    /// Accounts
    pub accounts: Vec<AccountMeta>,
    /// Data
    pub data: Vec<u8>,
}

/// Account metadata for an instruction
#[derive(Debug, Clone, Copy)]
pub struct AccountMeta {
    /// Account pubkey
    pub pubkey: Pubkey,
    /// Is signer
    pub is_signer: bool,
    /// Is writable
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    pub fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        instructions: &[Instruction],
        payer: &Pubkey,
        recent_blockhash: [u8; 32],
    ) -> Self {
        let message = Message::new(instructions, payer, recent_blockhash);
        let num_signers = message.header.num_required_signatures as usize;

        Self {
            signatures: vec![[0u8; 64]; num_signers],
            message,
        }
    }

    /// Get the message to sign
    pub fn message_data(&self) -> Vec<u8> {
        self.message.serialize()
    }

    /// Apply a signature
    pub fn apply_signature(&mut self, signer_index: usize, signature: [u8; 64]) {
        if signer_index < self.signatures.len() {
            self.signatures[signer_index] = signature;
        }
    }

    /// Serialize the transaction
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Signatures
        data.push(self.signatures.len() as u8);
        for sig in &self.signatures {
            data.extend_from_slice(sig);
        }

        // Message
        data.extend(self.message.serialize());

        data
    }

    /// Check if all signatures are present
    pub fn is_signed(&self) -> bool {
        self.signatures.iter().all(|s| s != &[0u8; 64])
    }
}

impl Message {
    /// Create a new message
    pub fn new(
        instructions: &[Instruction],
        payer: &Pubkey,
        recent_blockhash: [u8; 32],
    ) -> Self {
        // Collect all unique accounts
        let mut accounts: Vec<(Pubkey, bool, bool)> = Vec::new(); // (pubkey, is_signer, is_writable)

        // Payer is always first, always signer and writable
        accounts.push((*payer, true, true));

        // Collect accounts from instructions
        for ix in instructions {
            for meta in &ix.accounts {
                if let Some(existing) = accounts.iter_mut().find(|(p, _, _)| p == &meta.pubkey) {
                    existing.1 |= meta.is_signer;
                    existing.2 |= meta.is_writable;
                } else {
                    accounts.push((meta.pubkey, meta.is_signer, meta.is_writable));
                }
            }
            // Add program ID as read-only
            if !accounts.iter().any(|(p, _, _)| p == &ix.program_id) {
                accounts.push((ix.program_id, false, false));
            }
        }

        // Sort accounts: signers first, then writable, then read-only
        let mut signers_writable: Vec<Pubkey> = accounts.iter()
            .filter(|(_, is_signer, is_writable)| *is_signer && *is_writable)
            .map(|(p, _, _)| *p)
            .collect();

        let mut signers_readonly: Vec<Pubkey> = accounts.iter()
            .filter(|(_, is_signer, is_writable)| *is_signer && !*is_writable)
            .map(|(p, _, _)| *p)
            .collect();

        let mut non_signers_writable: Vec<Pubkey> = accounts.iter()
            .filter(|(_, is_signer, is_writable)| !*is_signer && *is_writable)
            .map(|(p, _, _)| *p)
            .collect();

        let mut non_signers_readonly: Vec<Pubkey> = accounts.iter()
            .filter(|(_, is_signer, is_writable)| !*is_signer && !*is_writable)
            .map(|(p, _, _)| *p)
            .collect();

        let mut account_keys = Vec::new();
        account_keys.append(&mut signers_writable);
        account_keys.append(&mut signers_readonly);
        account_keys.append(&mut non_signers_writable);
        account_keys.append(&mut non_signers_readonly);

        let num_required_signatures = accounts.iter().filter(|(_, is_signer, _)| *is_signer).count() as u8;
        let num_readonly_signed = signers_readonly.len() as u8;
        let num_readonly_unsigned = non_signers_readonly.len() as u8;

        // Compile instructions
        let compiled_instructions: Vec<CompiledInstruction> = instructions.iter().map(|ix| {
            let program_id_index = account_keys.iter()
                .position(|p| p == &ix.program_id)
                .unwrap() as u8;

            let account_indices: Vec<u8> = ix.accounts.iter()
                .map(|meta| account_keys.iter().position(|p| p == &meta.pubkey).unwrap() as u8)
                .collect();

            CompiledInstruction {
                program_id_index,
                accounts: account_indices,
                data: ix.data.clone(),
            }
        }).collect();

        Self {
            header: MessageHeader {
                num_required_signatures,
                num_readonly_signed_accounts: num_readonly_signed,
                num_readonly_unsigned_accounts: num_readonly_unsigned,
            },
            account_keys,
            recent_blockhash,
            instructions: compiled_instructions,
        }
    }

    /// Serialize the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.push(self.header.num_required_signatures);
        data.push(self.header.num_readonly_signed_accounts);
        data.push(self.header.num_readonly_unsigned_accounts);

        // Account keys
        data.push(self.account_keys.len() as u8);
        for key in &self.account_keys {
            data.extend_from_slice(key.as_bytes());
        }

        // Recent blockhash
        data.extend_from_slice(&self.recent_blockhash);

        // Instructions
        data.push(self.instructions.len() as u8);
        for ix in &self.instructions {
            data.push(ix.program_id_index);
            data.push(ix.accounts.len() as u8);
            data.extend_from_slice(&ix.accounts);
            encode_compact_u16(&mut data, ix.data.len() as u16);
            data.extend_from_slice(&ix.data);
        }

        data
    }
}

/// System program instructions
pub mod system_instruction {
    use super::*;

    /// Create a transfer instruction
    pub fn transfer(from: &Pubkey, to: &Pubkey, lamports: Lamports) -> Instruction {
        let mut data = vec![2, 0, 0, 0]; // Transfer instruction discriminator
        data.extend_from_slice(&lamports.as_lamports().to_le_bytes());

        Instruction {
            program_id: Pubkey::SYSTEM_PROGRAM,
            accounts: vec![
                AccountMeta::new(*from, true),
                AccountMeta::new(*to, false),
            ],
            data,
        }
    }

    /// Create an account creation instruction
    pub fn create_account(
        from: &Pubkey,
        to: &Pubkey,
        lamports: Lamports,
        space: u64,
        owner: &Pubkey,
    ) -> Instruction {
        let mut data = vec![0, 0, 0, 0]; // CreateAccount instruction discriminator
        data.extend_from_slice(&lamports.as_lamports().to_le_bytes());
        data.extend_from_slice(&space.to_le_bytes());
        data.extend_from_slice(owner.as_bytes());

        Instruction {
            program_id: Pubkey::SYSTEM_PROGRAM,
            accounts: vec![
                AccountMeta::new(*from, true),
                AccountMeta::new(*to, true),
            ],
            data,
        }
    }
}

/// Encode a compact u16 (used in Solana serialization)
fn encode_compact_u16(buf: &mut Vec<u8>, value: u16) {
    if value < 0x80 {
        buf.push(value as u8);
    } else if value < 0x4000 {
        buf.push(((value & 0x7f) | 0x80) as u8);
        buf.push((value >> 7) as u8);
    } else {
        buf.push(((value & 0x7f) | 0x80) as u8);
        buf.push((((value >> 7) & 0x7f) | 0x80) as u8);
        buf.push((value >> 14) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_instruction() {
        let from = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let to = Pubkey::from_bytes(&[2u8; 32]).unwrap();

        let ix = system_instruction::transfer(&from, &to, Lamports::from_sol(1.0));

        assert_eq!(ix.accounts.len(), 2);
        assert!(ix.accounts[0].is_signer);
        assert!(!ix.accounts[1].is_signer);
    }

    #[test]
    fn test_transaction_creation() {
        let payer = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let to = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let blockhash = [0u8; 32];

        let ix = system_instruction::transfer(&payer, &to, Lamports::from_sol(1.0));
        let tx = Transaction::new(&[ix], &payer, blockhash);

        assert_eq!(tx.signatures.len(), 1);
        assert!(!tx.is_signed());
    }

    #[test]
    fn test_transaction_serialization() {
        let payer = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let to = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let blockhash = [0u8; 32];

        let ix = system_instruction::transfer(&payer, &to, Lamports::from_sol(1.0));
        let tx = Transaction::new(&[ix], &payer, blockhash);

        let serialized = tx.serialize();
        assert!(!serialized.is_empty());
    }
}
