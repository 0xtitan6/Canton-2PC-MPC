//! SPL Token program interactions

use crate::address::Pubkey;
use crate::transaction::{AccountMeta, Instruction};

/// SPL Token instruction discriminators
pub mod instruction_type {
    pub const INITIALIZE_MINT: u8 = 0;
    pub const INITIALIZE_ACCOUNT: u8 = 1;
    pub const INITIALIZE_MULTISIG: u8 = 2;
    pub const TRANSFER: u8 = 3;
    pub const APPROVE: u8 = 4;
    pub const REVOKE: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
    pub const MINT_TO: u8 = 7;
    pub const BURN: u8 = 8;
    pub const CLOSE_ACCOUNT: u8 = 9;
    pub const FREEZE_ACCOUNT: u8 = 10;
    pub const THAW_ACCOUNT: u8 = 11;
    pub const TRANSFER_CHECKED: u8 = 12;
    pub const APPROVE_CHECKED: u8 = 13;
    pub const MINT_TO_CHECKED: u8 = 14;
    pub const BURN_CHECKED: u8 = 15;
    pub const INITIALIZE_ACCOUNT_2: u8 = 16;
    pub const SYNC_NATIVE: u8 = 17;
    pub const INITIALIZE_ACCOUNT_3: u8 = 18;
    pub const INITIALIZE_MINT_2: u8 = 20;
}

/// SPL Token instructions
pub struct SplToken;

impl SplToken {
    /// Create a transfer instruction
    pub fn transfer(
        source: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        amount: u64,
    ) -> Instruction {
        let mut data = vec![instruction_type::TRANSFER];
        data.extend_from_slice(&amount.to_le_bytes());

        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create a transfer_checked instruction (safer)
    pub fn transfer_checked(
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        let mut data = vec![instruction_type::TRANSFER_CHECKED];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);

        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an approve instruction
    pub fn approve(
        source: &Pubkey,
        delegate: &Pubkey,
        owner: &Pubkey,
        amount: u64,
    ) -> Instruction {
        let mut data = vec![instruction_type::APPROVE];
        data.extend_from_slice(&amount.to_le_bytes());

        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*delegate, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    /// Create a revoke instruction
    pub fn revoke(source: &Pubkey, owner: &Pubkey) -> Instruction {
        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data: vec![instruction_type::REVOKE],
        }
    }

    /// Create a close_account instruction
    pub fn close_account(
        account: &Pubkey,
        destination: &Pubkey,
        owner: &Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data: vec![instruction_type::CLOSE_ACCOUNT],
        }
    }

    /// Create a sync_native instruction (for wrapped SOL)
    pub fn sync_native(account: &Pubkey) -> Instruction {
        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![AccountMeta::new(*account, false)],
            data: vec![instruction_type::SYNC_NATIVE],
        }
    }

    /// Create an initialize_account_3 instruction
    pub fn initialize_account_3(
        account: &Pubkey,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Instruction {
        let mut data = vec![instruction_type::INITIALIZE_ACCOUNT_3];
        data.extend_from_slice(owner.as_bytes());

        Instruction {
            program_id: crate::programs::token_program(),
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
            ],
            data,
        }
    }
}

/// Associated Token Account instructions
pub struct AssociatedToken;

impl AssociatedToken {
    /// Create an associated token account
    pub fn create(
        payer: &Pubkey,
        wallet: &Pubkey,
        mint: &Pubkey,
    ) -> Instruction {
        let associated_token_address = Pubkey::get_associated_token_address(wallet, mint);

        Instruction {
            program_id: crate::programs::associated_token_program(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(associated_token_address, false),
                AccountMeta::new_readonly(*wallet, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(Pubkey::SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(crate::programs::token_program(), false),
            ],
            data: vec![],
        }
    }

    /// Create an associated token account idempotently
    pub fn create_idempotent(
        payer: &Pubkey,
        wallet: &Pubkey,
        mint: &Pubkey,
    ) -> Instruction {
        let associated_token_address = Pubkey::get_associated_token_address(wallet, mint);

        Instruction {
            program_id: crate::programs::associated_token_program(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(associated_token_address, false),
                AccountMeta::new_readonly(*wallet, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(Pubkey::SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(crate::programs::token_program(), false),
            ],
            data: vec![1], // CreateIdempotent instruction
        }
    }
}

/// Common SPL tokens on Solana mainnet
pub mod tokens {
    use super::Pubkey;

    /// USDC (Circle)
    pub fn usdc() -> Pubkey {
        Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap()
    }

    /// USDT (Tether)
    pub fn usdt() -> Pubkey {
        Pubkey::from_base58("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB").unwrap()
    }

    /// Wrapped SOL
    pub fn wsol() -> Pubkey {
        Pubkey::from_base58("So11111111111111111111111111111111111111112").unwrap()
    }

    /// BONK
    pub fn bonk() -> Pubkey {
        Pubkey::from_base58("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_instruction() {
        let source = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let dest = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let authority = Pubkey::from_bytes(&[3u8; 32]).unwrap();

        let ix = SplToken::transfer(&source, &dest, &authority, 1_000_000);

        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.data[0], instruction_type::TRANSFER);
    }

    #[test]
    fn test_transfer_checked_instruction() {
        let source = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let mint = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let dest = Pubkey::from_bytes(&[3u8; 32]).unwrap();
        let authority = Pubkey::from_bytes(&[4u8; 32]).unwrap();

        let ix = SplToken::transfer_checked(&source, &mint, &dest, &authority, 1_000_000, 6);

        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.data[0], instruction_type::TRANSFER_CHECKED);
        assert_eq!(ix.data[9], 6); // decimals
    }

    #[test]
    fn test_create_ata() {
        let payer = Pubkey::from_bytes(&[1u8; 32]).unwrap();
        let wallet = Pubkey::from_bytes(&[2u8; 32]).unwrap();
        let mint = tokens::usdc();

        let ix = AssociatedToken::create(&payer, &wallet, &mint);

        assert_eq!(ix.accounts.len(), 6);
    }
}
