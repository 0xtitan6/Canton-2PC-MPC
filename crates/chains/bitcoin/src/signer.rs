//! Bitcoin transaction signing with MPC support

use crate::address::AddressType;
use crate::psbt::{Psbt, PsbtInput};
use crate::transaction::{Transaction, TxOutput};
use crate::{BitcoinError, BitcoinSignatureType, Result};
use crypto_core::hash::{hash256, sha256, tagged_hash};

/// Sighash types for Bitcoin transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashType {
    /// Sign all inputs and outputs
    All = 0x01,
    /// Sign all inputs, no outputs
    None = 0x02,
    /// Sign all inputs, only the output at the same index
    Single = 0x03,
    /// Anyone can add inputs (combined with above)
    AnyoneCanPay = 0x80,
}

impl SighashType {
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Bitcoin transaction signer for MPC
pub struct BitcoinSigner;

impl BitcoinSigner {
    /// Compute the sighash for a legacy (non-SegWit) input
    pub fn legacy_sighash(
        tx: &Transaction,
        input_index: usize,
        script_pubkey: &[u8],
        sighash_type: SighashType,
    ) -> Result<[u8; 32]> {
        let preimage = tx.serialize_for_signing(input_index, script_pubkey, sighash_type.to_u32());
        Ok(hash256(&preimage))
    }

    /// Compute the sighash for a SegWit v0 (P2WPKH/P2WSH) input
    pub fn segwit_v0_sighash(
        tx: &Transaction,
        input_index: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: SighashType,
    ) -> Result<[u8; 32]> {
        let preimage = tx.serialize_for_segwit_signing(
            input_index,
            script_code,
            value,
            sighash_type.to_u32(),
        );
        Ok(hash256(&preimage))
    }

    /// Compute the sighash for a Taproot key-path spend
    pub fn taproot_key_sighash(
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOutput],
        sighash_type: SighashType,
    ) -> Result<[u8; 32]> {
        let preimage = tx.serialize_for_taproot_signing(
            input_index,
            prevouts,
            sighash_type.to_u8(),
        );

        // BIP-341: tagged hash with "TapSighash"
        Ok(tagged_hash("TapSighash", &preimage))
    }

    /// Create the script code for P2WPKH signing
    pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        // OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(pubkey_hash);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    /// Encode a DER signature with sighash type
    pub fn encode_signature(signature: &[u8], sighash_type: SighashType) -> Vec<u8> {
        // Input: 64-byte raw signature (r || s)
        // Output: DER-encoded signature + sighash byte

        if signature.len() != 64 {
            return Vec::new();
        }

        let r = &signature[..32];
        let s = &signature[32..];

        let mut der = Vec::new();

        // Sequence tag
        der.push(0x30);

        // Build r and s components
        let r_der = Self::encode_der_integer(r);
        let s_der = Self::encode_der_integer(s);

        // Total length
        der.push((r_der.len() + s_der.len()) as u8);

        // Add components
        der.extend_from_slice(&r_der);
        der.extend_from_slice(&s_der);

        // Add sighash type
        der.push(sighash_type.to_u8());

        der
    }

    fn encode_der_integer(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02]; // Integer tag

        // Remove leading zeros but keep one if needed for positive sign
        let mut start = 0;
        while start < value.len() - 1 && value[start] == 0 {
            start += 1;
        }

        // Add leading zero if high bit is set (to keep positive)
        let needs_padding = value[start] & 0x80 != 0;
        let len = value.len() - start + if needs_padding { 1 } else { 0 };

        result.push(len as u8);
        if needs_padding {
            result.push(0x00);
        }
        result.extend_from_slice(&value[start..]);

        result
    }

    /// Encode a Schnorr signature for Taproot
    pub fn encode_schnorr_signature(signature: &[u8], sighash_type: SighashType) -> Vec<u8> {
        if signature.len() != 64 {
            return Vec::new();
        }

        let mut result = signature.to_vec();

        // Only append sighash byte if not SIGHASH_ALL_DEFAULT (0x00)
        if sighash_type != SighashType::All {
            result.push(sighash_type.to_u8());
        }

        result
    }

    /// Compute the message to sign for a PSBT input
    pub fn compute_sighash_for_psbt(
        psbt: &Psbt,
        input_index: usize,
        sighash_type: SighashType,
    ) -> Result<([u8; 32], BitcoinSignatureType)> {
        if input_index >= psbt.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }

        let input = &psbt.inputs[input_index];

        // Determine the signing method based on UTXO type
        if let Some(witness_utxo) = &input.witness_utxo {
            // Check if Taproot
            if witness_utxo.script_pubkey.len() == 34
                && witness_utxo.script_pubkey[0] == 0x51
                && witness_utxo.script_pubkey[1] == 0x20
            {
                // Taproot (P2TR)
                let prevouts: Vec<TxOutput> = psbt
                    .inputs
                    .iter()
                    .filter_map(|i| i.witness_utxo.clone())
                    .collect();

                let sighash = Self::taproot_key_sighash(
                    &psbt.unsigned_tx,
                    input_index,
                    &prevouts,
                    sighash_type,
                )?;

                return Ok((sighash, BitcoinSignatureType::Schnorr));
            }

            // SegWit v0 (P2WPKH)
            if witness_utxo.script_pubkey.len() == 22
                && witness_utxo.script_pubkey[0] == 0x00
                && witness_utxo.script_pubkey[1] == 0x14
            {
                let mut pubkey_hash = [0u8; 20];
                pubkey_hash.copy_from_slice(&witness_utxo.script_pubkey[2..]);

                let script_code = Self::p2wpkh_script_code(&pubkey_hash);
                let sighash = Self::segwit_v0_sighash(
                    &psbt.unsigned_tx,
                    input_index,
                    &script_code,
                    witness_utxo.value,
                    sighash_type,
                )?;

                return Ok((sighash, BitcoinSignatureType::Ecdsa));
            }
        }

        // Legacy signing
        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let prev_vout = psbt.unsigned_tx.inputs[input_index].prev_vout as usize;
            let script_pubkey = &non_witness_utxo.outputs[prev_vout].script_pubkey;

            let sighash = Self::legacy_sighash(
                &psbt.unsigned_tx,
                input_index,
                script_pubkey,
                sighash_type,
            )?;

            return Ok((sighash, BitcoinSignatureType::Ecdsa));
        }

        Err(BitcoinError::InvalidTransaction("Cannot determine signing method".into()))
    }
}

/// MPC signing interface for Bitcoin
pub trait MpcBitcoinSigner {
    /// Sign a message using the 2PC-MPC protocol
    fn mpc_sign(
        &self,
        message: &[u8; 32],
        signature_type: BitcoinSignatureType,
    ) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_encoding() {
        // Test with a simple signature
        let signature = [0u8; 64];
        let der = BitcoinSigner::encode_signature(&signature, SighashType::All);

        // Should start with 0x30 (sequence)
        assert_eq!(der[0], 0x30);
        // Should end with sighash type
        assert_eq!(*der.last().unwrap(), 0x01);
    }

    #[test]
    fn test_p2wpkh_script_code() {
        let pubkey_hash = [0u8; 20];
        let script_code = BitcoinSigner::p2wpkh_script_code(&pubkey_hash);

        // Should be 25 bytes: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(script_code.len(), 25);
        assert_eq!(script_code[0], 0x76); // OP_DUP
        assert_eq!(script_code[1], 0xa9); // OP_HASH160
        assert_eq!(script_code[2], 0x14); // PUSH20
    }

    #[test]
    fn test_schnorr_signature_encoding() {
        let signature = [0u8; 64];

        // SIGHASH_ALL doesn't need suffix
        let encoded = BitcoinSigner::encode_schnorr_signature(&signature, SighashType::All);
        assert_eq!(encoded.len(), 64);

        // Other sighash types need suffix
        let encoded = BitcoinSigner::encode_schnorr_signature(&signature, SighashType::None);
        assert_eq!(encoded.len(), 65);
        assert_eq!(*encoded.last().unwrap(), 0x02);
    }
}
