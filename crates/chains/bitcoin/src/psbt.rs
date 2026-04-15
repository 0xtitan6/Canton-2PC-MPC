//! Partially Signed Bitcoin Transactions (PSBT) - BIP-174
//!
//! PSBTs are essential for MPC signing as they allow multiple parties
//! to contribute signatures without sharing private keys.

use crate::transaction::{Transaction, TxOutput, Utxo};
use crate::{BitcoinError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Partially Signed Bitcoin Transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Psbt {
    /// The unsigned transaction
    pub unsigned_tx: Transaction,
    /// Per-input data
    pub inputs: Vec<PsbtInput>,
    /// Per-output data
    pub outputs: Vec<PsbtOutput>,
    /// Global xpubs (optional)
    pub xpubs: HashMap<Vec<u8>, Vec<u8>>,
    /// Version
    pub version: u32,
}

/// Per-input PSBT data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsbtInput {
    /// Non-witness UTXO (full transaction)
    pub non_witness_utxo: Option<Transaction>,
    /// Witness UTXO (just the output being spent)
    pub witness_utxo: Option<TxOutput>,
    /// Partial signatures (pubkey -> signature)
    pub partial_sigs: HashMap<Vec<u8>, Vec<u8>>,
    /// Sighash type to use
    pub sighash_type: Option<u32>,
    /// Redeem script (for P2SH)
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script (for P2WSH)
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 derivation paths (pubkey -> (fingerprint, path))
    pub bip32_derivation: HashMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    /// Final script sig
    pub final_script_sig: Option<Vec<u8>>,
    /// Final witness
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// Taproot key spend signature
    pub tap_key_sig: Option<Vec<u8>>,
    /// Taproot script spend signatures
    pub tap_script_sigs: HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
    /// Taproot internal key
    pub tap_internal_key: Option<Vec<u8>>,
    /// Taproot merkle root
    pub tap_merkle_root: Option<Vec<u8>>,
}

/// Per-output PSBT data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsbtOutput {
    /// Redeem script
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 derivation paths
    pub bip32_derivation: HashMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    /// Taproot internal key
    pub tap_internal_key: Option<Vec<u8>>,
}

impl Psbt {
    /// Create a new PSBT from an unsigned transaction
    pub fn from_unsigned_tx(tx: Transaction) -> Self {
        let input_count = tx.inputs.len();
        let output_count = tx.outputs.len();

        Self {
            unsigned_tx: tx,
            inputs: vec![PsbtInput::default(); input_count],
            outputs: vec![PsbtOutput::default(); output_count],
            xpubs: HashMap::new(),
            version: 0,
        }
    }

    /// Add witness UTXO information for an input
    pub fn add_witness_utxo(&mut self, input_index: usize, utxo: TxOutput) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }
        self.inputs[input_index].witness_utxo = Some(utxo);
        Ok(())
    }

    /// Add a partial signature for an input
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }
        self.inputs[input_index].partial_sigs.insert(public_key, signature);
        Ok(())
    }

    /// Add a Taproot key-path signature
    pub fn add_taproot_key_sig(&mut self, input_index: usize, signature: Vec<u8>) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }
        self.inputs[input_index].tap_key_sig = Some(signature);
        Ok(())
    }

    /// Set the sighash type for an input
    pub fn set_sighash_type(&mut self, input_index: usize, sighash_type: u32) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }
        self.inputs[input_index].sighash_type = Some(sighash_type);
        Ok(())
    }

    /// Check if the PSBT has all required signatures for an input
    pub fn input_is_fully_signed(&self, input_index: usize) -> bool {
        if input_index >= self.inputs.len() {
            return false;
        }

        let input = &self.inputs[input_index];

        // Check for finalized input
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            return true;
        }

        // Check for Taproot key-path signature
        if input.tap_key_sig.is_some() {
            return true;
        }

        // Check for at least one partial signature
        !input.partial_sigs.is_empty()
    }

    /// Check if all inputs are fully signed
    pub fn is_fully_signed(&self) -> bool {
        (0..self.inputs.len()).all(|i| self.input_is_fully_signed(i))
    }

    /// Finalize an input (prepare for broadcast)
    pub fn finalize_input(&mut self, input_index: usize) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(BitcoinError::InvalidTransaction("Invalid input index".into()));
        }

        let input = &mut self.inputs[input_index];

        // Handle Taproot key-path spend
        if let Some(sig) = &input.tap_key_sig {
            input.final_script_witness = Some(vec![sig.clone()]);
            return Ok(());
        }

        // Handle regular signatures
        if !input.partial_sigs.is_empty() {
            // For P2WPKH, witness is [signature, pubkey]
            if let Some((pubkey, sig)) = input.partial_sigs.iter().next() {
                input.final_script_witness = Some(vec![sig.clone(), pubkey.clone()]);
            }
        }

        Ok(())
    }

    /// Finalize all inputs
    pub fn finalize(&mut self) -> Result<()> {
        for i in 0..self.inputs.len() {
            self.finalize_input(i)?;
        }
        Ok(())
    }

    /// Extract the final signed transaction
    pub fn extract_tx(&self) -> Result<Transaction> {
        let mut tx = self.unsigned_tx.clone();

        for (i, psbt_input) in self.inputs.iter().enumerate() {
            if let Some(final_sig) = &psbt_input.final_script_sig {
                tx.inputs[i].script_sig = final_sig.clone();
            }

            if let Some(final_witness) = &psbt_input.final_script_witness {
                tx.inputs[i].witness = final_witness.clone();
            }
        }

        Ok(tx)
    }

    /// Serialize the PSBT to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Magic bytes: "psbt" + 0xff
        data.extend_from_slice(b"psbt\xff");

        // Global section
        // Unsigned transaction
        let tx_bytes = self.unsigned_tx.serialize();
        data.push(0x00); // key type: unsigned tx
        self.write_compact_size(&mut data, tx_bytes.len());
        data.extend_from_slice(&tx_bytes);

        // Version
        data.push(0xfb); // key type: version
        data.push(0x04); // value length
        data.extend_from_slice(&self.version.to_le_bytes());

        // Separator
        data.push(0x00);

        // Per-input data
        for input in &self.inputs {
            self.serialize_input(&mut data, input);
            data.push(0x00); // separator
        }

        // Per-output data
        for output in &self.outputs {
            self.serialize_output(&mut data, output);
            data.push(0x00); // separator
        }

        data
    }

    fn serialize_input(&self, data: &mut Vec<u8>, input: &PsbtInput) {
        // Witness UTXO
        if let Some(utxo) = &input.witness_utxo {
            data.push(0x01); // key type
            let mut utxo_data = Vec::new();
            utxo_data.extend_from_slice(&utxo.value.to_le_bytes());
            utxo_data.push(utxo.script_pubkey.len() as u8);
            utxo_data.extend_from_slice(&utxo.script_pubkey);
            self.write_compact_size(data, utxo_data.len());
            data.extend_from_slice(&utxo_data);
        }

        // Partial signatures
        for (pubkey, sig) in &input.partial_sigs {
            data.push(0x02); // key type
            data.extend_from_slice(pubkey);
            self.write_compact_size(data, sig.len());
            data.extend_from_slice(sig);
        }

        // Sighash type
        if let Some(sighash) = input.sighash_type {
            data.push(0x03); // key type
            data.push(0x04); // value length
            data.extend_from_slice(&sighash.to_le_bytes());
        }

        // Taproot key signature
        if let Some(sig) = &input.tap_key_sig {
            data.push(0x13); // key type
            self.write_compact_size(data, sig.len());
            data.extend_from_slice(sig);
        }
    }

    fn serialize_output(&self, data: &mut Vec<u8>, output: &PsbtOutput) {
        // Redeem script
        if let Some(script) = &output.redeem_script {
            data.push(0x00); // key type
            self.write_compact_size(data, script.len());
            data.extend_from_slice(script);
        }

        // Taproot internal key
        if let Some(key) = &output.tap_internal_key {
            data.push(0x05); // key type
            self.write_compact_size(data, key.len());
            data.extend_from_slice(key);
        }
    }

    fn write_compact_size(&self, data: &mut Vec<u8>, size: usize) {
        if size < 0xfd {
            data.push(size as u8);
        } else if size <= 0xffff {
            data.push(0xfd);
            data.extend_from_slice(&(size as u16).to_le_bytes());
        } else if size <= 0xffffffff {
            data.push(0xfe);
            data.extend_from_slice(&(size as u32).to_le_bytes());
        } else {
            data.push(0xff);
            data.extend_from_slice(&(size as u64).to_le_bytes());
        }
    }

    /// Deserialize a PSBT from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        // Check magic bytes
        if data.len() < 5 || &data[..5] != b"psbt\xff" {
            return Err(BitcoinError::InvalidTransaction("Invalid PSBT magic".into()));
        }

        // Simplified deserialization - production code would fully parse
        Err(BitcoinError::InvalidTransaction("PSBT deserialization not fully implemented".into()))
    }
}

/// PSBT role for MPC signing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtRole {
    /// Creator - creates the unsigned transaction
    Creator,
    /// Updater - adds UTXO information and derivation paths
    Updater,
    /// Signer - adds partial signatures
    Signer,
    /// Combiner - merges multiple PSBTs
    Combiner,
    /// Finalizer - creates final scriptSig/witness
    Finalizer,
    /// Extractor - extracts final transaction
    Extractor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_creation() {
        let tx = Transaction::new();
        let psbt = Psbt::from_unsigned_tx(tx);
        assert_eq!(psbt.version, 0);
        assert!(psbt.inputs.is_empty());
    }

    #[test]
    fn test_psbt_serialization() {
        let tx = Transaction::new();
        let psbt = Psbt::from_unsigned_tx(tx);
        let serialized = psbt.serialize();

        // Should start with PSBT magic
        assert_eq!(&serialized[..5], b"psbt\xff");
    }

    #[test]
    fn test_add_partial_sig() {
        let mut tx = Transaction::new();
        tx.inputs.push(crate::transaction::TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        });

        let mut psbt = Psbt::from_unsigned_tx(tx);

        let pubkey = vec![0x02; 33];
        let signature = vec![0x30; 72];

        psbt.add_partial_sig(0, pubkey.clone(), signature.clone()).unwrap();

        assert!(psbt.inputs[0].partial_sigs.contains_key(&pubkey));
    }
}
