//! Bitcoin transaction building and serialization

use crate::address::Address;
use crate::{Amount, BitcoinError, Result};
use serde::{Deserialize, Serialize};

/// A Bitcoin transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version
    pub version: i32,
    /// Transaction inputs
    pub inputs: Vec<TxInput>,
    /// Transaction outputs
    pub outputs: Vec<TxOutput>,
    /// Lock time
    pub lock_time: u32,
}

/// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    /// Previous transaction hash
    pub prev_txid: [u8; 32],
    /// Previous output index
    pub prev_vout: u32,
    /// Script signature (for non-witness)
    pub script_sig: Vec<u8>,
    /// Sequence number
    pub sequence: u32,
    /// Witness data (for SegWit)
    pub witness: Vec<Vec<u8>>,
}

/// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    /// Output value in satoshis
    pub value: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
}

/// Unspent transaction output (UTXO)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Output value
    pub value: Amount,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
    /// Address (if known)
    pub address: Option<String>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    /// Add an input from a UTXO
    pub fn add_input(&mut self, utxo: &Utxo) {
        self.inputs.push(TxInput {
            prev_txid: utxo.txid,
            prev_vout: utxo.vout,
            script_sig: Vec::new(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        });
    }

    /// Add an output
    pub fn add_output(&mut self, address: &Address, amount: Amount) {
        self.outputs.push(TxOutput {
            value: amount.as_sat(),
            script_pubkey: address.script_pubkey.clone(),
        });
    }

    /// Add a raw output
    pub fn add_raw_output(&mut self, script_pubkey: Vec<u8>, amount: Amount) {
        self.outputs.push(TxOutput {
            value: amount.as_sat(),
            script_pubkey,
        });
    }

    /// Serialize the transaction for signing (legacy sighash)
    pub fn serialize_for_signing(&self, input_index: usize, script_code: &[u8], sighash_type: u32) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Inputs
        data.push(self.inputs.len() as u8);
        for (i, input) in self.inputs.iter().enumerate() {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());

            if i == input_index {
                // Include the script code for the input being signed
                data.push(script_code.len() as u8);
                data.extend_from_slice(script_code);
            } else {
                data.push(0); // Empty script for other inputs
            }

            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        data.push(self.outputs.len() as u8);
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.push(output.script_pubkey.len() as u8);
            data.extend_from_slice(&output.script_pubkey);
        }

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        // Sighash type
        data.extend_from_slice(&sighash_type.to_le_bytes());

        data
    }

    /// Serialize the transaction for signing (BIP-143 SegWit sighash)
    pub fn serialize_for_segwit_signing(
        &self,
        input_index: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Hash of all input outpoints
        let mut prevouts = Vec::new();
        for input in &self.inputs {
            prevouts.extend_from_slice(&input.prev_txid);
            prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
        }
        data.extend_from_slice(&crypto_core::hash::hash256(&prevouts));

        // Hash of all input sequences
        let mut sequences = Vec::new();
        for input in &self.inputs {
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        data.extend_from_slice(&crypto_core::hash::hash256(&sequences));

        // Outpoint being spent
        let input = &self.inputs[input_index];
        data.extend_from_slice(&input.prev_txid);
        data.extend_from_slice(&input.prev_vout.to_le_bytes());

        // Script code
        data.push(script_code.len() as u8);
        data.extend_from_slice(script_code);

        // Value
        data.extend_from_slice(&value.to_le_bytes());

        // Sequence
        data.extend_from_slice(&input.sequence.to_le_bytes());

        // Hash of all outputs
        let mut outputs = Vec::new();
        for output in &self.outputs {
            outputs.extend_from_slice(&output.value.to_le_bytes());
            outputs.push(output.script_pubkey.len() as u8);
            outputs.extend_from_slice(&output.script_pubkey);
        }
        data.extend_from_slice(&crypto_core::hash::hash256(&outputs));

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        // Sighash type
        data.extend_from_slice(&sighash_type.to_le_bytes());

        data
    }

    /// Serialize the transaction for signing (BIP-341 Taproot sighash)
    pub fn serialize_for_taproot_signing(
        &self,
        input_index: usize,
        prevouts: &[TxOutput],
        sighash_type: u8,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Epoch (0x00 for taproot)
        data.push(0x00);

        // Sighash type
        data.push(sighash_type);

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        // SHA256 of all prevouts
        let mut prevout_data = Vec::new();
        for input in &self.inputs {
            prevout_data.extend_from_slice(&input.prev_txid);
            prevout_data.extend_from_slice(&input.prev_vout.to_le_bytes());
        }
        data.extend_from_slice(&crypto_core::hash::sha256(&prevout_data));

        // SHA256 of all amounts
        let mut amount_data = Vec::new();
        for prevout in prevouts {
            amount_data.extend_from_slice(&prevout.value.to_le_bytes());
        }
        data.extend_from_slice(&crypto_core::hash::sha256(&amount_data));

        // SHA256 of all script pubkeys
        let mut script_data = Vec::new();
        for prevout in prevouts {
            script_data.push(prevout.script_pubkey.len() as u8);
            script_data.extend_from_slice(&prevout.script_pubkey);
        }
        data.extend_from_slice(&crypto_core::hash::sha256(&script_data));

        // SHA256 of all sequences
        let mut seq_data = Vec::new();
        for input in &self.inputs {
            seq_data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        data.extend_from_slice(&crypto_core::hash::sha256(&seq_data));

        // SHA256 of all outputs
        let mut output_data = Vec::new();
        for output in &self.outputs {
            output_data.extend_from_slice(&output.value.to_le_bytes());
            output_data.push(output.script_pubkey.len() as u8);
            output_data.extend_from_slice(&output.script_pubkey);
        }
        data.extend_from_slice(&crypto_core::hash::sha256(&output_data));

        // Spend type (0 for key path)
        data.push(0x00);

        // Input index
        data.extend_from_slice(&(input_index as u32).to_le_bytes());

        data
    }

    /// Serialize the full transaction
    pub fn serialize(&self) -> Vec<u8> {
        let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());

        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // SegWit marker and flag
        if has_witness {
            data.push(0x00); // marker
            data.push(0x01); // flag
        }

        // Inputs
        data.push(self.inputs.len() as u8);
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());
            data.push(input.script_sig.len() as u8);
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        data.push(self.outputs.len() as u8);
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.push(output.script_pubkey.len() as u8);
            data.extend_from_slice(&output.script_pubkey);
        }

        // Witness data
        if has_witness {
            for input in &self.inputs {
                data.push(input.witness.len() as u8);
                for item in &input.witness {
                    data.push(item.len() as u8);
                    data.extend_from_slice(item);
                }
            }
        }

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        data
    }

    /// Compute the transaction ID (hash of non-witness serialization)
    pub fn txid(&self) -> [u8; 32] {
        // Serialize without witness
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_le_bytes());

        data.push(self.inputs.len() as u8);
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());
            data.push(input.script_sig.len() as u8);
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        data.push(self.outputs.len() as u8);
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.push(output.script_pubkey.len() as u8);
            data.extend_from_slice(&output.script_pubkey);
        }

        data.extend_from_slice(&self.lock_time.to_le_bytes());

        let hash = crypto_core::hash::hash256(&data);
        let mut txid = [0u8; 32];
        // Reverse for display (Bitcoin uses little-endian internally)
        for (i, byte) in hash.iter().enumerate() {
            txid[31 - i] = *byte;
        }
        txid
    }

    /// Get the virtual size (vsize) of the transaction
    pub fn vsize(&self) -> usize {
        let base_size = self.serialize().len();
        let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());

        if has_witness {
            // vsize = (weight + 3) / 4
            // weight = base_size * 3 + total_size
            let total_size = self.serialize().len();
            (base_size * 3 + total_size + 3) / 4
        } else {
            base_size
        }
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction builder for easier construction
pub struct TransactionBuilder {
    tx: Transaction,
    utxos: Vec<Utxo>,
    fee_rate: u64, // sat/vbyte
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            tx: Transaction::new(),
            utxos: Vec::new(),
            fee_rate: 1, // 1 sat/vbyte default
        }
    }

    /// Set the fee rate in sat/vbyte
    pub fn fee_rate(mut self, rate: u64) -> Self {
        self.fee_rate = rate;
        self
    }

    /// Add a UTXO as input
    pub fn add_utxo(mut self, utxo: Utxo) -> Self {
        self.utxos.push(utxo);
        self
    }

    /// Add an output
    pub fn add_output(mut self, address: &Address, amount: Amount) -> Self {
        self.tx.add_output(address, amount);
        self
    }

    /// Build the transaction with automatic change calculation
    pub fn build(mut self, change_address: &Address) -> Result<Transaction> {
        // Calculate total input value
        let total_in: u64 = self.utxos.iter().map(|u| u.value.as_sat()).sum();

        // Calculate total output value
        let total_out: u64 = self.tx.outputs.iter().map(|o| o.value).sum();

        // Add all UTXOs as inputs
        for utxo in &self.utxos {
            self.tx.add_input(utxo);
        }

        // Estimate transaction size and fee
        let estimated_vsize = self.tx.vsize() + 34; // +34 for change output
        let fee = estimated_vsize as u64 * self.fee_rate;

        // Check for sufficient funds
        if total_in < total_out + fee {
            return Err(BitcoinError::InsufficientFunds {
                needed: total_out + fee,
                available: total_in,
            });
        }

        // Add change output if there's dust threshold (546 sats for P2PKH)
        let change = total_in - total_out - fee;
        if change > 546 {
            self.tx.add_output(change_address, Amount::from_sat(change));
        }

        Ok(self.tx)
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 2);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn test_transaction_serialization() {
        let mut tx = Transaction::new();

        // Add a dummy input
        tx.inputs.push(TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        });

        // Add a dummy output
        tx.outputs.push(TxOutput {
            value: 50000,
            script_pubkey: vec![0x76, 0xa9, 0x14], // partial P2PKH
        });

        let serialized = tx.serialize();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_txid_computation() {
        let tx = Transaction::new();
        let txid = tx.txid();
        assert_eq!(txid.len(), 32);
    }
}
