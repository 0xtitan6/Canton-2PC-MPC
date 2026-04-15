//! Ethereum transaction types and RLP encoding

use crate::address::Address;
use crate::{EthereumError, Network, Result, Wei};
use serde::{Deserialize, Serialize};

/// Transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    /// Legacy transaction (pre-EIP-2718)
    Legacy = 0,
    /// EIP-2930 access list transaction
    AccessList = 1,
    /// EIP-1559 dynamic fee transaction
    DynamicFee = 2,
}

/// An Ethereum transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    pub tx_type: u8,
    /// Chain ID
    pub chain_id: u64,
    /// Nonce
    pub nonce: u64,
    /// Gas price (for legacy tx) or max priority fee (for EIP-1559)
    pub gas_price: Wei,
    /// Max fee per gas (EIP-1559 only)
    pub max_fee_per_gas: Option<Wei>,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value in wei
    pub value: Wei,
    /// Input data
    pub data: Vec<u8>,
    /// Access list (EIP-2930+)
    pub access_list: Vec<AccessListItem>,
    /// Signature v value
    pub v: u64,
    /// Signature r value
    pub r: [u8; 32],
    /// Signature s value
    pub s: [u8; 32],
}

/// Access list item for EIP-2930
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

impl Transaction {
    /// Create a new legacy transaction
    pub fn legacy(
        chain_id: u64,
        nonce: u64,
        gas_price: Wei,
        gas_limit: u64,
        to: Option<Address>,
        value: Wei,
        data: Vec<u8>,
    ) -> Self {
        Self {
            tx_type: TxType::Legacy as u8,
            chain_id,
            nonce,
            gas_price,
            max_fee_per_gas: None,
            gas_limit,
            to,
            value,
            data,
            access_list: Vec::new(),
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }

    /// Create a new EIP-1559 transaction
    pub fn eip1559(
        chain_id: u64,
        nonce: u64,
        max_priority_fee: Wei,
        max_fee_per_gas: Wei,
        gas_limit: u64,
        to: Option<Address>,
        value: Wei,
        data: Vec<u8>,
    ) -> Self {
        Self {
            tx_type: TxType::DynamicFee as u8,
            chain_id,
            nonce,
            gas_price: max_priority_fee,
            max_fee_per_gas: Some(max_fee_per_gas),
            gas_limit,
            to,
            value,
            data,
            access_list: Vec::new(),
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }

    /// Serialize for signing (unsigned transaction hash)
    pub fn signing_hash(&self) -> [u8; 32] {
        let encoded = self.encode_for_signing();
        crypto_core::hash::keccak256(&encoded)
    }

    /// RLP encode for signing
    fn encode_for_signing(&self) -> Vec<u8> {
        match self.tx_type {
            0 => self.encode_legacy_for_signing(),
            2 => self.encode_eip1559_for_signing(),
            _ => self.encode_legacy_for_signing(),
        }
    }

    fn encode_legacy_for_signing(&self) -> Vec<u8> {
        // Legacy transaction: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
        let mut items = Vec::new();

        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.gas_price.as_wei()));
        items.push(rlp_encode_u64(self.gas_limit));
        items.push(self.to.map_or(vec![0x80], |a| rlp_encode_bytes(a.as_bytes())));
        items.push(rlp_encode_u128(self.value.as_wei()));
        items.push(rlp_encode_bytes(&self.data));
        items.push(rlp_encode_u64(self.chain_id));
        items.push(vec![0x80]); // 0
        items.push(vec![0x80]); // 0

        rlp_encode_list(&items)
    }

    fn encode_eip1559_for_signing(&self) -> Vec<u8> {
        // EIP-1559: 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
        let mut items = Vec::new();

        items.push(rlp_encode_u64(self.chain_id));
        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.gas_price.as_wei())); // maxPriorityFeePerGas
        items.push(rlp_encode_u128(self.max_fee_per_gas.unwrap_or(self.gas_price).as_wei()));
        items.push(rlp_encode_u64(self.gas_limit));
        items.push(self.to.map_or(vec![0x80], |a| rlp_encode_bytes(a.as_bytes())));
        items.push(rlp_encode_u128(self.value.as_wei()));
        items.push(rlp_encode_bytes(&self.data));
        items.push(self.encode_access_list());

        let mut result = vec![0x02]; // EIP-1559 type prefix
        result.extend(rlp_encode_list(&items));
        result
    }

    fn encode_access_list(&self) -> Vec<u8> {
        if self.access_list.is_empty() {
            return vec![0xc0]; // Empty list
        }

        let items: Vec<Vec<u8>> = self.access_list.iter().map(|item| {
            let addr = rlp_encode_bytes(item.address.as_bytes());
            let keys: Vec<Vec<u8>> = item.storage_keys.iter()
                .map(|k| rlp_encode_bytes(k))
                .collect();
            let keys_list = rlp_encode_list(&keys);
            rlp_encode_list(&[addr, keys_list])
        }).collect();

        rlp_encode_list(&items)
    }

    /// Serialize the signed transaction
    pub fn encode_signed(&self) -> Vec<u8> {
        match self.tx_type {
            0 => self.encode_legacy_signed(),
            2 => self.encode_eip1559_signed(),
            _ => self.encode_legacy_signed(),
        }
    }

    fn encode_legacy_signed(&self) -> Vec<u8> {
        let mut items = Vec::new();

        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.gas_price.as_wei()));
        items.push(rlp_encode_u64(self.gas_limit));
        items.push(self.to.map_or(vec![0x80], |a| rlp_encode_bytes(a.as_bytes())));
        items.push(rlp_encode_u128(self.value.as_wei()));
        items.push(rlp_encode_bytes(&self.data));
        items.push(rlp_encode_u64(self.v));
        items.push(rlp_encode_bytes(&self.r));
        items.push(rlp_encode_bytes(&self.s));

        rlp_encode_list(&items)
    }

    fn encode_eip1559_signed(&self) -> Vec<u8> {
        let mut items = Vec::new();

        items.push(rlp_encode_u64(self.chain_id));
        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.gas_price.as_wei()));
        items.push(rlp_encode_u128(self.max_fee_per_gas.unwrap_or(self.gas_price).as_wei()));
        items.push(rlp_encode_u64(self.gas_limit));
        items.push(self.to.map_or(vec![0x80], |a| rlp_encode_bytes(a.as_bytes())));
        items.push(rlp_encode_u128(self.value.as_wei()));
        items.push(rlp_encode_bytes(&self.data));
        items.push(self.encode_access_list());
        items.push(rlp_encode_u64(self.v));
        items.push(rlp_encode_bytes(&self.r));
        items.push(rlp_encode_bytes(&self.s));

        let mut result = vec![0x02];
        result.extend(rlp_encode_list(&items));
        result
    }

    /// Apply signature to transaction
    pub fn apply_signature(&mut self, signature: &[u8], recovery_id: u8) {
        if signature.len() != 64 {
            return;
        }

        self.r.copy_from_slice(&signature[..32]);
        self.s.copy_from_slice(&signature[32..]);

        // Calculate v based on transaction type
        self.v = match self.tx_type {
            0 => {
                // Legacy: v = chainId * 2 + 35 + recovery_id
                self.chain_id * 2 + 35 + recovery_id as u64
            }
            _ => {
                // EIP-1559 and later: v is just the recovery id (0 or 1)
                recovery_id as u64
            }
        };
    }

    /// Compute the transaction hash
    pub fn hash(&self) -> [u8; 32] {
        crypto_core::hash::keccak256(&self.encode_signed())
    }
}

// RLP encoding helpers

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    // Remove leading zeros for numbers
    let data = if !data.is_empty() && data[0] == 0 {
        let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
        &data[start..]
    } else {
        data
    };

    if data.is_empty() {
        vec![0x80]
    } else if data.len() == 1 && data[0] < 0x80 {
        data.to_vec()
    } else if data.len() <= 55 {
        let mut result = vec![0x80 + data.len() as u8];
        result.extend_from_slice(data);
        result
    } else {
        let len_bytes = encode_length(data.len());
        let mut result = vec![0xb7 + len_bytes.len() as u8];
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(data);
        result
    }
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|i| i.len()).sum();

    let mut result = if total_len <= 55 {
        vec![0xc0 + total_len as u8]
    } else {
        let len_bytes = encode_length(total_len);
        let mut r = vec![0xf7 + len_bytes.len() as u8];
        r.extend_from_slice(&len_bytes);
        r
    };

    for item in items {
        result.extend_from_slice(item);
    }

    result
}

fn encode_length(len: usize) -> Vec<u8> {
    let bytes = len.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_transaction() {
        let to = Address::from_hex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        let tx = Transaction::legacy(
            1, // mainnet
            0, // nonce
            Wei::from_gwei(20),
            21000,
            Some(to),
            Wei::from_eth(1.0),
            Vec::new(),
        );

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_eip1559_transaction() {
        let to = Address::from_hex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        let tx = Transaction::eip1559(
            1, // mainnet
            0, // nonce
            Wei::from_gwei(2), // priority fee
            Wei::from_gwei(100), // max fee
            21000,
            Some(to),
            Wei::from_eth(1.0),
            Vec::new(),
        );

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_rlp_encoding() {
        // Empty string
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);

        // Single byte < 0x80
        assert_eq!(rlp_encode_bytes(&[0x00]), vec![0x80]); // 0 encodes as empty
        assert_eq!(rlp_encode_bytes(&[0x7f]), vec![0x7f]);

        // Short string
        assert_eq!(rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);

        // Longer string
        let long = vec![0x00; 60];
        let encoded = rlp_encode_bytes(&long);
        assert!(encoded.len() > 60);
    }
}
