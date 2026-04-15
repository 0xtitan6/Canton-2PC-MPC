//! Bitcoin address generation and validation

use crate::{BitcoinError, BitcoinSignatureType, Network, Result};
use crypto_core::hash::{hash256, sha256};

/// A Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The address string
    pub address: String,
    /// The network
    pub network: Network,
    /// The address type
    pub address_type: AddressType,
    /// The underlying script pubkey
    pub script_pubkey: Vec<u8>,
}

/// Types of Bitcoin addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay to Public Key Hash (legacy)
    P2PKH,
    /// Pay to Script Hash
    P2SH,
    /// Pay to Witness Public Key Hash (SegWit v0)
    P2WPKH,
    /// Pay to Witness Script Hash (SegWit v0)
    P2WSH,
    /// Pay to Taproot (SegWit v1)
    P2TR,
}

impl AddressType {
    /// Get the signature type needed for this address type
    pub fn signature_type(&self) -> BitcoinSignatureType {
        match self {
            AddressType::P2TR => BitcoinSignatureType::Schnorr,
            _ => BitcoinSignatureType::Ecdsa,
        }
    }
}

impl Address {
    /// Create a P2PKH address from a public key
    pub fn p2pkh(public_key: &[u8], network: Network) -> Result<Self> {
        if public_key.len() != 33 && public_key.len() != 65 {
            return Err(BitcoinError::InvalidAddress(
                "Invalid public key length".into(),
            ));
        }

        // HASH160 = RIPEMD160(SHA256(pubkey))
        let sha = sha256(public_key);
        let hash160 = ripemd160(&sha);

        // Base58Check encoding
        let mut payload = vec![network.p2pkh_prefix()];
        payload.extend_from_slice(&hash160);

        let checksum = &hash256(&payload)[..4];
        payload.extend_from_slice(checksum);

        let address = bs58::encode(&payload).into_string();

        // Script: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
        let mut script_pubkey = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
        script_pubkey.extend_from_slice(&hash160);
        script_pubkey.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

        Ok(Address {
            address,
            network,
            address_type: AddressType::P2PKH,
            script_pubkey,
        })
    }

    /// Create a P2WPKH (native SegWit) address from a public key
    pub fn p2wpkh(public_key: &[u8], network: Network) -> Result<Self> {
        if public_key.len() != 33 {
            return Err(BitcoinError::InvalidAddress(
                "P2WPKH requires compressed public key (33 bytes)".into(),
            ));
        }

        let sha = sha256(public_key);
        let hash160 = ripemd160(&sha);

        // Bech32 encoding with witness version 0
        let hrp = bech32::Hrp::parse(network.bech32_hrp())
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        let mut data = vec![0u8]; // witness version 0
        data.extend(convert_bits(&hash160, 8, 5, true)?);

        let address = bech32::encode::<bech32::Bech32>(hrp, &data)
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        // Script: OP_0 <hash160>
        let mut script_pubkey = vec![0x00, 0x14]; // OP_0 PUSH20
        script_pubkey.extend_from_slice(&hash160);

        Ok(Address {
            address,
            network,
            address_type: AddressType::P2WPKH,
            script_pubkey,
        })
    }

    /// Create a P2TR (Taproot) address from an x-only public key
    pub fn p2tr(x_only_pubkey: &[u8], network: Network) -> Result<Self> {
        if x_only_pubkey.len() != 32 {
            return Err(BitcoinError::InvalidAddress(
                "P2TR requires x-only public key (32 bytes)".into(),
            ));
        }

        // Bech32m encoding with witness version 1
        let hrp = bech32::Hrp::parse(network.bech32_hrp())
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        let mut data = vec![1u8]; // witness version 1
        data.extend(convert_bits(x_only_pubkey, 8, 5, true)?);

        let address = bech32::encode::<bech32::Bech32m>(hrp, &data)
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        // Script: OP_1 <x-only-pubkey>
        let mut script_pubkey = vec![0x51, 0x20]; // OP_1 PUSH32
        script_pubkey.extend_from_slice(x_only_pubkey);

        Ok(Address {
            address,
            network,
            address_type: AddressType::P2TR,
            script_pubkey,
        })
    }

    /// Parse an address string
    pub fn from_string(address: &str, network: Network) -> Result<Self> {
        // Try bech32/bech32m first
        if address.starts_with(network.bech32_hrp()) {
            return Self::parse_bech32(address, network);
        }

        // Try base58
        Self::parse_base58(address, network)
    }

    fn parse_bech32(address: &str, network: Network) -> Result<Self> {
        // Try bech32m (Taproot)
        if let Ok((hrp, data)) = bech32::decode(address) {
            if hrp.as_str() != network.bech32_hrp() {
                return Err(BitcoinError::InvalidAddress("Wrong network".into()));
            }

            if data.is_empty() {
                return Err(BitcoinError::InvalidAddress("Empty witness program".into()));
            }

            let witness_version = data[0];
            let program = convert_bits(&data[1..], 5, 8, false)?;

            match witness_version {
                0 if program.len() == 20 => {
                    // P2WPKH
                    let mut script_pubkey = vec![0x00, 0x14];
                    script_pubkey.extend_from_slice(&program);
                    Ok(Address {
                        address: address.to_string(),
                        network,
                        address_type: AddressType::P2WPKH,
                        script_pubkey,
                    })
                }
                0 if program.len() == 32 => {
                    // P2WSH
                    let mut script_pubkey = vec![0x00, 0x20];
                    script_pubkey.extend_from_slice(&program);
                    Ok(Address {
                        address: address.to_string(),
                        network,
                        address_type: AddressType::P2WSH,
                        script_pubkey,
                    })
                }
                1 if program.len() == 32 => {
                    // P2TR
                    let mut script_pubkey = vec![0x51, 0x20];
                    script_pubkey.extend_from_slice(&program);
                    Ok(Address {
                        address: address.to_string(),
                        network,
                        address_type: AddressType::P2TR,
                        script_pubkey,
                    })
                }
                _ => Err(BitcoinError::InvalidAddress("Unknown witness program".into())),
            }
        } else {
            Err(BitcoinError::InvalidAddress("Invalid bech32 encoding".into()))
        }
    }

    fn parse_base58(address: &str, network: Network) -> Result<Self> {
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        if decoded.len() != 25 {
            return Err(BitcoinError::InvalidAddress("Invalid address length".into()));
        }

        // Verify checksum
        let checksum = &hash256(&decoded[..21])[..4];
        if checksum != &decoded[21..] {
            return Err(BitcoinError::InvalidAddress("Invalid checksum".into()));
        }

        let version = decoded[0];
        let hash = &decoded[1..21];

        if version == network.p2pkh_prefix() {
            let mut script_pubkey = vec![0x76, 0xa9, 0x14];
            script_pubkey.extend_from_slice(hash);
            script_pubkey.extend_from_slice(&[0x88, 0xac]);
            Ok(Address {
                address: address.to_string(),
                network,
                address_type: AddressType::P2PKH,
                script_pubkey,
            })
        } else if version == network.p2sh_prefix() {
            let mut script_pubkey = vec![0xa9, 0x14];
            script_pubkey.extend_from_slice(hash);
            script_pubkey.push(0x87);
            Ok(Address {
                address: address.to_string(),
                network,
                address_type: AddressType::P2SH,
                script_pubkey,
            })
        } else {
            Err(BitcoinError::InvalidAddress("Unknown address version".into()))
        }
    }
}

/// Simple RIPEMD160 implementation (placeholder - use proper impl in production)
fn ripemd160(data: &[u8]) -> [u8; 20] {
    // This is a placeholder - in production use the ripemd crate
    let hash = sha256(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[..20]);
    result
}

/// Convert bits for bech32 encoding
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to) - 1;

    for value in data {
        let v = *value as u32;
        if (v >> from) != 0 {
            return Err(BitcoinError::InvalidAddress("Invalid bit conversion".into()));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(BitcoinError::InvalidAddress("Invalid padding".into()));
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_address() {
        // Test with a known public key
        let pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();

        let address = Address::p2pkh(&pubkey, Network::Mainnet).unwrap();
        assert!(address.address.starts_with('1'));
        assert_eq!(address.address_type, AddressType::P2PKH);
    }

    #[test]
    fn test_p2wpkh_address() {
        let pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();

        let address = Address::p2wpkh(&pubkey, Network::Mainnet).unwrap();
        assert!(address.address.starts_with("bc1q"));
        assert_eq!(address.address_type, AddressType::P2WPKH);
    }

    #[test]
    fn test_p2tr_address() {
        // X-only public key (32 bytes)
        let x_only = hex::decode(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();

        let address = Address::p2tr(&x_only, Network::Mainnet).unwrap();
        assert!(address.address.starts_with("bc1p"));
        assert_eq!(address.address_type, AddressType::P2TR);
    }
}
