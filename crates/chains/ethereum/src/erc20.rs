//! ERC-20 token interaction support

use crate::address::Address;
use crate::{EthereumError, Result, Wei};
use crypto_core::hash::keccak256;

/// ERC-20 function selectors
pub mod selectors {
    /// transfer(address,uint256)
    pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// approve(address,uint256)
    pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
    /// transferFrom(address,address,uint256)
    pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
    /// balanceOf(address)
    pub const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
    /// allowance(address,address)
    pub const ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
    /// totalSupply()
    pub const TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
    /// decimals()
    pub const DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
    /// symbol()
    pub const SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
    /// name()
    pub const NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];
}

/// ABI encoder for ERC-20 calls
pub struct Erc20;

impl Erc20 {
    /// Encode a transfer(address,uint256) call
    pub fn encode_transfer(to: &Address, amount: u128) -> Vec<u8> {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&selectors::TRANSFER);
        data.extend_from_slice(&Self::encode_address(to));
        data.extend_from_slice(&Self::encode_uint256(amount));
        data
    }

    /// Encode an approve(address,uint256) call
    pub fn encode_approve(spender: &Address, amount: u128) -> Vec<u8> {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&selectors::APPROVE);
        data.extend_from_slice(&Self::encode_address(spender));
        data.extend_from_slice(&Self::encode_uint256(amount));
        data
    }

    /// Encode a transferFrom(address,address,uint256) call
    pub fn encode_transfer_from(from: &Address, to: &Address, amount: u128) -> Vec<u8> {
        let mut data = Vec::with_capacity(100);
        data.extend_from_slice(&selectors::TRANSFER_FROM);
        data.extend_from_slice(&Self::encode_address(from));
        data.extend_from_slice(&Self::encode_address(to));
        data.extend_from_slice(&Self::encode_uint256(amount));
        data
    }

    /// Encode a balanceOf(address) call
    pub fn encode_balance_of(account: &Address) -> Vec<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selectors::BALANCE_OF);
        data.extend_from_slice(&Self::encode_address(account));
        data
    }

    /// Encode an allowance(address,address) call
    pub fn encode_allowance(owner: &Address, spender: &Address) -> Vec<u8> {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&selectors::ALLOWANCE);
        data.extend_from_slice(&Self::encode_address(owner));
        data.extend_from_slice(&Self::encode_address(spender));
        data
    }

    /// Encode totalSupply() call
    pub fn encode_total_supply() -> Vec<u8> {
        selectors::TOTAL_SUPPLY.to_vec()
    }

    /// Encode decimals() call
    pub fn encode_decimals() -> Vec<u8> {
        selectors::DECIMALS.to_vec()
    }

    /// Encode symbol() call
    pub fn encode_symbol() -> Vec<u8> {
        selectors::SYMBOL.to_vec()
    }

    /// Encode name() call
    pub fn encode_name() -> Vec<u8> {
        selectors::NAME.to_vec()
    }

    /// Decode a uint256 return value
    pub fn decode_uint256(data: &[u8]) -> Result<u128> {
        if data.len() < 32 {
            return Err(EthereumError::AbiError("Insufficient data".into()));
        }
        // Take the lower 128 bits
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[16..32]);
        Ok(u128::from_be_bytes(bytes))
    }

    /// Decode a string return value
    pub fn decode_string(data: &[u8]) -> Result<String> {
        if data.len() < 64 {
            return Err(EthereumError::AbiError("Insufficient data".into()));
        }

        // First 32 bytes: offset to string data
        // Next 32 bytes: string length
        let length = Self::decode_uint256(&data[32..64])? as usize;

        if data.len() < 64 + length {
            return Err(EthereumError::AbiError("Insufficient string data".into()));
        }

        String::from_utf8(data[64..64 + length].to_vec())
            .map_err(|e| EthereumError::AbiError(e.to_string()))
    }

    // ABI encoding helpers

    fn encode_address(addr: &Address) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[12..].copy_from_slice(addr.as_bytes());
        result
    }

    fn encode_uint256(value: u128) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[16..].copy_from_slice(&value.to_be_bytes());
        result
    }
}

/// Common ERC-20 tokens on Ethereum mainnet
pub mod tokens {
    use super::Address;

    /// USDC (Circle)
    pub fn usdc() -> Address {
        Address::from_hex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()
    }

    /// USDT (Tether)
    pub fn usdt() -> Address {
        Address::from_hex("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap()
    }

    /// WETH (Wrapped Ether)
    pub fn weth() -> Address {
        Address::from_hex("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()
    }

    /// DAI (MakerDAO)
    pub fn dai() -> Address {
        Address::from_hex("0x6B175474E89094C44Da98b954EesEcdB0e3bE93").unwrap()
    }

    /// WBTC (Wrapped Bitcoin)
    pub fn wbtc() -> Address {
        Address::from_hex("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_transfer() {
        let to = Address::from_hex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();
        let amount = 1_000_000u128; // 1 USDC (6 decimals)

        let data = Erc20::encode_transfer(&to, amount);

        // Should be 4 bytes selector + 32 bytes address + 32 bytes amount
        assert_eq!(data.len(), 68);
        assert_eq!(&data[..4], &selectors::TRANSFER);
    }

    #[test]
    fn test_encode_approve() {
        let spender = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let amount = u128::MAX; // Unlimited approval

        let data = Erc20::encode_approve(&spender, amount);
        assert_eq!(data.len(), 68);
        assert_eq!(&data[..4], &selectors::APPROVE);
    }

    #[test]
    fn test_encode_balance_of() {
        let account = Address::from_hex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap();

        let data = Erc20::encode_balance_of(&account);
        assert_eq!(data.len(), 36);
        assert_eq!(&data[..4], &selectors::BALANCE_OF);
    }

    #[test]
    fn test_decode_uint256() {
        let mut data = [0u8; 32];
        data[31] = 42; // 42 as uint256

        let value = Erc20::decode_uint256(&data).unwrap();
        assert_eq!(value, 42);
    }
}
