//! Zcash transparent address encoding and decoding.
//!
//! Handles t-addresses (P2PKH and P2SH) for Zcash mainnet, testnet, and regtest.
//! Shielded addresses (z-addresses, unified addresses) are not handled in Phase 1.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Script;

use crate::chain::Network;

// Zcash transparent address version bytes
const ZCASH_P2PKH_VERSION: [u8; 2] = [0x1C, 0xB8]; // t1 prefix
const ZCASH_P2SH_VERSION: [u8; 2] = [0x1C, 0xBD]; // t3 prefix
const ZCASH_TESTNET_P2PKH_VERSION: [u8; 2] = [0x1D, 0x25]; // tm prefix
const ZCASH_TESTNET_P2SH_VERSION: [u8; 2] = [0x1C, 0xBA]; // t2 prefix

fn network_params(network: Network) -> ([u8; 2], [u8; 2]) {
    match network {
        Network::Zcash => (ZCASH_P2PKH_VERSION, ZCASH_P2SH_VERSION),
        Network::ZcashTestnet | Network::ZcashRegtest => {
            (ZCASH_TESTNET_P2PKH_VERSION, ZCASH_TESTNET_P2SH_VERSION)
        }
    }
}

/// Convert a scriptPubKey to a Zcash transparent address string.
pub fn script_to_zcash_address(script: &Script, network: Network) -> Option<String> {
    let (p2pkh_ver, p2sh_ver) = network_params(network);
    let bytes = script.as_bytes();

    if script.is_p2pkh() && bytes.len() == 25 {
        Some(base58check_encode_2byte(&p2pkh_ver, &bytes[3..23]))
    } else if script.is_p2sh() && bytes.len() == 23 {
        Some(base58check_encode_2byte(&p2sh_ver, &bytes[2..22]))
    } else {
        None
    }
}

/// Parse a Zcash transparent address string and return the scriptPubKey bytes.
pub fn parse_zcash_address(addr: &str, network: Network) -> Option<Vec<u8>> {
    let (p2pkh_ver, p2sh_ver) = network_params(network);

    let (version, hash) = base58check_decode_2byte(addr)?;
    if version == p2pkh_ver && hash.len() == 20 {
        // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&[0x88, 0xac]);
        Some(script)
    } else if version == p2sh_ver && hash.len() == 20 {
        // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&hash);
        script.push(0x87);
        Some(script)
    } else {
        None
    }
}

// --- Base58Check with 2-byte version (Zcash uses 2-byte version prefixes) ---

fn base58check_encode_2byte(version: &[u8; 2], payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(2 + payload.len() + 4);
    data.extend_from_slice(version);
    data.extend_from_slice(payload);
    let checksum = sha256d::Hash::hash(&data);
    data.extend_from_slice(&checksum[..4]);
    base58_encode(&data)
}

fn base58check_decode_2byte(addr: &str) -> Option<([u8; 2], Vec<u8>)> {
    let data = base58_decode(addr)?;
    if data.len() < 6 {
        // 2 byte version + at least 0 payload + 4 byte checksum
        return None;
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    let hash = sha256d::Hash::hash(payload);
    if &hash[..4] != checksum {
        return None;
    }
    let mut version = [0u8; 2];
    version.copy_from_slice(&payload[..2]);
    Some((version, payload[2..].to_vec()))
}

// --- Base58 encoding/decoding ---

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(data: &[u8]) -> String {
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut num = data.to_vec();
    let mut result = Vec::new();

    while !num.is_empty() {
        let mut remainder = 0u32;
        let mut new_num = Vec::new();
        for &byte in &num {
            let acc = (remainder << 8) | byte as u32;
            let digit = acc / 58;
            remainder = acc % 58;
            if !new_num.is_empty() || digit > 0 {
                new_num.push(digit as u8);
            }
        }
        result.push(BASE58_ALPHABET[remainder as usize]);
        num = new_num;
    }

    for _ in 0..leading_zeros {
        result.push(b'1');
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let leading_ones = s.chars().take_while(|&c| c == '1').count();
    let mut result: Vec<u8> = Vec::new();

    for ch in s.chars() {
        let pos = BASE58_ALPHABET.iter().position(|&c| c == ch as u8)? as u32;
        let mut carry = pos;
        for byte in result.iter_mut().rev() {
            let acc = (*byte as u32) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            result.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut final_result = vec![0u8; leading_ones];
    final_result.extend_from_slice(&result);
    Some(final_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58check_2byte_roundtrip() {
        let hash = [0u8; 20];
        let encoded = base58check_encode_2byte(&ZCASH_P2PKH_VERSION, &hash);
        let (version, decoded) = base58check_decode_2byte(&encoded).unwrap();
        assert_eq!(version, ZCASH_P2PKH_VERSION);
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_zcash_p2pkh_address_prefix() {
        let hash = [1u8; 20];
        let addr = base58check_encode_2byte(&ZCASH_P2PKH_VERSION, &hash);
        assert!(
            addr.starts_with("t1"),
            "P2PKH address should start with t1, got: {}",
            addr
        );
    }

    #[test]
    fn test_zcash_p2sh_address_prefix() {
        let hash = [1u8; 20];
        let addr = base58check_encode_2byte(&ZCASH_P2SH_VERSION, &hash);
        assert!(
            addr.starts_with("t3"),
            "P2SH address should start with t3, got: {}",
            addr
        );
    }

    #[test]
    fn test_parse_and_validate_roundtrip() {
        // Create a P2PKH scriptPubKey
        let mut p2pkh_script = vec![0x76, 0xa9, 0x14];
        p2pkh_script.extend_from_slice(&[1u8; 20]);
        p2pkh_script.extend_from_slice(&[0x88, 0xac]);

        let script = bitcoin::ScriptBuf::from(p2pkh_script.clone());
        let addr = script_to_zcash_address(&script, Network::Zcash).unwrap();
        let decoded_script = parse_zcash_address(&addr, Network::Zcash).unwrap();
        assert_eq!(decoded_script, p2pkh_script);
    }

    #[test]
    fn test_wrong_network_rejected() {
        let hash = [1u8; 20];
        let addr = base58check_encode_2byte(&ZCASH_P2PKH_VERSION, &hash);
        // mainnet address should not parse as testnet
        assert!(parse_zcash_address(&addr, Network::ZcashTestnet).is_none());
    }
}
