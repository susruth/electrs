//! Zcash-specific serialize/deserialize functions.
//!
//! These replace `bitcoin::consensus::encode::{serialize, deserialize}` when
//! the `zcash` feature is active, and handle both our custom Zcash types and
//! bitcoin hash types (BlockHash, Txid).

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::hex::DisplayHex;
use std::io;

use super::deserialize as zcash_deser;
use super::types::*;

/// Zcash serialization error type.
#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

/// Trait for types that can be serialized in Zcash wire format.
pub trait ZcashEncodable {
    fn zcash_serialize(&self) -> Vec<u8>;
}

/// Trait for types that can be deserialized from Zcash wire format.
pub trait ZcashDecodable: Sized {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error>;
}

// --- Serialize/Deserialize functions matching bitcoin::consensus API ---

pub fn serialize<T: ZcashEncodable>(obj: &T) -> Vec<u8> {
    obj.zcash_serialize()
}

pub fn deserialize<T: ZcashDecodable>(data: &[u8]) -> Result<T, Error> {
    T::zcash_deserialize(data)
}

pub fn serialize_hex<T: ZcashEncodable>(obj: &T) -> String {
    serialize(obj).to_lower_hex_string()
}

// --- Implementations for Zcash custom types ---

impl ZcashEncodable for Transaction {
    fn zcash_serialize(&self) -> Vec<u8> {
        self.raw.clone()
    }
}

impl ZcashDecodable for Transaction {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        zcash_deser::deserialize_transaction(data).map_err(|e| Error(e.0))
    }
}

impl ZcashEncodable for BlockHeader {
    fn zcash_serialize(&self) -> Vec<u8> {
        self.raw.clone()
    }
}

impl ZcashDecodable for BlockHeader {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        zcash_deser::deserialize_header(data).map_err(|e| Error(e.0))
    }
}

impl ZcashEncodable for TxOut {
    fn zcash_serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // value as i64 LE (same as Bitcoin wire format)
        buf.extend_from_slice(&(self.value.to_sat() as i64).to_le_bytes());
        // scriptPubKey with compact size prefix
        let script = self.script_pubkey.as_bytes();
        write_compact_size(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
        buf
    }
}

impl ZcashDecodable for TxOut {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = io::Cursor::new(data);
        let mut value_buf = [0u8; 8];
        io::Read::read_exact(&mut cursor, &mut value_buf)
            .map_err(|e| Error(format!("failed to read TxOut value: {}", e)))?;
        let value = i64::from_le_bytes(value_buf) as u64;

        let script_len = read_compact_size_from(&mut cursor)
            .map_err(|e| Error(format!("failed to read TxOut script length: {}", e)))?;
        let mut script_bytes = vec![0u8; script_len as usize];
        io::Read::read_exact(&mut cursor, &mut script_bytes)
            .map_err(|e| Error(format!("failed to read TxOut script: {}", e)))?;

        Ok(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from(script_bytes),
        })
    }
}

// --- Implementations for bitcoin hash types ---

impl ZcashEncodable for bitcoin::BlockHash {
    fn zcash_serialize(&self) -> Vec<u8> {
        // BlockHash serializes as raw 32 bytes (internal byte order)
        self.to_raw_hash().to_byte_array().to_vec()
    }
}

impl ZcashDecodable for bitcoin::BlockHash {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 32 {
            return Err(Error(format!(
                "invalid BlockHash length: {} (expected 32)",
                data.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        Ok(bitcoin::BlockHash::from_raw_hash(
            sha256d::Hash::from_byte_array(bytes),
        ))
    }
}

impl ZcashEncodable for bitcoin::Txid {
    fn zcash_serialize(&self) -> Vec<u8> {
        self.to_raw_hash().to_byte_array().to_vec()
    }
}

impl ZcashDecodable for bitcoin::Txid {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 32 {
            return Err(Error(format!(
                "invalid Txid length: {} (expected 32)",
                data.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        Ok(bitcoin::Txid::from_raw_hash(
            sha256d::Hash::from_byte_array(bytes),
        ))
    }
}

impl ZcashEncodable for bitcoin::hashes::sha256d::Hash {
    fn zcash_serialize(&self) -> Vec<u8> {
        self.to_byte_array().to_vec()
    }
}

impl ZcashDecodable for bitcoin::hashes::sha256d::Hash {
    fn zcash_deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 32 {
            return Err(Error(format!(
                "invalid sha256d::Hash length: {} (expected 32)",
                data.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        Ok(sha256d::Hash::from_byte_array(bytes))
    }
}

impl ZcashEncodable for bitcoin::VarInt {
    fn zcash_serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, self.0);
        buf
    }
}

// --- Helpers ---

fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(253);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(254);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_compact_size_from(r: &mut impl io::Read) -> io::Result<u64> {
    let mut byte = [0u8; 1];
    r.read_exact(&mut byte)?;
    match byte[0] {
        0..=252 => Ok(byte[0] as u64),
        253 => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        254 => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        255 => {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}
