//! ZIP 244: Transaction Identifier Non-Malleable Hash
//!
//! Implements the txid computation for Zcash v5 transactions as specified in
//! https://zips.z.cash/zip-0244

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Txid;

use super::deserialize::{OrchardBundle, SaplingBundle};
use super::types::{TxIn, TxOut};

/// BLAKE2b-256 with a 16-byte personalization string.
fn blake2b_256(personalization: &[u8], data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Encode a compact size (varint) into bytes.
fn compact_size_bytes(n: u64) -> Vec<u8> {
    if n < 253 {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![253u8];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xFFFF_FFFF {
        let mut v = vec![254u8];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![255u8];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// Compute the txid for a v5 transaction per ZIP 244.
pub(crate) fn compute_txid(
    version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    lock_time: u32,
    expiry_height: u32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    sapling: &SaplingBundle,
    orchard: &OrchardBundle,
) -> Txid {
    let header_digest = compute_header_digest(
        version,
        version_group_id,
        consensus_branch_id,
        lock_time,
        expiry_height,
    );
    let transparent_digest = compute_transparent_digest(inputs, outputs);
    let sapling_digest = compute_sapling_digest(sapling);
    let orchard_digest = compute_orchard_digest(orchard);

    // personalization: "ZcashTxHash_" (12 bytes) + consensus_branch_id (4 bytes LE)
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..16].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&header_digest);
    data.extend_from_slice(&transparent_digest);
    data.extend_from_slice(&sapling_digest);
    data.extend_from_slice(&orchard_digest);

    let hash = blake2b_256(&personal, &data);
    // Convert to Txid (which is a SHA256d hash type but we're storing a BLAKE2b result)
    Txid::from_raw_hash(sha256d::Hash::from_byte_array(hash))
}

fn compute_header_digest(
    version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    lock_time: u32,
    expiry_height: u32,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(20);
    // header field: fOverwintered flag | version
    data.extend_from_slice(&(version | (1u32 << 31)).to_le_bytes());
    data.extend_from_slice(&version_group_id.to_le_bytes());
    data.extend_from_slice(&consensus_branch_id.to_le_bytes());
    data.extend_from_slice(&lock_time.to_le_bytes());
    data.extend_from_slice(&expiry_height.to_le_bytes());

    blake2b_256(b"ZTxIdHeadersHash", &data)
}

fn compute_transparent_digest(inputs: &[TxIn], outputs: &[TxOut]) -> [u8; 32] {
    if inputs.is_empty() && outputs.is_empty() {
        return blake2b_256(b"ZTxIdTranspaHash", &[]);
    }

    let prevouts_digest = {
        let mut data = Vec::new();
        for input in inputs {
            data.extend_from_slice(&input.previous_output.txid[..]);
            data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        }
        blake2b_256(b"ZTxIdPrevoutHash", &data)
    };

    let sequence_digest = {
        let mut data = Vec::new();
        for input in inputs {
            data.extend_from_slice(&input.sequence.0.to_le_bytes());
        }
        blake2b_256(b"ZTxIdSequencHash", &data)
    };

    let outputs_digest = {
        let mut data = Vec::new();
        for output in outputs {
            data.extend_from_slice(&(output.value.to_sat() as i64).to_le_bytes());
            let script_bytes = output.script_pubkey.as_bytes();
            data.extend_from_slice(&compact_size_bytes(script_bytes.len() as u64));
            data.extend_from_slice(script_bytes);
        }
        blake2b_256(b"ZTxIdOutputsHash", &data)
    };

    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&prevouts_digest);
    data.extend_from_slice(&sequence_digest);
    data.extend_from_slice(&outputs_digest);

    blake2b_256(b"ZTxIdTranspaHash", &data)
}

fn compute_sapling_digest(sapling: &SaplingBundle) -> [u8; 32] {
    if sapling.spends.is_empty() && sapling.outputs.is_empty() {
        return blake2b_256(b"ZTxIdSapligHash\0", &[]);
    }

    let spends_digest = compute_sapling_spends_digest(sapling);
    let outputs_digest = compute_sapling_outputs_digest(sapling);

    let mut data = Vec::new();
    data.extend_from_slice(&spends_digest);
    data.extend_from_slice(&outputs_digest);
    data.extend_from_slice(&sapling.value_balance.to_le_bytes());

    blake2b_256(b"ZTxIdSapligHash\0", &data)
}

fn compute_sapling_spends_digest(sapling: &SaplingBundle) -> [u8; 32] {
    if sapling.spends.is_empty() {
        return blake2b_256(b"ZTxIdSSpendsHash", &[]);
    }

    // Compact digest: nullifiers
    let compact = {
        let mut data = Vec::new();
        for spend in &sapling.spends {
            data.extend_from_slice(&spend.nullifier);
        }
        blake2b_256(b"ZTxIdSSpendCHash", &data)
    };

    // Non-compact digest: cv, anchor, rk, zkproof, spend_auth_sig
    let noncompact = {
        let mut data = Vec::new();
        for spend in &sapling.spends {
            data.extend_from_slice(&spend.cv);
            data.extend_from_slice(&spend.anchor);
            data.extend_from_slice(&spend.rk);
            data.extend_from_slice(&spend.zkproof);
            data.extend_from_slice(&spend.spend_auth_sig);
        }
        blake2b_256(b"ZTxIdSSpendNHash", &data)
    };

    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&compact);
    data.extend_from_slice(&noncompact);

    blake2b_256(b"ZTxIdSSpendsHash", &data)
}

fn compute_sapling_outputs_digest(sapling: &SaplingBundle) -> [u8; 32] {
    if sapling.outputs.is_empty() {
        return blake2b_256(b"ZTxIdSOutputHash", &[]);
    }

    // Compact: cmu, ephemeral_key, enc_ciphertext[0..52]
    let compact = {
        let mut data = Vec::new();
        for output in &sapling.outputs {
            data.extend_from_slice(&output.cmu);
            data.extend_from_slice(&output.ephemeral_key);
            data.extend_from_slice(&output.enc_ciphertext[..52]);
        }
        blake2b_256(b"ZTxIdSOutC__Hash", &data)
    };

    // Memos: enc_ciphertext[52..564]
    let memos = {
        let mut data = Vec::new();
        for output in &sapling.outputs {
            data.extend_from_slice(&output.enc_ciphertext[52..564]);
        }
        blake2b_256(b"ZTxIdSOutM__Hash", &data)
    };

    // Non-compact: cv, enc_ciphertext[564..580], out_ciphertext, zkproof
    let noncompact = {
        let mut data = Vec::new();
        for output in &sapling.outputs {
            data.extend_from_slice(&output.cv);
            data.extend_from_slice(&output.enc_ciphertext[564..580]);
            data.extend_from_slice(&output.out_ciphertext);
            data.extend_from_slice(&output.zkproof);
        }
        blake2b_256(b"ZTxIdSOutN__Hash", &data)
    };

    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&compact);
    data.extend_from_slice(&memos);
    data.extend_from_slice(&noncompact);

    blake2b_256(b"ZTxIdSOutputHash", &data)
}

fn compute_orchard_digest(orchard: &OrchardBundle) -> [u8; 32] {
    if orchard.actions.is_empty() {
        return blake2b_256(b"ZTxIdOrchardHash", &[]);
    }

    // Compact: nullifier, cmx, ephemeral_key, enc_ciphertext[0..52]
    let compact = {
        let mut data = Vec::new();
        for action in &orchard.actions {
            data.extend_from_slice(&action.nullifier);
            data.extend_from_slice(&action.cmx);
            data.extend_from_slice(&action.ephemeral_key);
            data.extend_from_slice(&action.enc_ciphertext[..52]);
        }
        blake2b_256(b"ZTxIdOActC__Hash", &data)
    };

    // Memos: enc_ciphertext[52..564]
    let memos = {
        let mut data = Vec::new();
        for action in &orchard.actions {
            data.extend_from_slice(&action.enc_ciphertext[52..564]);
        }
        blake2b_256(b"ZTxIdOActM__Hash", &data)
    };

    // Non-compact: cv, rk, enc_ciphertext[564..580], out_ciphertext
    let noncompact = {
        let mut data = Vec::new();
        for action in &orchard.actions {
            data.extend_from_slice(&action.cv);
            data.extend_from_slice(&action.rk);
            data.extend_from_slice(&action.enc_ciphertext[564..580]);
            data.extend_from_slice(&action.out_ciphertext);
        }
        blake2b_256(b"ZTxIdOActN__Hash", &data)
    };

    let actions_digest = {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&compact);
        data.extend_from_slice(&memos);
        data.extend_from_slice(&noncompact);
        blake2b_256(b"ZTxIdOActionsHash", &data)
    };

    let mut data = Vec::new();
    data.extend_from_slice(&actions_digest);
    data.push(orchard.flags);
    data.extend_from_slice(&orchard.value_balance.to_le_bytes());
    data.extend_from_slice(&orchard.anchor);

    blake2b_256(b"ZTxIdOrchardHash", &data)
}
