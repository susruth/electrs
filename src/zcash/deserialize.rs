//! Zcash block and transaction deserialization from wire format.
//!
//! Handles all Zcash transaction versions (v1-v5) and block format including
//! the Equihash-specific header (32-byte nonce + variable-length solution).

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{BlockHash, OutPoint, Sequence, Txid};
use std::io::{self, Cursor, Read};

use super::types::*;
use super::zip244;

/// Zcash error type for deserialization failures.
#[derive(Debug)]
pub struct ZcashError(pub String);

impl std::fmt::Display for ZcashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zcash error: {}", self.0)
    }
}

impl std::error::Error for ZcashError {}

impl From<io::Error> for ZcashError {
    fn from(e: io::Error) -> Self {
        ZcashError(format!("IO error: {}", e))
    }
}

// Version group IDs for different Zcash transaction versions
const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
const NU5_VERSION_GROUP_ID: u32 = 0x26A7_270A;

/// Read a compact size (varint) from the stream.
fn read_compact_size(r: &mut impl Read) -> io::Result<u64> {
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

fn read_u32_le(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_i32_le(r: &mut impl Read) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

fn read_i64_le(r: &mut impl Read) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

fn read_bytes(r: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_hash32(r: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Deserialize a Zcash block from raw bytes.
pub fn deserialize_block(data: &[u8]) -> Result<Block, ZcashError> {
    let mut cursor = Cursor::new(data);

    // Deserialize header
    let header_start = cursor.position() as usize;
    let header = deserialize_header_from_reader(&mut cursor)?;
    let header_end = cursor.position() as usize;

    // Store raw header bytes
    let raw_header = data[header_start..header_end].to_vec();
    let header = BlockHeader::from_raw(
        header.0, header.1, header.2, header.3, header.4, header.5, header.6, header.7, raw_header,
    );

    // Read transactions
    let tx_count = read_compact_size(&mut cursor)
        .map_err(|e| ZcashError(format!("failed to read tx count: {}", e)))?;

    let mut txdata = Vec::with_capacity(tx_count as usize);
    for i in 0..tx_count {
        let tx_start = cursor.position() as usize;
        let tx = deserialize_transaction_inner(&mut cursor)
            .map_err(|e| ZcashError(format!("failed to parse tx {}: {}", i, e)))?;
        let tx_end = cursor.position() as usize;
        let raw_tx = data[tx_start..tx_end].to_vec();

        let txid = compute_txid(&tx, &raw_tx);

        txdata.push(Transaction::new(
            tx.version,
            tx.lock_time,
            tx.input,
            tx.output,
            txid,
            raw_tx,
        ));
    }

    Ok(Block::new(header, txdata, data.len()))
}

/// Deserialize a Zcash block header from raw bytes.
pub fn deserialize_header(data: &[u8]) -> Result<BlockHeader, ZcashError> {
    let mut cursor = Cursor::new(data);
    let h = deserialize_header_from_reader(&mut cursor)?;
    Ok(BlockHeader::from_raw(
        h.0,
        h.1,
        h.2,
        h.3,
        h.4,
        h.5,
        h.6,
        h.7,
        data.to_vec(),
    ))
}

/// Deserialize a Zcash transaction from raw bytes.
pub fn deserialize_transaction(data: &[u8]) -> Result<Transaction, ZcashError> {
    let mut cursor = Cursor::new(data);
    let tx = deserialize_transaction_inner(&mut cursor)?;
    let txid = compute_txid(&tx, data);
    Ok(Transaction::new(
        tx.version,
        tx.lock_time,
        tx.input,
        tx.output,
        txid,
        data.to_vec(),
    ))
}

// Raw parsed header fields (before constructing the final type)
type RawHeader = (
    i32,       // version
    BlockHash, // prev_blockhash
    [u8; 32],  // merkle_root
    [u8; 32],  // hash_final_sapling_root
    u32,       // time
    u32,       // bits
    [u8; 32],  // nonce
    Vec<u8>,   // solution
);

fn deserialize_header_from_reader(r: &mut impl Read) -> Result<RawHeader, ZcashError> {
    let version = read_i32_le(r)?;

    let prev_hash = read_hash32(r)?;
    let prev_blockhash = BlockHash::from_raw_hash(sha256d::Hash::from_byte_array(prev_hash));

    let merkle_root = read_hash32(r)?;
    let hash_final_sapling_root = read_hash32(r)?;

    let time = read_u32_le(r)?;
    let bits = read_u32_le(r)?;
    let nonce = read_hash32(r)?;

    let solution_len = read_compact_size(r)? as usize;
    let solution = read_bytes(r, solution_len)?;

    Ok((
        version,
        prev_blockhash,
        merkle_root,
        hash_final_sapling_root,
        time,
        bits,
        nonce,
        solution,
    ))
}

/// Intermediate parsed transaction (before txid is computed).
struct ParsedTx {
    version: Version,
    lock_time: LockTime,
    input: Vec<TxIn>,
    output: Vec<TxOut>,
    /// For v5+ transactions, we need these fields for ZIP 244 txid computation.
    v5_fields: Option<V5Fields>,
}

struct V5Fields {
    version_group_id: u32,
    consensus_branch_id: u32,
    expiry_height: u32,
    sapling_bundle: SaplingBundle,
    orchard_bundle: OrchardBundle,
}

/// Sapling bundle data needed for txid computation.
pub(crate) struct SaplingBundle {
    pub spends: Vec<SaplingSpend>,
    pub outputs: Vec<SaplingOutput>,
    pub value_balance: i64, // only if spends + outputs > 0
}

pub(crate) struct SaplingSpend {
    pub cv: [u8; 32],
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub zkproof: Vec<u8>,        // 192 bytes
    pub spend_auth_sig: Vec<u8>, // 64 bytes
}

pub(crate) struct SaplingOutput {
    pub cv: [u8; 32],
    pub cmu: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>, // 580 bytes
    pub out_ciphertext: Vec<u8>, // 80 bytes
    pub zkproof: Vec<u8>,        // 192 bytes
}

/// Orchard bundle data needed for txid computation.
pub(crate) struct OrchardBundle {
    pub actions: Vec<OrchardAction>,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: [u8; 32],
    pub _proofs: Vec<u8>,
    pub _spend_auth_sigs: Vec<Vec<u8>>,
    pub _binding_sig: Vec<u8>,
}

pub(crate) struct OrchardAction {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>, // 580 bytes
    pub out_ciphertext: Vec<u8>, // 80 bytes
}

fn deserialize_transaction_inner(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let header = read_u32_le(r)?;
    let f_overwintered = (header >> 31) == 1;
    let version = (header & 0x7FFF_FFFF) as i32;

    if f_overwintered {
        let version_group_id = read_u32_le(r)?;
        match (version, version_group_id) {
            (3, OVERWINTER_VERSION_GROUP_ID) => parse_v3(r),
            (4, SAPLING_VERSION_GROUP_ID) => parse_v4(r),
            (5, NU5_VERSION_GROUP_ID) => parse_v5(r),
            _ => Err(ZcashError(format!(
                "unknown overwintered version {}/group_id {:#010x}",
                version, version_group_id
            ))),
        }
    } else {
        match version {
            1 => parse_v1(r),
            2 => parse_v2(r),
            _ => Err(ZcashError(format!("unknown tx version {}", version))),
        }
    }
}

/// Parse transparent inputs from the byte stream.
fn parse_transparent_inputs(r: &mut impl Read) -> io::Result<Vec<TxIn>> {
    let count = read_compact_size(r)? as usize;
    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let prev_hash = read_hash32(r)?;
        let prev_txid = Txid::from_raw_hash(sha256d::Hash::from_byte_array(prev_hash));
        let prev_index = read_u32_le(r)?;
        let script_len = read_compact_size(r)? as usize;
        let script_bytes = read_bytes(r, script_len)?;
        let sequence = read_u32_le(r)?;

        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout: prev_index,
            },
            script_sig: Script::from(script_bytes),
            sequence: Sequence(sequence),
            witness: Witness,
        });
    }
    Ok(inputs)
}

/// Parse transparent outputs from the byte stream.
fn parse_transparent_outputs(r: &mut impl Read) -> io::Result<Vec<TxOut>> {
    let count = read_compact_size(r)? as usize;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let value = read_i64_le(r)? as u64;
        let script_len = read_compact_size(r)? as usize;
        let script_bytes = read_bytes(r, script_len)?;

        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from(script_bytes),
        });
    }
    Ok(outputs)
}

/// Skip JoinSplit data (Sprout shielded transactions, pre-Sapling).
fn skip_joinsplits(r: &mut impl Read, use_groth: bool) -> io::Result<()> {
    let count = read_compact_size(r)? as usize;
    if count == 0 {
        return Ok(());
    }

    let proof_size = if use_groth { 192 } else { 296 };
    for _ in 0..count {
        // vpub_old(8) + vpub_new(8) + anchor(32) + nullifiers(2*32) + commitments(2*32)
        // + random_seed(32) + vmacs(2*32) + proof + enc_ciphertexts(2*601)
        let joinsplit_size = 8 + 8 + 32 + 64 + 64 + 32 + 64 + proof_size + 1202;
        read_bytes(r, joinsplit_size)?;
    }
    // joinSplitPubKey(32) + joinSplitSig(64)
    read_bytes(r, 32 + 64)?;
    Ok(())
}

/// Parse v1 transaction (pre-Overwinter, no shielded data).
fn parse_v1(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let inputs = parse_transparent_inputs(r)?;
    let outputs = parse_transparent_outputs(r)?;
    let lock_time = read_u32_le(r)?;

    Ok(ParsedTx {
        version: Version(1),
        lock_time: LockTime(lock_time),
        input: inputs,
        output: outputs,
        v5_fields: None,
    })
}

/// Parse v2 transaction (JoinSplit support).
fn parse_v2(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let inputs = parse_transparent_inputs(r)?;
    let outputs = parse_transparent_outputs(r)?;
    let lock_time = read_u32_le(r)?;
    // Skip JoinSplit data (BCTV14 proofs)
    skip_joinsplits(r, false)?;

    Ok(ParsedTx {
        version: Version(2),
        lock_time: LockTime(lock_time),
        input: inputs,
        output: outputs,
        v5_fields: None,
    })
}

/// Parse v3 transaction (Overwinter).
fn parse_v3(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let inputs = parse_transparent_inputs(r)?;
    let outputs = parse_transparent_outputs(r)?;
    let lock_time = read_u32_le(r)?;
    let _expiry_height = read_u32_le(r)?;
    // Skip JoinSplit data (Groth16 proofs)
    skip_joinsplits(r, true)?;

    Ok(ParsedTx {
        version: Version(3),
        lock_time: LockTime(lock_time),
        input: inputs,
        output: outputs,
        v5_fields: None,
    })
}

/// Parse v4 transaction (Sapling).
fn parse_v4(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let inputs = parse_transparent_inputs(r)?;
    let outputs = parse_transparent_outputs(r)?;
    let lock_time = read_u32_le(r)?;
    let _expiry_height = read_u32_le(r)?;
    let _value_balance = read_i64_le(r)?;

    // Skip Sapling shielded spends
    let n_shielded_spend = read_compact_size(r)? as usize;
    for _ in 0..n_shielded_spend {
        // cv(32) + anchor(32) + nullifier(32) + rk(32) + zkproof(192) + spend_auth_sig(64) = 384
        read_bytes(r, 384)?;
    }

    // Skip Sapling shielded outputs
    let n_shielded_output = read_compact_size(r)? as usize;
    for _ in 0..n_shielded_output {
        // cv(32) + cmu(32) + ephemeral_key(32) + enc_ciphertext(580) + out_ciphertext(80) + zkproof(192) = 948
        read_bytes(r, 948)?;
    }

    // Skip JoinSplit data (Groth16 proofs)
    skip_joinsplits(r, true)?;

    // Skip binding sig if Sapling data present
    if n_shielded_spend + n_shielded_output > 0 {
        read_bytes(r, 64)?; // bindingSig
    }

    Ok(ParsedTx {
        version: Version(4),
        lock_time: LockTime(lock_time),
        input: inputs,
        output: outputs,
        v5_fields: None,
    })
}

/// Parse v5 transaction (NU5).
/// v5 has a different field ordering from v1-v4 and requires ZIP 244 for txid.
fn parse_v5(r: &mut Cursor<&[u8]>) -> Result<ParsedTx, ZcashError> {
    let consensus_branch_id = read_u32_le(r)?;
    let lock_time = read_u32_le(r)?;
    let expiry_height = read_u32_le(r)?;

    // Transparent data
    let inputs = parse_transparent_inputs(r)?;
    let outputs = parse_transparent_outputs(r)?;

    // Sapling bundle
    let sapling_bundle = parse_v5_sapling_bundle(r)?;

    // Orchard bundle
    let orchard_bundle = parse_v5_orchard_bundle(r)?;

    Ok(ParsedTx {
        version: Version(5),
        lock_time: LockTime(lock_time),
        input: inputs,
        output: outputs,
        v5_fields: Some(V5Fields {
            version_group_id: NU5_VERSION_GROUP_ID,
            consensus_branch_id,
            expiry_height,
            sapling_bundle,
            orchard_bundle,
        }),
    })
}

fn parse_v5_sapling_bundle(r: &mut impl Read) -> Result<SaplingBundle, ZcashError> {
    let n_spends = read_compact_size(r)? as usize;

    // Read spend descriptions (compact part)
    let mut spends: Vec<SaplingSpend> = Vec::with_capacity(n_spends);
    for _ in 0..n_spends {
        let cv = read_hash32(r)?;
        let nullifier = read_hash32(r)?;
        let rk = read_hash32(r)?;
        spends.push(SaplingSpend {
            cv,
            anchor: [0u8; 32], // filled in below
            nullifier,
            rk,
            zkproof: Vec::new(),
            spend_auth_sig: Vec::new(),
        });
    }

    let n_outputs = read_compact_size(r)? as usize;

    // Read output descriptions (compact part)
    let mut sapling_outputs: Vec<SaplingOutput> = Vec::with_capacity(n_outputs);
    for _ in 0..n_outputs {
        let cv = read_hash32(r)?;
        let cmu = read_hash32(r)?;
        let ephemeral_key = read_hash32(r)?;
        let enc_ciphertext = read_bytes(r, 580)?;
        let out_ciphertext = read_bytes(r, 80)?;
        sapling_outputs.push(SaplingOutput {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof: Vec::new(),
        });
    }

    let mut value_balance: i64 = 0;
    if n_spends + n_outputs > 0 {
        value_balance = read_i64_le(r)?;
    }

    // Anchor (shared across all spends)
    if n_spends > 0 {
        let anchor = read_hash32(r)?;
        for spend in &mut spends {
            spend.anchor = anchor;
        }
    }

    // Spend proofs
    for spend in &mut spends {
        spend.zkproof = read_bytes(r, 192)?;
    }

    // Spend auth sigs
    for spend in &mut spends {
        spend.spend_auth_sig = read_bytes(r, 64)?;
    }

    // Output proofs
    for output in &mut sapling_outputs {
        output.zkproof = read_bytes(r, 192)?;
    }

    // Binding sig
    if n_spends + n_outputs > 0 {
        read_bytes(r, 64)?; // binding_sig
    }

    Ok(SaplingBundle {
        spends,
        outputs: sapling_outputs,
        value_balance,
    })
}

fn parse_v5_orchard_bundle(r: &mut impl Read) -> Result<OrchardBundle, ZcashError> {
    let n_actions = read_compact_size(r)? as usize;

    if n_actions == 0 {
        return Ok(OrchardBundle {
            actions: Vec::new(),
            flags: 0,
            value_balance: 0,
            anchor: [0u8; 32],
            _proofs: Vec::new(),
            _spend_auth_sigs: Vec::new(),
            _binding_sig: Vec::new(),
        });
    }

    let mut actions = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        let cv = read_hash32(r)?;
        let nullifier = read_hash32(r)?;
        let rk = read_hash32(r)?;
        let cmx = read_hash32(r)?;
        let ephemeral_key = read_hash32(r)?;
        let enc_ciphertext = read_bytes(r, 580)?;
        let out_ciphertext = read_bytes(r, 80)?;
        actions.push(OrchardAction {
            cv,
            nullifier,
            rk,
            cmx,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        });
    }

    let mut flags_byte = [0u8; 1];
    r.read_exact(&mut flags_byte)?;
    let flags = flags_byte[0];

    let value_balance = read_i64_le(r)?;
    let anchor = read_hash32(r)?;

    let proofs_size = read_compact_size(r)? as usize;
    let proofs = read_bytes(r, proofs_size)?;

    let mut spend_auth_sigs = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        spend_auth_sigs.push(read_bytes(r, 64)?);
    }

    let binding_sig = read_bytes(r, 64)?;

    Ok(OrchardBundle {
        actions,
        flags,
        value_balance,
        anchor,
        _proofs: proofs,
        _spend_auth_sigs: spend_auth_sigs,
        _binding_sig: binding_sig,
    })
}

/// Compute the txid for a transaction.
/// - v1-v4: SHA256d of the entire serialized transaction
/// - v5: ZIP 244 digest
fn compute_txid(tx: &ParsedTx, raw: &[u8]) -> Txid {
    match &tx.v5_fields {
        None => {
            // v1-v4: txid = SHA256d(raw_bytes)
            let hash = sha256d::Hash::hash(raw);
            Txid::from_raw_hash(hash)
        }
        Some(v5) => {
            // v5: ZIP 244 txid computation
            zip244::compute_txid(
                5,
                v5.version_group_id,
                v5.consensus_branch_id,
                tx.lock_time.0,
                v5.expiry_height,
                &tx.input,
                &tx.output,
                &v5.sapling_bundle,
                &v5.orchard_bundle,
            )
        }
    }
}
