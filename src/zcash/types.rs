use bitcoin::hashes::{sha256d, Hash};
pub use bitcoin::{BlockHash, OutPoint, ScriptBuf as Script, Sequence, Txid};

/// Zcash block: header + transactions.
#[derive(Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub txdata: Vec<Transaction>,
    raw_size: usize,
}

impl Block {
    pub fn new(header: BlockHeader, txdata: Vec<Transaction>, raw_size: usize) -> Self {
        Block {
            header,
            txdata,
            raw_size,
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Zcash does not have SegWit, so weight = size * 4.
    pub fn weight(&self) -> u64 {
        self.raw_size as u64 * 4
    }

    /// Total serialized size in bytes.
    pub fn total_size(&self) -> usize {
        self.raw_size
    }
}

/// Zcash block header.
///
/// Unlike Bitcoin's 80-byte header, Zcash headers include a 32-byte nonce
/// and a variable-length Equihash solution (~1344 bytes for mainnet).
#[derive(Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: [u8; 32],
    pub hash_final_sapling_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: [u8; 32],
    pub solution: Vec<u8>,
    /// Cached block hash (SHA256d of the serialized header).
    hash: BlockHash,
    /// Raw serialized header bytes (for DB storage and hash computation).
    pub(crate) raw: Vec<u8>,
}

impl BlockHeader {
    pub fn from_raw(
        version: i32,
        prev_blockhash: BlockHash,
        merkle_root: [u8; 32],
        hash_final_sapling_root: [u8; 32],
        time: u32,
        bits: u32,
        nonce: [u8; 32],
        solution: Vec<u8>,
        raw: Vec<u8>,
    ) -> Self {
        let hash_bytes = sha256d::Hash::hash(&raw);
        let hash = BlockHash::from_raw_hash(hash_bytes);
        BlockHeader {
            version,
            prev_blockhash,
            merkle_root,
            hash_final_sapling_root,
            time,
            bits,
            nonce,
            solution,
            hash,
            raw,
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        self.hash
    }
}

/// Zcash transaction version.
#[derive(Clone, Copy, Debug)]
pub struct Version(pub i32);

/// Zcash lock time (identical semantics to Bitcoin).
#[derive(Clone, Copy, Debug)]
pub struct LockTime(pub u32);

impl LockTime {
    pub fn to_consensus_u32(self) -> u32 {
        self.0
    }
}

/// Zcash transparent transaction input.
#[derive(Clone)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: Sequence,
    /// Zcash transparent inputs have no witness data (no SegWit).
    pub witness: Witness,
}

/// Empty witness type for Zcash (no SegWit support).
#[derive(Clone)]
pub struct Witness;

impl Witness {
    pub fn is_empty(&self) -> bool {
        true
    }

    pub fn iter(&self) -> std::iter::Empty<&[u8]> {
        std::iter::empty()
    }
}

/// Zcash transparent transaction output.
#[derive(Clone)]
pub struct TxOut {
    pub value: Amount,
    pub script_pubkey: Script,
}

/// Zcash amount in zatoshi (1 ZEC = 10^8 zatoshi).
/// Mirrors bitcoin::Amount interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(pub u64);

impl Amount {
    pub fn from_sat(sat: u64) -> Self {
        Amount(sat)
    }

    pub fn to_sat(self) -> u64 {
        self.0
    }
}

impl serde::Serialize for Amount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Amount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Amount(u64::deserialize(deserializer)?))
    }
}

/// Zcash transaction with transparent data and cached metadata.
#[derive(Clone)]
pub struct Transaction {
    pub version: Version,
    pub lock_time: LockTime,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
    /// Cached txid.
    txid: Txid,
    /// Full raw serialized tx bytes (for DB storage).
    pub(crate) raw: Vec<u8>,
}

impl Transaction {
    pub fn new(
        version: Version,
        lock_time: LockTime,
        input: Vec<TxIn>,
        output: Vec<TxOut>,
        txid: Txid,
        raw: Vec<u8>,
    ) -> Self {
        Transaction {
            version,
            lock_time,
            input,
            output,
            txid,
            raw,
        }
    }

    pub fn compute_txid(&self) -> Txid {
        self.txid
    }

    pub fn txid(&self) -> Txid {
        self.txid
    }

    /// Zcash has no SegWit, so weight = size * 4.
    pub fn weight(&self) -> u64 {
        self.raw.len() as u64 * 4
    }

    /// Total serialized size in bytes.
    pub fn total_size(&self) -> usize {
        self.raw.len()
    }

    /// Check if this transaction is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }
}
