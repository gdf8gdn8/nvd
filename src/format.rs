//! Database serialization format support.
//!
//! This module provides encoding/decoding for multiple binary serialization
//! formats used as the outer container for CVE item byte blobs:
//!
//! * **Protobuf** — Protocol Buffers via `prost` (default)
//! * **MessagePack** — via `rmp-serde` (compact binary JSON)
//! * **FlatBuffers** — via `flatbuffers` crate (zero-copy, non-size-prefixed)
//! * **CapnProto** — size-prefixed binary format (via `flatbuffers` builder)
//! * **RkyvMmapRedb** — complete combination: rkyv-serialised batches in a
//!   redb database, accessed via memory-mapped I/O (`.rmr`)
//! * **Turso** — items stored in a libSQL (Turso) database (`.turso`)

use crate::cve_api::{
    CveItemBytes,
    NvdCve,
};
use prost::Message;
use redb::{
    ReadableDatabase,
    ReadableTable,
};
use std::error::Error;
use std::io::Read;

/// Supported database serialisation format.
///
/// Each variant serialises a `Vec<Vec<u8>>` (a list of protobuf-encoded
/// CVE items) into a file with a distinct extension.  Formats marked with
/// "zst" use zstd compression; others store raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DbFormat {
    /// Protocol Buffers (default).  File extension: `.proto.zst`.
    Protobuf,
    /// MessagePack via `rmp-serde`.  File extension: `.msgpack.zst`.
    MessagePack,
    /// FlatBuffers via `flatbuffers` crate.  File extension: `.flatbuf.zst`.
    FlatBuffers,
    /// Size-prefixed binary container.  File extension: `.capnp.zst`.
    CapnProto,
    /// Complete combination: rkyv-encoded batches in a redb database,
    /// accessible via memory-mapped I/O.  File extension: `.rmr`.
    RkyvMmapRedb,
    /// Items stored in a libSQL (Turso) database.  File extension: `.turso`.
    Turso,
}

impl DbFormat {
    /// Return the file extension for this format (e.g. `".proto.zst"`).
    pub fn ext(&self) -> &'static str {
        match self {
            DbFormat::Protobuf => ".proto.zst",
            DbFormat::MessagePack => ".msgpack.zst",
            DbFormat::FlatBuffers => ".flatbuf.zst",
            DbFormat::CapnProto => ".capnp.zst",
            DbFormat::RkyvMmapRedb => ".rmr",
            DbFormat::Turso => ".turso",
        }
    }

    /// Whether this format uses zstd compression.
    pub fn uses_zstd(&self) -> bool {
        !matches!(self, DbFormat::RkyvMmapRedb | DbFormat::Turso)
    }

    /// All known database file extensions, used by `--rebuild` to purge old files.
    pub fn all_extensions() -> &'static [&'static str] {
        &[
            ".proto.zst",
            ".msgpack.zst",
            ".flatbuf.zst",
            ".capnp.zst",
            ".rmr",
            ".turso",
        ]
    }

    /// Serialise a list of CVE item byte blobs into a single byte buffer.
    pub fn encode_items(&self, items: &[Vec<u8>]) -> Vec<u8> {
        match self {
            DbFormat::Protobuf => encode_protobuf(items),
            DbFormat::MessagePack => encode_msgpack(items),
            DbFormat::FlatBuffers => encode_flatbuf(items),
            DbFormat::CapnProto => encode_capnp(items),
            DbFormat::RkyvMmapRedb => encode_rmr(items),
            DbFormat::Turso => encode_turso(items),
        }
    }

    /// Deserialise a byte buffer back into a list of CVE item byte blobs.
    pub fn decode_items(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        match self {
            DbFormat::Protobuf => decode_protobuf(data),
            DbFormat::MessagePack => decode_msgpack(data),
            DbFormat::FlatBuffers => decode_flatbuf(data),
            DbFormat::CapnProto => decode_capnp(data),
            DbFormat::RkyvMmapRedb => decode_rmr(data),
            DbFormat::Turso => decode_turso(data),
        }
    }
}

// ── ProtoBuf ──────────────────────────────────────────────────────────

fn encode_protobuf(items: &[Vec<u8>]) -> Vec<u8> {
    let nvd_cve = NvdCve {
        cve_item_bytes_list: items
            .iter()
            .map(|b| CveItemBytes {
                cve_item_bytes: b.clone(),
            })
            .collect(),
    };
    let mut buf = Vec::new();
    nvd_cve.encode(&mut buf).unwrap();
    buf
}

fn decode_protobuf(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let nvd_cve = NvdCve::decode(data)?;
    Ok(nvd_cve
        .cve_item_bytes_list
        .into_iter()
        .map(|b| b.cve_item_bytes)
        .collect())
}

// ── MessagePack ───────────────────────────────────────────────────────

fn encode_msgpack(items: &[Vec<u8>]) -> Vec<u8> {
    rmp_serde::to_vec_named(items).unwrap()
}

fn decode_msgpack(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let items: Vec<Vec<u8>> = rmp_serde::from_slice(data)?;
    Ok(items)
}

// ── FlatBuffers (standard, non-size-prefixed) ────────────────────────

fn encode_flatbuf(items: &[Vec<u8>]) -> Vec<u8> {
    use flatbuffers::FlatBufferBuilder;

    let mut fbb = FlatBufferBuilder::new();
    let packed = pack_items(items);
    let v = fbb.create_vector(&packed);
    fbb.finish(v, None);
    fbb.finished_data().to_vec()
}

fn decode_flatbuf(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let packed = extract_vector_from_flatbuffer(data)?;
    unpack_items(&packed)
}

// ── Cap'n Proto (size-prefixed flatbuffer) ──────────────────────────

fn encode_capnp(items: &[Vec<u8>]) -> Vec<u8> {
    use flatbuffers::FlatBufferBuilder;

    let mut fbb = FlatBufferBuilder::new();
    let packed = pack_items(items);
    let v = fbb.create_vector(&packed);
    fbb.finish_size_prefixed(v, None);
    fbb.finished_data().to_vec()
}

fn decode_capnp(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    if data.len() < 8 {
        return Err("capnp data too short".into());
    }
    let buf = &data[4..];
    let packed = extract_vector_from_flatbuffer(buf)?;
    unpack_items(&packed)
}

// ── Rkyv Mmap Redb (complete combination) ──────────────────────────────

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
};

#[derive(Archive, Deserialize, Serialize)]
struct RkyvContainer {
    items: Vec<Vec<u8>>,
}

pub(crate) fn encode_rkyv(items: &[Vec<u8>]) -> Vec<u8> {
    let container = RkyvContainer {
        items: items.to_vec(),
    };
    rkyv::to_bytes::<rkyv::rancor::Error>(&container)
        .unwrap()
        .as_ref()
        .to_vec()
}

pub(crate) fn decode_rkyv(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let container = rkyv::from_bytes::<RkyvContainer, rkyv::rancor::Error>(data)?;
    Ok(container.items)
}

/// Encode items as rkyv archives stored in a redb database.
///
/// Items are batched (up to 8000 per batch), each batch is rkyv-encoded,
/// and stored at a sequential key in a redb database.  The file is
/// designed to be memory-mapped for zero-copy access to the rkyv data.
fn encode_rmr(items: &[Vec<u8>]) -> Vec<u8> {
    let dir = std::env::temp_dir();
    let path = dir.join("nvd_rmr_encode.tmp");
    let _ = std::fs::remove_file(&path);
    let db = redb::Database::create(&path).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let table_def: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("batches");
        let mut table = txn.open_table(table_def).unwrap();
        let batch_size: usize = 8000;
        let chunks = items.chunks(batch_size);
        let mut key: u64 = 0;
        for chunk in chunks {
            let rkyv_bytes = encode_rkyv(chunk);
            table.insert(key, rkyv_bytes.as_slice()).unwrap();
            key += 1;
        }
    }
    txn.commit().unwrap();
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

/// Decode all items from a redb database containing rkyv-encoded batches.
///
/// Opens the redb database (the bytes come from a temp file), iterates
/// all batch entries, and rkyv-decodes each batch to recover the items.
/// In production, the redb file would be memory-mapped (`memmap2`) for
/// efficient I/O — the temp-file dance is only needed here because
/// `encode_items`/`decode_items` work with byte buffers.
fn decode_rmr(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let dir = std::env::temp_dir();
    let path = dir.join("nvd_rmr_decode.tmp");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, data)?;
    let db = redb::Database::open(&path)?;
    let txn = db.begin_read()?;
    let table_def: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("batches");
    let table = txn.open_table(table_def)?;
    let mut all_items = Vec::new();
    for entry in table.iter()? {
        let (_key, value) = entry?;
        let batch = decode_rkyv(value.value())?;
        all_items.extend(batch);
    }
    let _ = std::fs::remove_file(&path);
    all_items.shrink_to_fit();
    Ok(all_items)
}

// ── Turso (libSQL via turso crate) ────────────────────────────────────

/// Encode items into a libSQL database (Turso-compatible).
///
/// Each item is stored as a row in the `cve_items` table.  The file bytes
/// are read back after the database is fully written, so they can be fed
/// through the `encode_items`/`decode_items` byte-buffer interface.
fn encode_turso(items: &[Vec<u8>]) -> Vec<u8> {
    let dir = std::env::temp_dir();
    let path = dir.join("nvd_turso_encode.tmp");
    let _ = std::fs::remove_file(&path);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        let _ = conn.pragma_update("journal_mode", "DELETE").await.unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cve_items (id INTEGER PRIMARY KEY, data BLOB)",
            (),
        )
        .await
        .unwrap();
        for (i, item) in items.iter().enumerate() {
            conn.execute(
                "INSERT INTO cve_items (id, data) VALUES (?1, ?2)",
                (i as i64, item.as_slice()),
            )
            .await
            .unwrap();
        }
        let _ = conn
            .pragma_update("wal_checkpoint", "TRUNCATE")
            .await
            .unwrap();
        let _ = conn.cacheflush();
    });
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

/// Decode all items from a libSQL database byte blob compatible with
/// Turso.
///
/// Writes the bytes to a temp file, opens it with the `turso` crate, reads
/// all rows from `cve_items` ordered by id, and returns the items.
fn decode_turso(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let dir = std::env::temp_dir();
    let path = dir.join("nvd_turso_decode.tmp");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, data)?;

    let rt = tokio::runtime::Runtime::new()?;
    let items = rt.block_on(async {
        let db = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await?;
        let conn = db.connect()?;
        let mut stmt = conn
            .prepare("SELECT data FROM cve_items ORDER BY id")
            .await?;
        let mut rows = stmt.query(()).await?;
        let mut items = Vec::new();
        while let Some(row) = rows.next().await? {
            let value = row.get_value(0)?;
            if let turso::value::Value::Blob(data) = value {
                items.push(data);
            }
        }
        Ok::<_, Box<dyn Error>>(items)
    })?;

    let _ = std::fs::remove_file(&path);
    Ok(items)
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Pack items into a single byte buffer: [num_items:u32, len1:u32, data1..., ...]
fn pack_items(items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = 4 + items.iter().map(|i| 4 + i.len()).sum::<usize>();
    let mut packed = Vec::with_capacity(total_len);
    packed.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        packed.extend_from_slice(&(item.len() as u32).to_le_bytes());
        packed.extend_from_slice(item);
    }
    packed
}

fn unpack_items(data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    if data.len() < 4 {
        return Err("packed data too short".into());
    }
    let count = u32::from_le_bytes(data[0..4].try_into()?) as usize;
    let mut pos = 4;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return Err("truncated packed data".into());
        }
        let item_len = u32::from_le_bytes(data[pos..pos + 4].try_into()?) as usize;
        pos += 4;
        if pos + item_len > data.len() {
            return Err("truncated packed item data".into());
        }
        items.push(data[pos..pos + item_len].to_vec());
        pos += item_len;
    }
    Ok(items)
}

/// Extract a byte vector from a flatbuffer that has a vector as root.
///
/// `FlatBufferBuilder::finished_data()` places the root uoffset at the
/// *beginning* of the returned slice.  Layout:
///
/// ```text
/// [root_uoffset: u32 LE][vector_len: u32 LE][vector_data...]
/// ```
fn extract_vector_from_flatbuffer(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.len() < 8 {
        return Err("flatbuffer data too short".into());
    }
    let root_uoffset = u32::from_le_bytes(data[0..4].try_into()?) as usize;
    let vector_start = root_uoffset;
    if vector_start + 4 > data.len() {
        return Err("invalid flatbuffer root offset".into());
    }
    let packed_len = u32::from_le_bytes(data[vector_start..vector_start + 4].try_into()?) as usize;
    let packed_start = vector_start + 4;
    if packed_start + packed_len > data.len() {
        return Err("invalid flatbuffer vector length".into());
    }
    Ok(data[packed_start..packed_start + packed_len].to_vec())
}

#[cfg(test)]
mod tests {
    use crate::format::DbFormat;

    fn roundtrip(format: DbFormat) {
        let items: Vec<Vec<u8>> =
            vec![b"hello".to_vec(), b"world".to_vec(), vec![0u8; 256], vec![]];
        let encoded = format.encode_items(&items);
        let decoded = format.decode_items(&encoded).unwrap();
        assert_eq!(items, decoded, "roundtrip failed for {:?}", format);
    }

    #[test]
    fn test_rmr_roundtrip() {
        roundtrip(DbFormat::RkyvMmapRedb);
    }

    #[test]
    fn test_flatbuf_roundtrip() {
        roundtrip(DbFormat::FlatBuffers);
    }

    #[test]
    fn test_capnp_roundtrip() {
        roundtrip(DbFormat::CapnProto);
    }

    #[test]
    fn test_protobuf_roundtrip() {
        roundtrip(DbFormat::Protobuf);
    }

    #[test]
    fn test_msgpack_roundtrip() {
        roundtrip(DbFormat::MessagePack);
    }

    #[test]
    fn test_turso_roundtrip() {
        roundtrip(DbFormat::Turso);
    }

    #[test]
    fn test_all_extensions() {
        let exts = DbFormat::all_extensions();
        assert!(exts.contains(&".proto.zst"));
        assert!(exts.contains(&".rmr"));
        assert!(exts.contains(&".turso"));
        assert_eq!(exts.len(), 6);
    }

    #[test]
    fn test_uses_zstd() {
        assert!(DbFormat::Protobuf.uses_zstd());
        assert!(DbFormat::MessagePack.uses_zstd());
        assert!(DbFormat::FlatBuffers.uses_zstd());
        assert!(DbFormat::CapnProto.uses_zstd());
        assert!(!DbFormat::RkyvMmapRedb.uses_zstd());
        assert!(!DbFormat::Turso.uses_zstd());
    }
}
