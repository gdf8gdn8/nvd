//! Database serialization format support.
//!
//! This module provides encoding/decoding for multiple binary serialization
//! formats used as the outer container for CVE item byte blobs:
//!
//! * **Protobuf** — Protocol Buffers via `prost` (default)
//! * **MessagePack** — via `rmp-serde` (compact binary JSON)
//! * **FlatBuffers** — via `flatbuffers` crate (zero-copy, non-size-prefixed)
//! * **CapnProto** — size-prefixed binary format (via `flatbuffers` builder)

use std::error::Error;

use prost::Message;

use crate::cve_api::{CveItemBytes, NvdCve};

/// Supported database serialisation format.
///
/// Each variant serialises a `Vec<Vec<u8>>` (a list of protobuf-encoded
/// CVE items) into a zstd-compressed file with a distinct extension.
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
}

impl DbFormat {
    /// Return the file extension for this format (e.g. `".proto.zst"`).
    pub fn ext(&self) -> &'static str {
        match self {
            DbFormat::Protobuf => ".proto.zst",
            DbFormat::MessagePack => ".msgpack.zst",
            DbFormat::FlatBuffers => ".flatbuf.zst",
            DbFormat::CapnProto => ".capnp.zst",
        }
    }

    /// All known database file extensions, used by `--rebuild` to purge old files.
    pub fn all_extensions() -> &'static [&'static str] {
        &[".proto.zst", ".msgpack.zst", ".flatbuf.zst", ".capnp.zst"]
    }

    /// Serialise a list of CVE item byte blobs into a single byte buffer.
    pub fn encode_items(&self, items: &[Vec<u8>]) -> Vec<u8> {
        match self {
            DbFormat::Protobuf => encode_protobuf(items),
            DbFormat::MessagePack => encode_msgpack(items),
            DbFormat::FlatBuffers => encode_flatbuf(items),
            DbFormat::CapnProto => encode_capnp(items),
        }
    }

    /// Deserialise a byte buffer back into a list of CVE item byte blobs.
    pub fn decode_items(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        match self {
            DbFormat::Protobuf => decode_protobuf(data),
            DbFormat::MessagePack => decode_msgpack(data),
            DbFormat::FlatBuffers => decode_flatbuf(data),
            DbFormat::CapnProto => decode_capnp(data),
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
/// Layout: [vector_data...][root_uoffset: u32 LE]
fn extract_vector_from_flatbuffer(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.len() < 8 {
        return Err("flatbuffer data too short".into());
    }
    let len = data.len();
    let root_offset_bytes: [u8; 4] = data[len - 4..].try_into()?;
    let root_uoffset = u32::from_le_bytes(root_offset_bytes) as usize;
    let vector_start = len - 4 - root_uoffset;
    if vector_start + 4 > len {
        return Err("invalid flatbuffer root offset".into());
    }
    let vec_len_bytes: [u8; 4] = data[vector_start..vector_start + 4].try_into()?;
    let packed_len = u32::from_le_bytes(vec_len_bytes) as usize;
    let packed_start = vector_start + 4;
    if packed_start + packed_len > len {
        return Err("invalid flatbuffer vector length".into());
    }
    Ok(data[packed_start..packed_start + packed_len].to_vec())
}
