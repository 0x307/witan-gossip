//! WASI C-ABI exports for the `wasm32-wasip1` target.
//!
//! ## ABI Convention
//!
//! All functions use a 12-byte out-pointer for results:
//! - `[ok: i32, val_ptr: i32, val_len: i32]`
//!   - `ok == 1`: success; `val_ptr`/`val_len` describe the returned data
//!   - `ok == 0`: error; `val_ptr`/`val_len` point to a JSON error string
//!
//! Strings and byte slices are passed as `(ptr: i32, len: i32)` pairs.
//!
//! The host is responsible for calling [`wasi_free`] on any non-null pointer
//! returned in the out-slot.
//!
//! ## Memory Management
//!
//! - [`wasi_alloc`] / [`wasi_free`] expose the WASM linear-memory allocator.
//! - Returned heap data is leaked from Rust's allocator; the host must free it.

use crate::api;
use crate::error::GossipError;

// ── Allocator exports ─────────────────────────────────────────────────────────

/// Allocate `size` bytes in WASM linear memory. Returns the pointer.
///
/// The host uses this to write input data before calling any gossip function.
#[no_mangle]
pub unsafe extern "C" fn wasi_alloc(size: i32) -> i32 {
    let layout = std::alloc::Layout::from_size_align(size as usize, 1)
        .expect("wasi_alloc: invalid layout");
    let ptr = std::alloc::alloc(layout);
    ptr as i32
}

/// Free `len` bytes at `ptr` previously allocated by [`wasi_alloc`].
#[no_mangle]
pub unsafe extern "C" fn wasi_free(ptr: i32, len: i32) {
    if ptr == 0 || len == 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(len as usize, 1)
        .expect("wasi_free: invalid layout");
    std::alloc::dealloc(ptr as *mut u8, layout);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Serialize a [`GossipError`] to a JSON string and leak it into WASM memory.
/// Returns `(ptr, len)` suitable for writing into an error out-slot.
fn error_to_leaked_json(e: &GossipError) -> (i32, i32) {
    let variant = match e {
        GossipError::NotInitialized => "NotInitialized",
        GossipError::AlreadyInitialized => "AlreadyInitialized",
        GossipError::ConfigError(_) => "ConfigError",
        GossipError::IdentityError(_) => "IdentityError",
        GossipError::HandshakeError(_) => "HandshakeError",
        GossipError::SessionNotFound(_) => "SessionNotFound",
        GossipError::EnvelopeError(_) => "EnvelopeError",
        GossipError::SignatureInvalid => "SignatureInvalid",
        GossipError::ReplayDetected => "ReplayDetected",
        GossipError::TtlExpired => "TtlExpired",
        GossipError::PeerNotFound(_) => "PeerNotFound",
        GossipError::QuorumNotReached => "QuorumNotReached",
        GossipError::SerializationError(_) => "SerializationError",
        GossipError::CryptoError(_) => "CryptoError",
        GossipError::InvalidInput(_) => "InvalidInput",
    };
    let detail = e.to_string();
    let json = format!(r#"{{"error":"{variant}","detail":{detail_json}}}"#,
        variant = variant,
        detail_json = serde_json::to_string(&detail).unwrap_or_else(|_| "\"unknown\"".to_string()),
    );
    let bytes = json.into_bytes();
    let len = bytes.len();
    let ptr = bytes.as_ptr() as i32;
    std::mem::forget(bytes);
    (ptr, len as i32)
}

/// Write `[ok, ptr, len]` into the 12-byte out-slot at `out`.
unsafe fn write_out(out: i32, ok: i32, ptr: i32, len: i32) {
    let slot = out as *mut i32;
    slot.write(ok);
    slot.add(1).write(ptr);
    slot.add(2).write(len);
}

/// Write a success result with a byte buffer into the out-slot.
/// The buffer is leaked; the host must call `wasi_free(ptr, len)`.
unsafe fn write_ok_bytes(out: i32, data: Vec<u8>) {
    let len = data.len() as i32;
    let ptr = data.as_ptr() as i32;
    std::mem::forget(data);
    write_out(out, 1, ptr, len);
}

/// Write a success result with a fixed-size byte array into the out-slot.
unsafe fn write_ok_fixed<const N: usize>(out: i32, data: [u8; N]) {
    let boxed: Box<[u8; N]> = Box::new(data);
    let ptr = Box::into_raw(boxed) as i32;
    write_out(out, 1, ptr, N as i32);
}

/// Write a success result with no data (unit) into the out-slot.
unsafe fn write_ok_unit(out: i32) {
    write_out(out, 1, 0, 0);
}

/// Write an error result into the out-slot.
unsafe fn write_err(out: i32, e: &GossipError) {
    let (ptr, len) = error_to_leaked_json(e);
    write_out(out, 0, ptr, len);
}

/// Read a byte slice from WASM linear memory.
unsafe fn read_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    std::slice::from_raw_parts(ptr as *const u8, len as usize)
}

/// Read a UTF-8 string from WASM linear memory.
/// Returns an empty string on invalid UTF-8 (should not happen in practice).
unsafe fn read_str<'a>(ptr: i32, len: i32) -> &'a str {
    let bytes = read_bytes(ptr, len);
    std::str::from_utf8(bytes).unwrap_or("")
}

// ── Gossip API exports ────────────────────────────────────────────────────────

/// Initialize the gossip component with a JSON configuration string.
///
/// Out-slot: `Result<(), GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_init_wasi(cfg_ptr: i32, cfg_len: i32, out: i32) {
    let cfg = read_str(cfg_ptr, cfg_len);
    match api::gossip_init(cfg) {
        Ok(()) => write_ok_unit(out),
        Err(e) => write_err(out, &e),
    }
}

/// Publish a message to the gossip mesh.
///
/// Out-slot: `Result<[u8; 32], GossipError>` — 32-byte message ID on success.
#[no_mangle]
pub unsafe extern "C" fn gossip_publish_wasi(
    pt: i32,
    payload_ptr: i32,
    payload_len: i32,
    out: i32,
) {
    let payload = read_bytes(payload_ptr, payload_len);
    match api::gossip_publish(pt as u8, payload) {
        Ok(id) => write_ok_fixed::<32>(out, id),
        Err(e) => write_err(out, &e),
    }
}

/// Initiate a connection to a peer. Returns the probe bytes to send.
///
/// Out-slot: `Result<Vec<u8>, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_connect_peer_wasi(addr_ptr: i32, addr_len: i32, out: i32) {
    let addr = read_str(addr_ptr, addr_len);
    match api::gossip_connect_peer(addr) {
        Ok(bytes) => write_ok_bytes(out, bytes),
        Err(e) => write_err(out, &e),
    }
}

/// Disconnect from a peer.
///
/// Out-slot: `Result<(), GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_disconnect_peer_wasi(addr_ptr: i32, addr_len: i32, out: i32) {
    let addr = read_str(addr_ptr, addr_len);
    match api::gossip_disconnect_peer(addr) {
        Ok(()) => write_ok_unit(out),
        Err(e) => write_err(out, &e),
    }
}

/// Get the list of connected peers as a JSON string.
///
/// Out-slot: `Result<String, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_get_peers_wasi(out: i32) {
    match api::gossip_get_peers() {
        Ok(s) => write_ok_bytes(out, s.into_bytes()),
        Err(e) => write_err(out, &e),
    }
}

/// Get this node's identity as a JSON string.
///
/// Out-slot: `Result<String, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_get_node_identity_wasi(out: i32) {
    match api::gossip_get_node_identity() {
        Ok(s) => write_ok_bytes(out, s.into_bytes()),
        Err(e) => write_err(out, &e),
    }
}

/// Verify a gossip envelope.
///
/// Out-slot: `Result<bool, GossipError>` — `val_ptr == 1` means valid.
#[no_mangle]
pub unsafe extern "C" fn gossip_verify_envelope_wasi(bytes_ptr: i32, bytes_len: i32, out: i32) {
    let bytes = read_bytes(bytes_ptr, bytes_len);
    match api::gossip_verify_envelope(bytes) {
        Ok(valid) => write_out(out, 1, valid as i32, 0),
        Err(e) => write_err(out, &e),
    }
}

/// Encode a gossip envelope.
///
/// Out-slot: `Result<Vec<u8>, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_encode_envelope_wasi(
    pt: i32,
    payload_ptr: i32,
    payload_len: i32,
    out: i32,
) {
    let payload = read_bytes(payload_ptr, payload_len);
    match api::gossip_encode_envelope(pt as u8, payload) {
        Ok(bytes) => write_ok_bytes(out, bytes),
        Err(e) => write_err(out, &e),
    }
}

/// Decode a gossip envelope to a JSON string.
///
/// Out-slot: `Result<String, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_decode_envelope_wasi(bytes_ptr: i32, bytes_len: i32, out: i32) {
    let bytes = read_bytes(bytes_ptr, bytes_len);
    match api::gossip_decode_envelope(bytes) {
        Ok(s) => write_ok_bytes(out, s.into_bytes()),
        Err(e) => write_err(out, &e),
    }
}

/// Get gossip engine statistics as a JSON string.
///
/// Out-slot: `Result<String, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_get_stats_wasi(out: i32) {
    match api::gossip_get_stats() {
        Ok(s) => write_ok_bytes(out, s.into_bytes()),
        Err(e) => write_err(out, &e),
    }
}

/// Process incoming handshake bytes from a peer.
///
/// Returns the next handshake message bytes, or empty if the handshake is complete.
///
/// Out-slot: `Result<Option<Vec<u8>>, GossipError>`
/// - On `Ok(Some(bytes))`: `[1, ptr, len]`
/// - On `Ok(None)`:        `[1, 0, 0]`
/// - On `Err(e)`:          `[0, err_ptr, err_len]`
#[no_mangle]
pub unsafe extern "C" fn gossip_process_handshake_bytes_wasi(
    addr_ptr: i32,
    addr_len: i32,
    bytes_ptr: i32,
    bytes_len: i32,
    out: i32,
) {
    let addr = read_str(addr_ptr, addr_len);
    let bytes = read_bytes(bytes_ptr, bytes_len);
    match api::gossip_process_handshake_bytes(addr, bytes) {
        Ok(Some(response)) => write_ok_bytes(out, response),
        Ok(None) => write_out(out, 1, 0, 0),
        Err(e) => write_err(out, &e),
    }
}

/// Build a handshake ACK message from probe bytes.
///
/// Out-slot: `Result<Vec<u8>, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_build_handshake_ack_wasi(
    addr_ptr: i32,
    addr_len: i32,
    probe_ptr: i32,
    probe_len: i32,
    out: i32,
) {
    let addr = read_str(addr_ptr, addr_len);
    let probe = read_bytes(probe_ptr, probe_len);
    match api::gossip_build_handshake_ack(addr, probe) {
        Ok(bytes) => write_ok_bytes(out, bytes),
        Err(e) => write_err(out, &e),
    }
}

/// Build a handshake finish ACK message.
///
/// Out-slot: `Result<Vec<u8>, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_build_finish_ack_wasi(
    addr_ptr: i32,
    addr_len: i32,
    finish_ptr: i32,
    finish_len: i32,
    out: i32,
) {
    let addr = read_str(addr_ptr, addr_len);
    let finish = read_bytes(finish_ptr, finish_len);
    match api::gossip_build_finish_ack(addr, finish) {
        Ok(bytes) => write_ok_bytes(out, bytes),
        Err(e) => write_err(out, &e),
    }
}

/// Get the current time in milliseconds since Unix epoch.
///
/// Returns the value directly (not via out-slot).
#[no_mangle]
pub unsafe extern "C" fn gossip_now_ms_wasi() -> i64 {
    api::gossip_now_ms() as i64
}

/// Get the crate version string.
///
/// Out-slot: `Result<String, GossipError>` — always succeeds.
#[no_mangle]
pub unsafe extern "C" fn gossip_get_version_wasi(out: i32) {
    let version = api::gossip_get_version();
    write_ok_bytes(out, version.into_bytes());
}

/// Get the session info for a peer as a JSON string.
///
/// Out-slot: `Result<String, GossipError>`
#[no_mangle]
pub unsafe extern "C" fn gossip_get_session_wasi(addr_ptr: i32, addr_len: i32, out: i32) {
    let addr = read_str(addr_ptr, addr_len);
    match api::gossip_get_session(addr) {
        Ok(s) => write_ok_bytes(out, s.into_bytes()),
        Err(e) => write_err(out, &e),
    }
}
