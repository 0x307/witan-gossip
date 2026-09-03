//! Low-level WASM ABI helpers.
//!
//! Provides safe wrappers around the raw C-ABI exported by the
//! `witan-gossip` WASI module.
//!
//! ## Out-slot convention
//!
//! Every gossip function writes its result into a 12-byte "out-slot" in WASM
//! linear memory:
//!
//! ```text
//! [ok: i32, val_ptr: i32, val_len: i32]
//! ```
//!
//! - `ok == 1`: success; `val_ptr`/`val_len` describe the returned data.
//! - `ok == 0`: error; `val_ptr`/`val_len` point to a JSON error string.
//!
//! The host allocates the 12-byte slot with `wasi_alloc(12)` before each call
//! and reads it back afterwards.  Any non-null `val_ptr` returned by the WASM
//! module must be freed with `wasi_free(val_ptr, val_len)`.
//!
//! These helpers mirror the full WASI ABI surface exposed by the
//! `witan-gossip` component. `node.rs` currently inlines its own copies to
//! avoid `TypedFunc` borrow conflicts, so this module is kept as a
//! standalone, independently-usable reference implementation and is
//! intentionally allowed to contain currently-unused items.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Result};
use wasmtime::{Memory, Store, TypedFunc};
use wasmtime_wasi::preview1::WasiP1Ctx;

// ── Re-exported typed function signatures ─────────────────────────────────────

pub type FnAlloc = TypedFunc<i32, i32>;
pub type FnFree = TypedFunc<(i32, i32), ()>;

// ── Memory helpers ────────────────────────────────────────────────────────────

/// Write `data` into WASM linear memory at `offset`.
pub fn mem_write(store: &mut Store<WasiP1Ctx>, mem: &Memory, offset: usize, data: &[u8]) {
    mem.write(store, offset, data)
        .expect("mem_write: out-of-bounds write into WASM memory");
}

/// Read `len` bytes from WASM linear memory starting at `offset`.
pub fn mem_read(store: &Store<WasiP1Ctx>, mem: &Memory, offset: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    mem.read(store, offset, &mut buf)
        .expect("mem_read: out-of-bounds read from WASM memory");
    buf
}

/// Read a little-endian `i32` from WASM linear memory at `offset`.
pub fn mem_read_i32(store: &Store<WasiP1Ctx>, mem: &Memory, offset: usize) -> i32 {
    let bytes = mem_read(store, mem, offset, 4);
    i32::from_le_bytes(bytes.try_into().unwrap())
}

// ── Out-slot helpers ──────────────────────────────────────────────────────────

/// Allocate a 12-byte out-slot in WASM memory. Returns the pointer.
pub fn alloc_out_slot(store: &mut Store<WasiP1Ctx>, fn_alloc: &FnAlloc) -> Result<i32> {
    let ptr = fn_alloc.call(&mut *store, 12)?;
    Ok(ptr)
}

/// Read the three `i32` fields from a 12-byte out-slot.
///
/// Returns `(ok, val_ptr, val_len)`.
pub fn read_out_slot(store: &Store<WasiP1Ctx>, mem: &Memory, out_ptr: i32) -> (i32, i32, i32) {
    let base = out_ptr as usize;
    let ok = mem_read_i32(store, mem, base);
    let val_ptr = mem_read_i32(store, mem, base + 4);
    let val_len = mem_read_i32(store, mem, base + 8);
    (ok, val_ptr, val_len)
}

/// Read the result from an out-slot as a byte vector.
///
/// - On success (`ok == 1`): reads `val_len` bytes from `val_ptr` and frees them.
/// - On error  (`ok == 0`): reads the JSON error string, frees it, returns `Err`.
///
/// Also frees the 12-byte out-slot itself.
pub fn read_result_bytes(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_free: &FnFree,
    out_ptr: i32,
) -> Result<Vec<u8>> {
    let (ok, val_ptr, val_len) = read_out_slot(store, mem, out_ptr);

    // Free the out-slot itself
    fn_free.call(&mut *store, (out_ptr, 12))?;

    if ok == 1 {
        if val_ptr == 0 || val_len == 0 {
            return Ok(Vec::new());
        }
        let data = mem_read(store, mem, val_ptr as usize, val_len as usize);
        fn_free.call(&mut *store, (val_ptr, val_len))?;
        Ok(data)
    } else {
        let err_bytes = if val_ptr != 0 && val_len > 0 {
            let b = mem_read(store, mem, val_ptr as usize, val_len as usize);
            fn_free.call(&mut *store, (val_ptr, val_len))?;
            b
        } else {
            b"{}".to_vec()
        };
        let err_str = String::from_utf8_lossy(&err_bytes).into_owned();
        bail!("WASM error: {}", err_str)
    }
}

/// Read the result from an out-slot as a UTF-8 string.
pub fn read_result_string(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_free: &FnFree,
    out_ptr: i32,
) -> Result<String> {
    let bytes = read_result_bytes(store, mem, fn_free, out_ptr)?;
    String::from_utf8(bytes).map_err(|e| anyhow!("WASM returned invalid UTF-8: {e}"))
}

/// Read the result from an out-slot as a boolean.
///
/// `val_ptr == 1` means `true`; `val_ptr == 0` means `false`.
pub fn read_result_bool(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_free: &FnFree,
    out_ptr: i32,
) -> Result<bool> {
    let (ok, val_ptr, _val_len) = read_out_slot(store, mem, out_ptr);
    fn_free.call(&mut *store, (out_ptr, 12))?;

    if ok == 1 {
        Ok(val_ptr != 0)
    } else {
        bail!("WASM error: bool result returned ok=0 (val_ptr={})", val_ptr)
    }
}

/// Read the result from an out-slot as an optional byte vector.
///
/// `val_ptr == 0 && val_len == 0` means `None`.
pub fn read_result_option_bytes(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_free: &FnFree,
    out_ptr: i32,
) -> Result<Option<Vec<u8>>> {
    let (ok, val_ptr, val_len) = read_out_slot(store, mem, out_ptr);
    fn_free.call(&mut *store, (out_ptr, 12))?;

    if ok == 1 {
        if val_ptr == 0 && val_len == 0 {
            return Ok(None);
        }
        let data = mem_read(store, mem, val_ptr as usize, val_len as usize);
        fn_free.call(&mut *store, (val_ptr, val_len))?;
        Ok(Some(data))
    } else {
        let err_bytes = if val_ptr != 0 && val_len > 0 {
            let b = mem_read(store, mem, val_ptr as usize, val_len as usize);
            fn_free.call(&mut *store, (val_ptr, val_len))?;
            b
        } else {
            b"{}".to_vec()
        };
        let err_str = String::from_utf8_lossy(&err_bytes).into_owned();
        bail!("WASM error: {}", err_str)
    }
}

/// Read the result from an out-slot as a fixed-size 32-byte array.
pub fn read_result_fixed32(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_free: &FnFree,
    out_ptr: i32,
) -> Result<[u8; 32]> {
    let (ok, val_ptr, val_len) = read_out_slot(store, mem, out_ptr);
    fn_free.call(&mut *store, (out_ptr, 12))?;

    if ok == 1 {
        if val_ptr == 0 || val_len != 32 {
            bail!("WASM error: expected 32-byte result, got ptr={val_ptr} len={val_len}");
        }
        let data = mem_read(store, mem, val_ptr as usize, 32);
        fn_free.call(&mut *store, (val_ptr, val_len))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        Ok(arr)
    } else {
        let err_bytes = if val_ptr != 0 && val_len > 0 {
            let b = mem_read(store, mem, val_ptr as usize, val_len as usize);
            fn_free.call(&mut *store, (val_ptr, val_len))?;
            b
        } else {
            b"{}".to_vec()
        };
        let err_str = String::from_utf8_lossy(&err_bytes).into_owned();
        bail!("WASM error: {}", err_str)
    }
}

/// Write `data` into WASM memory using `wasi_alloc`. Returns the pointer.
///
/// The caller is responsible for freeing the returned pointer with `wasi_free`.
pub fn write_bytes_to_wasm(
    store: &mut Store<WasiP1Ctx>,
    mem: &Memory,
    fn_alloc: &FnAlloc,
    data: &[u8],
) -> Result<i32> {
    if data.is_empty() {
        return Ok(0);
    }
    let ptr = fn_alloc.call(&mut *store, data.len() as i32)?;
    mem_write(store, mem, ptr as usize, data);
    Ok(ptr)
}
