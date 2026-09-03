//! [`GossipNode`] — a single gossip node backed by a wasmtime WASM instance.
//!
//! Each node has its own isolated WASM linear memory and global state, which
//! mirrors the real deployment model where each process runs one WASM instance.
//!
//! ## wasmtime 25 WASI Preview 1 API
//!
//! For core WASM modules (not components) using WASI Preview 1:
//! - Store data type: `wasmtime_wasi::preview1::WasiP1Ctx`
//! - Build context: `WasiCtxBuilder::new().inherit_stdio().build_p1()`
//! - Add WASI imports: `wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |t| t)`

use anyhow::{anyhow, bail, Result};
use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};
use wasmtime_wasi::preview1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;


// ── GossipNode ────────────────────────────────────────────────────────────────

/// A single gossip node backed by a wasmtime WASM instance.
pub struct GossipNode {
    /// Human-readable address used as the peer identifier (e.g. `"node-a"`).
    pub addr: String,

    store: Store<WasiP1Ctx>,
    _instance: Instance,
    memory: Memory,

    // Cached typed function handles.
    fn_alloc: TypedFunc<i32, i32>,
    fn_free: TypedFunc<(i32, i32), ()>,
    fn_gossip_init: TypedFunc<(i32, i32, i32), ()>,
    fn_gossip_publish: TypedFunc<(i32, i32, i32, i32), ()>,
    fn_gossip_connect_peer: TypedFunc<(i32, i32, i32), ()>,
    fn_gossip_disconnect_peer: TypedFunc<(i32, i32, i32), ()>,
    fn_gossip_get_peers: TypedFunc<i32, ()>,
    fn_gossip_get_node_identity: TypedFunc<i32, ()>,
    fn_gossip_verify_envelope: TypedFunc<(i32, i32, i32), ()>,
    fn_gossip_encode_envelope: TypedFunc<(i32, i32, i32, i32), ()>,
    // These four are cached alongside the others to mirror the full WASI
    // export surface, even though the current 3-node test scenario doesn't
    // exercise every one of them.
    #[allow(dead_code)]
    fn_gossip_decode_envelope: TypedFunc<(i32, i32, i32), ()>,
    fn_gossip_get_stats: TypedFunc<i32, ()>,
    fn_gossip_process_handshake_bytes: TypedFunc<(i32, i32, i32, i32, i32), ()>,
    #[allow(dead_code)]
    fn_gossip_build_handshake_ack: TypedFunc<(i32, i32, i32, i32, i32), ()>,
    #[allow(dead_code)]
    fn_gossip_build_finish_ack: TypedFunc<(i32, i32, i32, i32, i32), ()>,
    #[allow(dead_code)]
    fn_gossip_now_ms: TypedFunc<(), i64>,
    fn_gossip_get_version: TypedFunc<i32, ()>,
    #[allow(dead_code)]
    fn_gossip_get_session: TypedFunc<(i32, i32, i32), ()>,
}

impl GossipNode {
    /// Instantiate a new gossip node from raw WASM bytes.
    pub fn new(addr: impl Into<String>, wasm_bytes: &[u8], engine: &Engine) -> Result<Self> {
        let addr = addr.into();

        let wasi_ctx = WasiCtxBuilder::new()
            .inherit_stdio()
            .build_p1();

        let mut store = Store::new(engine, wasi_ctx);

        let mut linker: Linker<WasiP1Ctx> = Linker::new(engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |t| t)?;

        let module = Module::new(engine, wasm_bytes)?;
        let instance = linker.instantiate(&mut store, &module)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("WASM module does not export 'memory'"))?;

        macro_rules! get_fn {
            ($name:expr, $ty:ty) => {
                instance.get_typed_func::<$ty, _>(&mut store, $name)
                    .map_err(|e| anyhow!("missing export '{}': {}", $name, e))?
            };
        }

        let fn_alloc = get_fn!("wasi_alloc", i32);
        let fn_free = get_fn!("wasi_free", (i32, i32));
        let fn_gossip_init = get_fn!("gossip_init_wasi", (i32, i32, i32));
        let fn_gossip_publish = get_fn!("gossip_publish_wasi", (i32, i32, i32, i32));
        let fn_gossip_connect_peer = get_fn!("gossip_connect_peer_wasi", (i32, i32, i32));
        let fn_gossip_disconnect_peer = get_fn!("gossip_disconnect_peer_wasi", (i32, i32, i32));
        let fn_gossip_get_peers = get_fn!("gossip_get_peers_wasi", i32);
        let fn_gossip_get_node_identity = get_fn!("gossip_get_node_identity_wasi", i32);
        let fn_gossip_verify_envelope = get_fn!("gossip_verify_envelope_wasi", (i32, i32, i32));
        let fn_gossip_encode_envelope =
            get_fn!("gossip_encode_envelope_wasi", (i32, i32, i32, i32));
        let fn_gossip_decode_envelope = get_fn!("gossip_decode_envelope_wasi", (i32, i32, i32));
        let fn_gossip_get_stats = get_fn!("gossip_get_stats_wasi", i32);
        let fn_gossip_process_handshake_bytes =
            get_fn!("gossip_process_handshake_bytes_wasi", (i32, i32, i32, i32, i32));
        let fn_gossip_build_handshake_ack =
            get_fn!("gossip_build_handshake_ack_wasi", (i32, i32, i32, i32, i32));
        let fn_gossip_build_finish_ack =
            get_fn!("gossip_build_finish_ack_wasi", (i32, i32, i32, i32, i32));
        let fn_gossip_now_ms = get_fn!("gossip_now_ms_wasi", ());
        let fn_gossip_get_version = get_fn!("gossip_get_version_wasi", i32);
        let fn_gossip_get_session = get_fn!("gossip_get_session_wasi", (i32, i32, i32));

        Ok(Self {
            addr,
            store,
            _instance: instance,
            memory,
            fn_alloc,
            fn_free,
            fn_gossip_init,
            fn_gossip_publish,
            fn_gossip_connect_peer,
            fn_gossip_disconnect_peer,
            fn_gossip_get_peers,
            fn_gossip_get_node_identity,
            fn_gossip_verify_envelope,
            fn_gossip_encode_envelope,
            fn_gossip_decode_envelope,
            fn_gossip_get_stats,
            fn_gossip_process_handshake_bytes,
            fn_gossip_build_handshake_ack,
            fn_gossip_build_finish_ack,
            fn_gossip_now_ms,
            fn_gossip_get_version,
            fn_gossip_get_session,
        })
    }

    // ── Low-level memory helpers ──────────────────────────────────────────────

    /// Allocate `size` bytes in WASM memory. Returns the pointer.
    fn wasm_alloc(&mut self, size: i32) -> Result<i32> {
        Ok(self.fn_alloc.call(&mut self.store, size)?)
    }

    /// Free `len` bytes at `ptr` in WASM memory.
    fn wasm_free(&mut self, ptr: i32, len: i32) -> Result<()> {
        if ptr != 0 && len > 0 {
            self.fn_free.call(&mut self.store, (ptr, len))?;
        }
        Ok(())
    }

    /// Write `data` into WASM memory. Returns the pointer (0 if empty).
    fn write_bytes(&mut self, data: &[u8]) -> Result<i32> {
        if data.is_empty() {
            return Ok(0);
        }
        let ptr = self.wasm_alloc(data.len() as i32)?;
        self.memory.write(&mut self.store, ptr as usize, data)
            .map_err(|e| anyhow!("write_bytes: {e}"))?;
        Ok(ptr)
    }

    /// Write a string into WASM memory. Returns the pointer (0 if empty).
    fn write_str(&mut self, s: &str) -> Result<i32> {
        self.write_bytes(s.as_bytes())
    }

    /// Allocate a 12-byte out-slot in WASM memory.
    fn alloc_out_slot(&mut self) -> Result<i32> {
        self.wasm_alloc(12)
    }

    /// Read a little-endian i32 from WASM memory at `offset`.
    fn read_i32(&self, offset: usize) -> i32 {
        let mut buf = [0u8; 4];
        self.memory.read(&self.store, offset, &mut buf)
            .expect("read_i32: out-of-bounds");
        i32::from_le_bytes(buf)
    }

    /// Read `len` bytes from WASM memory at `ptr`.
    fn read_mem(&self, ptr: usize, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.memory.read(&self.store, ptr, &mut buf)
            .expect("read_mem: out-of-bounds");
        buf
    }

    /// Read the `(ok, val_ptr, val_len)` triple from a 12-byte out-slot.
    fn read_out_slot(&self, out_ptr: i32) -> (i32, i32, i32) {
        let base = out_ptr as usize;
        let ok = self.read_i32(base);
        let val_ptr = self.read_i32(base + 4);
        let val_len = self.read_i32(base + 8);
        (ok, val_ptr, val_len)
    }

    // ── Result-reading helpers ────────────────────────────────────────────────
    //
    // These helpers read the out-slot, free WASM memory, and return the result.
    // They are split into two phases (read then free) to avoid simultaneous
    // &self / &mut self conflicts.

    /// Read a byte-vector result from an out-slot.
    fn result_bytes(&mut self, out_ptr: i32) -> Result<Vec<u8>> {
        let (ok, val_ptr, val_len) = self.read_out_slot(out_ptr);
        self.wasm_free(out_ptr, 12)?;

        if ok == 1 {
            if val_ptr == 0 || val_len == 0 {
                return Ok(Vec::new());
            }
            let data = self.read_mem(val_ptr as usize, val_len as usize);
            self.wasm_free(val_ptr, val_len)?;
            Ok(data)
        } else {
            let err = self.read_error(val_ptr, val_len)?;
            bail!("WASM error: {}", err)
        }
    }

    /// Read a string result from an out-slot.
    fn result_string(&mut self, out_ptr: i32) -> Result<String> {
        let bytes = self.result_bytes(out_ptr)?;
        String::from_utf8(bytes).map_err(|e| anyhow!("WASM returned invalid UTF-8: {e}"))
    }

    /// Read a bool result from an out-slot.
    fn result_bool(&mut self, out_ptr: i32) -> Result<bool> {
        let (ok, val_ptr, val_len) = self.read_out_slot(out_ptr);
        self.wasm_free(out_ptr, 12)?;

        if ok == 1 {
            Ok(val_ptr != 0)
        } else {
            let err = self.read_error(val_ptr, val_len)?;
            bail!("WASM error: {}", err)
        }
    }

    /// Read an optional byte-vector result from an out-slot.
    fn result_option_bytes(&mut self, out_ptr: i32) -> Result<Option<Vec<u8>>> {
        let (ok, val_ptr, val_len) = self.read_out_slot(out_ptr);
        self.wasm_free(out_ptr, 12)?;

        if ok == 1 {
            if val_ptr == 0 && val_len == 0 {
                return Ok(None);
            }
            let data = self.read_mem(val_ptr as usize, val_len as usize);
            self.wasm_free(val_ptr, val_len)?;
            Ok(Some(data))
        } else {
            let err = self.read_error(val_ptr, val_len)?;
            bail!("WASM error: {}", err)
        }
    }

    /// Read a fixed 32-byte result from an out-slot.
    fn result_fixed32(&mut self, out_ptr: i32) -> Result<[u8; 32]> {
        let (ok, val_ptr, val_len) = self.read_out_slot(out_ptr);
        self.wasm_free(out_ptr, 12)?;

        if ok == 1 {
            if val_ptr == 0 || val_len != 32 {
                bail!("WASM error: expected 32-byte result, got ptr={val_ptr} len={val_len}");
            }
            let data = self.read_mem(val_ptr as usize, 32);
            self.wasm_free(val_ptr, val_len)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data);
            Ok(arr)
        } else {
            let err = self.read_error(val_ptr, val_len)?;
            bail!("WASM error: {}", err)
        }
    }

    /// Read an error JSON string from WASM memory and free it.
    fn read_error(&mut self, err_ptr: i32, err_len: i32) -> Result<String> {
        if err_ptr == 0 || err_len == 0 {
            return Ok("(no error detail)".to_string());
        }
        let bytes = self.read_mem(err_ptr as usize, err_len as usize);
        self.wasm_free(err_ptr, err_len)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Initialize the gossip component with a JSON configuration string.
    pub fn init(&mut self, config_json: &str) -> Result<()> {
        let cfg_ptr = self.write_str(config_json)?;
        let cfg_len = config_json.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_init.call(&mut self.store, (cfg_ptr, cfg_len, out))?;

        self.wasm_free(cfg_ptr, cfg_len)?;
        let _ = self.result_bytes(out)?;
        Ok(())
    }

    /// Initiate a connection to `peer_addr`. Returns the probe bytes to send.
    pub fn connect_peer(&mut self, peer_addr: &str) -> Result<Vec<u8>> {
        let addr_ptr = self.write_str(peer_addr)?;
        let addr_len = peer_addr.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_connect_peer.call(&mut self.store, (addr_ptr, addr_len, out))?;

        self.wasm_free(addr_ptr, addr_len)?;
        self.result_bytes(out)
    }

    /// Process incoming handshake bytes from `peer_addr`.
    ///
    /// Returns the next message bytes, or `None` if the handshake is complete.
    pub fn process_handshake_bytes(
        &mut self,
        peer_addr: &str,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let addr_ptr = self.write_str(peer_addr)?;
        let addr_len = peer_addr.len() as i32;
        let bytes_ptr = self.write_bytes(bytes)?;
        let bytes_len = bytes.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_process_handshake_bytes.call(
            &mut self.store,
            (addr_ptr, addr_len, bytes_ptr, bytes_len, out),
        )?;

        self.wasm_free(addr_ptr, addr_len)?;
        self.wasm_free(bytes_ptr, bytes_len)?;
        self.result_option_bytes(out)
    }

    /// Encode a gossip envelope for `payload_type` and `payload`.
    pub fn encode_envelope(&mut self, payload_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let payload_ptr = self.write_bytes(payload)?;
        let payload_len = payload.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_encode_envelope.call(
            &mut self.store,
            (payload_type as i32, payload_ptr, payload_len, out),
        )?;

        self.wasm_free(payload_ptr, payload_len)?;
        self.result_bytes(out)
    }

    /// Verify a gossip envelope. Returns `true` if valid.
    pub fn verify_envelope(&mut self, bytes: &[u8]) -> Result<bool> {
        let bytes_ptr = self.write_bytes(bytes)?;
        let bytes_len = bytes.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_verify_envelope.call(&mut self.store, (bytes_ptr, bytes_len, out))?;

        self.wasm_free(bytes_ptr, bytes_len)?;
        self.result_bool(out)
    }

    /// Get this node's identity as a parsed JSON value.
    pub fn get_node_identity(&mut self) -> Result<serde_json::Value> {
        let out = self.alloc_out_slot()?;
        self.fn_gossip_get_node_identity.call(&mut self.store, out)?;
        let s = self.result_string(out)?;
        serde_json::from_str(&s).map_err(|e| anyhow!("identity JSON parse error: {e}\nraw: {s}"))
    }

    /// Get the list of connected peers as a parsed JSON array.
    pub fn get_peers(&mut self) -> Result<Vec<serde_json::Value>> {
        let out = self.alloc_out_slot()?;
        self.fn_gossip_get_peers.call(&mut self.store, out)?;
        let s = self.result_string(out)?;
        serde_json::from_str(&s).map_err(|e| anyhow!("peers JSON parse error: {e}\nraw: {s}"))
    }

    /// Get gossip engine statistics as a parsed JSON value.
    pub fn get_stats(&mut self) -> Result<serde_json::Value> {
        let out = self.alloc_out_slot()?;
        self.fn_gossip_get_stats.call(&mut self.store, out)?;
        let s = self.result_string(out)?;
        serde_json::from_str(&s).map_err(|e| anyhow!("stats JSON parse error: {e}\nraw: {s}"))
    }

    /// Publish a message. Returns the 32-byte message ID.
    pub fn publish(&mut self, payload_type: u8, payload: &[u8]) -> Result<[u8; 32]> {
        let payload_ptr = self.write_bytes(payload)?;
        let payload_len = payload.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_publish.call(
            &mut self.store,
            (payload_type as i32, payload_ptr, payload_len, out),
        )?;

        self.wasm_free(payload_ptr, payload_len)?;
        self.result_fixed32(out)
    }

    /// Get the crate version string.
    pub fn get_version(&mut self) -> Result<String> {
        let out = self.alloc_out_slot()?;
        self.fn_gossip_get_version.call(&mut self.store, out)?;
        self.result_string(out)
    }

    /// Get the current time in milliseconds since Unix epoch (from WASM).
    #[allow(dead_code)]
    pub fn now_ms(&mut self) -> Result<i64> {
        Ok(self.fn_gossip_now_ms.call(&mut self.store, ())?)
    }

    /// Disconnect from `peer_addr`.
    pub fn disconnect_peer(&mut self, peer_addr: &str) -> Result<()> {
        let addr_ptr = self.write_str(peer_addr)?;
        let addr_len = peer_addr.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_disconnect_peer.call(&mut self.store, (addr_ptr, addr_len, out))?;

        self.wasm_free(addr_ptr, addr_len)?;
        let _ = self.result_bytes(out)?;
        Ok(())
    }

    /// Get the session info for `peer_addr` as a parsed JSON value.
    #[allow(dead_code)]
    pub fn get_session(&mut self, peer_addr: &str) -> Result<serde_json::Value> {
        let addr_ptr = self.write_str(peer_addr)?;
        let addr_len = peer_addr.len() as i32;
        let out = self.alloc_out_slot()?;

        self.fn_gossip_get_session.call(&mut self.store, (addr_ptr, addr_len, out))?;

        self.wasm_free(addr_ptr, addr_len)?;
        let s = self.result_string(out)?;
        serde_json::from_str(&s).map_err(|e| anyhow!("session JSON parse error: {e}\nraw: {s}"))
    }
}

// The `abi` module provides a standalone, independently-usable reference
// implementation of the same WASI ABI helpers used inline above; it is not
// re-exported from `node.rs` itself.
