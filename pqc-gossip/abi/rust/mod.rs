// pqc-gossip/abi/rust/mod.rs
// Rust host bindings for the witan-gossip WASM component.
//
// Uses `wasmtime` to load and call the WASM binary compiled from
// pqc-gossip/src with target wasm32-unknown-unknown.
//
// ABI convention (wasm-bindgen style):
//   - Strings are passed as (ptr: i32, len: i32) pairs in WASM linear memory.
//   - Byte slices are passed as (ptr: i32, len: i32) pairs.
//   - Return values use an out-pointer pattern written to a 12-byte slot:
//       [0..4]  ok_flag: i32  (1 = Ok, 0 = Err)
//       [4..8]  val_ptr: i32  (pointer to value or error string)
//       [8..12] val_len: i32  (byte length of value or error string)
//   - Memory is allocated via __wbindgen_malloc and freed via __wbindgen_free.

use std::path::Path;
use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by the Rust host bindings.
#[derive(Debug)]
pub enum GossipBindingError {
    /// wasmtime engine / instantiation error.
    Wasm(wasmtime::Error),
    /// The WASM component returned a GossipError.
    Component(String),
    /// Memory access or pointer arithmetic error.
    Memory(String),
    /// UTF-8 decoding error.
    Utf8(std::string::FromUtf8Error),
    /// I/O error (file loading).
    Io(std::io::Error),
}

impl std::fmt::Display for GossipBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasm(e) => write!(f, "wasmtime error: {e}"),
            Self::Component(s) => write!(f, "gossip component error: {s}"),
            Self::Memory(s) => write!(f, "memory error: {s}"),
            Self::Utf8(e) => write!(f, "utf-8 error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for GossipBindingError {}

impl From<wasmtime::Error> for GossipBindingError {
    fn from(e: wasmtime::Error) -> Self {
        Self::Wasm(e)
    }
}

impl From<std::string::FromUtf8Error> for GossipBindingError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<std::io::Error> for GossipBindingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GossipClient
// ─────────────────────────────────────────────────────────────────────────────

/// Host-side client for the witan-gossip WASM component.
///
/// Wraps a `wasmtime` store and instance. All methods correspond 1:1 to
/// exported WASM functions. The client is **not** `Send` or `Sync` because
/// `wasmtime::Store` is single-threaded; use an external mutex if you need
/// to share across threads.
pub struct GossipClient {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
}

impl GossipClient {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Load the WASM component from a file path.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use witan_gossip_abi::GossipClient;
    /// let client = GossipClient::from_file("target/wasm32-unknown-unknown/release/pqc_gossip.wasm").unwrap();
    /// ```
    pub fn from_file(wasm_path: impl AsRef<Path>) -> Result<Self, GossipBindingError> {
        let bytes = std::fs::read(wasm_path)?;
        Self::from_bytes(&bytes)
    }

    /// Load the WASM component from raw bytes.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use witan_gossip_abi::GossipClient;
    /// let wasm_bytes = include_bytes!("../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm");
    /// let client = GossipClient::from_bytes(wasm_bytes).unwrap();
    /// ```
    pub fn from_bytes(wasm_bytes: &[u8]) -> Result<Self, GossipBindingError> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes)?;
        let linker: Linker<()> = Linker::new(&engine);
        let mut store = Store::new(&engine, ());

        let instance = linker.instantiate(&mut store, &module)?;

        // Retrieve the exported linear memory.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| {
                GossipBindingError::Memory("WASM module has no 'memory' export".into())
            })?;

        Ok(Self { store, instance, memory })
    }

    // ── Memory helpers ────────────────────────────────────────────────────────

    /// Allocate `len` bytes in WASM linear memory using `__wbindgen_malloc`.
    fn malloc(&mut self, len: usize) -> Result<i32, GossipBindingError> {
        let malloc_fn: TypedFunc<(i32, i32), i32> = self
            .instance
            .get_typed_func(&mut self.store, "__wbindgen_malloc")?;
        let ptr = malloc_fn.call(&mut self.store, (len as i32, 1))?;
        Ok(ptr)
    }

    /// Free WASM memory at `ptr` of `len` bytes using `__wbindgen_free`.
    fn free(&mut self, ptr: i32, len: i32) -> Result<(), GossipBindingError> {
        let free_fn: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "__wbindgen_free")?;
        free_fn.call(&mut self.store, (ptr, len, 1))?;
        Ok(())
    }

    /// Write `data` into WASM linear memory at `ptr`.
    fn write_bytes(&mut self, ptr: i32, data: &[u8]) -> Result<(), GossipBindingError> {
        let mem_data = self.memory.data_mut(&mut self.store);
        let start = ptr as usize;
        let end = start + data.len();
        if end > mem_data.len() {
            return Err(GossipBindingError::Memory(format!(
                "write out of bounds: ptr={ptr} len={} mem_size={}",
                data.len(),
                mem_data.len()
            )));
        }
        mem_data[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Read `len` bytes from WASM linear memory at `ptr`.
    fn read_bytes(&self, ptr: i32, len: i32) -> Result<Vec<u8>, GossipBindingError> {
        let mem_data = self.memory.data(&self.store);
        let start = ptr as usize;
        let end = start + len as usize;
        if end > mem_data.len() {
            return Err(GossipBindingError::Memory(format!(
                "read out of bounds: ptr={ptr} len={len} mem_size={}",
                mem_data.len()
            )));
        }
        Ok(mem_data[start..end].to_vec())
    }

    /// Read a 12-byte result slot at `ret_ptr`:
    ///   [0..4]  ok_flag: i32
    ///   [4..8]  val_ptr: i32
    ///   [8..12] val_len: i32
    fn read_result_slot(&self, ret_ptr: i32) -> Result<(i32, i32, i32), GossipBindingError> {
        let mem_data = self.memory.data(&self.store);
        let base = ret_ptr as usize;
        if base + 12 > mem_data.len() {
            return Err(GossipBindingError::Memory(format!(
                "result slot out of bounds: ret_ptr={ret_ptr}"
            )));
        }
        let ok_flag = i32::from_le_bytes(mem_data[base..base + 4].try_into().unwrap());
        let val_ptr = i32::from_le_bytes(mem_data[base + 4..base + 8].try_into().unwrap());
        let val_len = i32::from_le_bytes(mem_data[base + 8..base + 12].try_into().unwrap());
        Ok((ok_flag, val_ptr, val_len))
    }

    /// Allocate a 12-byte return slot in WASM memory.
    fn alloc_ret_slot(&mut self) -> Result<i32, GossipBindingError> {
        self.malloc(12)
    }

    /// Write a string into WASM memory and return (ptr, len).
    fn write_str(&mut self, s: &str) -> Result<(i32, i32), GossipBindingError> {
        let bytes = s.as_bytes();
        let ptr = self.malloc(bytes.len().max(1))?;
        self.write_bytes(ptr, bytes)?;
        Ok((ptr, bytes.len() as i32))
    }

    /// Write a byte slice into WASM memory and return (ptr, len).
    fn write_slice(&mut self, data: &[u8]) -> Result<(i32, i32), GossipBindingError> {
        if data.is_empty() {
            let ptr = self.malloc(1)?;
            return Ok((ptr, 0));
        }
        let ptr = self.malloc(data.len())?;
        self.write_bytes(ptr, data)?;
        Ok((ptr, data.len() as i32))
    }

    /// Interpret a result slot as `Result<(), String>`.
    fn result_unit(&self, ret_ptr: i32) -> Result<(), GossipBindingError> {
        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        if ok_flag == 1 {
            Ok(())
        } else {
            let err_bytes = self.read_bytes(val_ptr, val_len)?;
            let msg = String::from_utf8(err_bytes)?;
            Err(GossipBindingError::Component(msg))
        }
    }

    /// Interpret a result slot as `Result<String, String>`.
    fn result_string(&self, ret_ptr: i32) -> Result<String, GossipBindingError> {
        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        let bytes = self.read_bytes(val_ptr, val_len)?;
        let s = String::from_utf8(bytes)?;
        if ok_flag == 1 {
            Ok(s)
        } else {
            Err(GossipBindingError::Component(s))
        }
    }

    /// Interpret a result slot as `Result<Vec<u8>, String>`.
    fn result_bytes(&self, ret_ptr: i32) -> Result<Vec<u8>, GossipBindingError> {
        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        if ok_flag == 1 {
            self.read_bytes(val_ptr, val_len)
        } else {
            let err_bytes = self.read_bytes(val_ptr, val_len)?;
            let msg = String::from_utf8(err_bytes)?;
            Err(GossipBindingError::Component(msg))
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Initialize the gossip engine with a JSON configuration string.
    ///
    /// Must be called exactly once before any other method.
    /// Pass `"{}"` to use all defaults.
    ///
    /// # Errors
    /// Returns `GossipBindingError::Component` if the config is invalid or
    /// the component has already been initialized.
    pub fn init(&mut self, config_json: &str) -> Result<(), GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (str_ptr, str_len) = self.write_str(config_json)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_init")?;
        f.call(&mut self.store, (ret_ptr, str_ptr, str_len))?;

        let result = self.result_unit(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(str_ptr, str_len.max(1))?;
        result
    }

    /// Publish a message to the gossip mesh.
    ///
    /// Returns the 32-byte message ID as a fixed-size array.
    ///
    /// # Parameters
    /// - `payload_type`: u8 discriminant (0=Transaction, 1=BlockProposal,
    ///   2=FinalityVote, 3=StateSync, 4=PeerDiscovery)
    /// - `payload`: raw message bytes (max 1MB by default)
    pub fn publish(
        &mut self,
        payload_type: u8,
        payload: &[u8],
    ) -> Result<[u8; 32], GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (buf_ptr, buf_len) = self.write_slice(payload)?;

        let f: TypedFunc<(i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_publish")?;
        f.call(&mut self.store, (ret_ptr, payload_type as i32, buf_ptr, buf_len))?;

        let bytes = self.result_bytes(ret_ptr)?;
        self.free(ret_ptr, 12)?;
        self.free(buf_ptr, buf_len.max(1))?;

        if bytes.len() != 32 {
            return Err(GossipBindingError::Memory(format!(
                "expected 32-byte message_id, got {} bytes",
                bytes.len()
            )));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(id)
    }

    /// Initiate a PQC handshake with a peer.
    ///
    /// Returns the probe bytes that the host must transmit to the peer.
    /// The host must then call [`process_handshake_bytes`] as responses arrive.
    pub fn connect_peer(&mut self, peer_addr: &str) -> Result<Vec<u8>, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (str_ptr, str_len) = self.write_str(peer_addr)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_connect_peer")?;
        f.call(&mut self.store, (ret_ptr, str_ptr, str_len))?;

        let result = self.result_bytes(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(str_ptr, str_len.max(1))?;
        result
    }

    /// Disconnect from a peer and remove their session.
    pub fn disconnect_peer(&mut self, peer_addr: &str) -> Result<(), GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (str_ptr, str_len) = self.write_str(peer_addr)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_disconnect_peer")?;
        f.call(&mut self.store, (ret_ptr, str_ptr, str_len))?;

        let result = self.result_unit(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(str_ptr, str_len.max(1))?;
        result
    }

    /// Get the list of currently connected peers as a JSON array string.
    ///
    /// Returns JSON: `[{"addr":"...","node_id":"...","session_id":"...","established_at_ms":...}]`
    pub fn get_peers(&mut self) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;

        let f: TypedFunc<i32, ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_get_peers")?;
        f.call(&mut self.store, ret_ptr)?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        result
    }

    /// Get the node's public identity as a JSON object string.
    ///
    /// Returns JSON:
    /// ```json
    /// {
    ///   "node_id": "hex...",
    ///   "kem_public_key_json": "{...}",
    ///   "sig_public_key_hex": "hex...",
    ///   "key_epoch": "ephemeral-runtime"
    /// }
    /// ```
    pub fn get_node_identity(&mut self) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;

        let f: TypedFunc<i32, ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_get_node_identity")?;
        f.call(&mut self.store, ret_ptr)?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        result
    }

    /// Verify a received GossipEnvelope (bincode-encoded bytes).
    ///
    /// Checks:
    /// 1. Bincode deserialization succeeds
    /// 2. `message_id == SHA-256(payload_type_byte || payload)`
    /// 3. ML-DSA-65 signature valid
    /// 4. Timestamp within ±30s of current time
    /// 5. TTL > 0
    ///
    /// Returns `true` if all checks pass.
    pub fn verify_envelope(&mut self, envelope_bytes: &[u8]) -> Result<bool, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (buf_ptr, buf_len) = self.write_slice(envelope_bytes)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_verify_envelope")?;
        f.call(&mut self.store, (ret_ptr, buf_ptr, buf_len))?;

        // Result<bool, GossipError>: ok value is a 1-byte bool
        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        let result = if ok_flag == 1 {
            let bytes = self.read_bytes(val_ptr, val_len)?;
            Ok(bytes.first().copied().unwrap_or(0) != 0)
        } else {
            let err_bytes = self.read_bytes(val_ptr, val_len)?;
            let msg = String::from_utf8(err_bytes)?;
            Err(GossipBindingError::Component(msg))
        };

        self.free(ret_ptr, 12)?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Encode a new signed GossipEnvelope to bincode bytes.
    ///
    /// Builds the envelope, signs it with the node's ML-DSA-65 key,
    /// and returns the bincode-encoded bytes ready for transmission.
    pub fn encode_envelope(
        &mut self,
        payload_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (buf_ptr, buf_len) = self.write_slice(payload)?;

        let f: TypedFunc<(i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_encode_envelope")?;
        f.call(&mut self.store, (ret_ptr, payload_type as i32, buf_ptr, buf_len))?;

        let result = self.result_bytes(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Decode a GossipEnvelope from bincode bytes to a JSON string.
    ///
    /// Signature bytes are hex-encoded in the JSON output.
    pub fn decode_envelope(&mut self, bytes: &[u8]) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (buf_ptr, buf_len) = self.write_slice(bytes)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_decode_envelope")?;
        f.call(&mut self.store, (ret_ptr, buf_ptr, buf_len))?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Get runtime statistics as a JSON object string.
    ///
    /// Returns JSON matching the `GossipStats` struct fields.
    pub fn get_stats(&mut self) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;

        let f: TypedFunc<i32, ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_get_stats")?;
        f.call(&mut self.store, ret_ptr)?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        result
    }

    /// Process incoming handshake bytes from a peer.
    ///
    /// The host calls this when it receives bytes from a peer during the
    /// handshake phase. Returns optional response bytes to send back, or
    /// `None` if the handshake is complete or no response is needed.
    pub fn process_handshake_bytes(
        &mut self,
        peer_addr: &str,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (addr_ptr, addr_len) = self.write_str(peer_addr)?;
        let (buf_ptr, buf_len) = self.write_slice(bytes)?;

        let f: TypedFunc<(i32, i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_process_handshake_bytes")?;
        f.call(&mut self.store, (ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len))?;

        // Result<Option<Vec<u8>>, GossipError>
        // ok_flag=1 → val_ptr/val_len is the response bytes (len=0 means None)
        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        let result = if ok_flag == 1 {
            if val_len == 0 {
                Ok(None)
            } else {
                let resp = self.read_bytes(val_ptr, val_len)?;
                Ok(Some(resp))
            }
        } else {
            let err_bytes = self.read_bytes(val_ptr, val_len)?;
            let msg = String::from_utf8(err_bytes)?;
            Err(GossipBindingError::Component(msg))
        };

        self.free(ret_ptr, 12)?;
        self.free(addr_ptr, addr_len.max(1))?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Create handshake init bytes to send to a peer.
    ///
    /// Alias for [`connect_peer`] — returns the probe bytes for the host
    /// to transmit to initiate the PQC handshake.
    pub fn create_handshake_init(
        &mut self,
        peer_addr: &str,
    ) -> Result<Vec<u8>, GossipBindingError> {
        self.connect_peer(peer_addr)
    }

    /// Get session info for a peer as a JSON object string.
    pub fn get_session(&mut self, peer_addr: &str) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (str_ptr, str_len) = self.write_str(peer_addr)?;

        let f: TypedFunc<(i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_get_session")?;
        f.call(&mut self.store, (ret_ptr, str_ptr, str_len))?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(str_ptr, str_len.max(1))?;
        result
    }

    /// Rotate node identity keys.
    ///
    /// Returns the new node ID as a 64-char hex string.
    ///
    /// **Warning:** Key rotation invalidates all existing peer sessions.
    /// Peers will need to re-handshake after rotation.
    pub fn rotate_keys(&mut self) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;

        let f: TypedFunc<i32, ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_rotate_keys")?;
        f.call(&mut self.store, ret_ptr)?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        result
    }

    /// Get the protocol version string (e.g. `"0.1.0"`).
    pub fn get_version(&mut self) -> Result<String, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;

        let f: TypedFunc<i32, ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_get_version")?;
        f.call(&mut self.store, ret_ptr)?;

        let result = self.result_string(ret_ptr);
        self.free(ret_ptr, 12)?;
        result
    }

    /// Get the current Unix timestamp in milliseconds from the WASM component.
    pub fn now_ms(&mut self) -> Result<u64, GossipBindingError> {
        let f: TypedFunc<(), i64> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_now_ms")?;
        let ts = f.call(&mut self.store, ())?;
        Ok(ts as u64)
    }

    /// Build the server-side handshake ACK (step 2 of 4).
    ///
    /// Called by a node acting as server when it receives a probe.
    /// Returns the ACK bytes to send back to the client.
    pub fn build_handshake_ack(
        &mut self,
        peer_addr: &str,
        probe_bytes: &[u8],
    ) -> Result<Vec<u8>, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (addr_ptr, addr_len) = self.write_str(peer_addr)?;
        let (buf_ptr, buf_len) = self.write_slice(probe_bytes)?;

        let f: TypedFunc<(i32, i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_build_handshake_ack")?;
        f.call(&mut self.store, (ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len))?;

        let result = self.result_bytes(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(addr_ptr, addr_len.max(1))?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Build the server-side finish ACK (step 4 of 4).
    ///
    /// Called by a node acting as server when it receives the finish probe.
    /// Returns the finish ACK bytes and completes the session.
    pub fn build_finish_ack(
        &mut self,
        peer_addr: &str,
        finish_bytes: &[u8],
    ) -> Result<Vec<u8>, GossipBindingError> {
        let ret_ptr = self.alloc_ret_slot()?;
        let (addr_ptr, addr_len) = self.write_str(peer_addr)?;
        let (buf_ptr, buf_len) = self.write_slice(finish_bytes)?;

        let f: TypedFunc<(i32, i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_build_finish_ack")?;
        f.call(&mut self.store, (ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len))?;

        let result = self.result_bytes(ret_ptr);
        self.free(ret_ptr, 12)?;
        self.free(addr_ptr, addr_len.max(1))?;
        self.free(buf_ptr, buf_len.max(1))?;
        result
    }

    /// Verify a standalone ML-DSA-65 signature.
    ///
    /// Useful for the host to verify node identity claims independently.
    pub fn verify_signature(
        &mut self,
        public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, GossipBindingError> {
        // Allocate a 16-byte return slot (ok_flag + ptr + len for bool result)
        let ret_ptr = self.alloc_ret_slot()?;
        let (pk_ptr, pk_len) = self.write_slice(public_key_bytes)?;
        let (msg_ptr, msg_len) = self.write_slice(message)?;
        let (sig_ptr, sig_len) = self.write_slice(signature)?;
        let (ctx_ptr, ctx_len) = self.write_slice(context)?;

        let f: TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32), ()> = self
            .instance
            .get_typed_func(&mut self.store, "gossip_verify_signature")?;
        f.call(
            &mut self.store,
            (ret_ptr, pk_ptr, pk_len, msg_ptr, msg_len, sig_ptr, sig_len, ctx_ptr, ctx_len),
        )?;

        let (ok_flag, val_ptr, val_len) = self.read_result_slot(ret_ptr)?;
        let result = if ok_flag == 1 {
            let bytes = self.read_bytes(val_ptr, val_len)?;
            Ok(bytes.first().copied().unwrap_or(0) != 0)
        } else {
            let err_bytes = self.read_bytes(val_ptr, val_len)?;
            let msg = String::from_utf8(err_bytes)?;
            Err(GossipBindingError::Component(msg))
        };

        self.free(ret_ptr, 12)?;
        self.free(pk_ptr, pk_len.max(1))?;
        self.free(msg_ptr, msg_len.max(1))?;
        self.free(sig_ptr, sig_len.max(1))?;
        self.free(ctx_ptr, ctx_len.max(1))?;
        result
    }
}