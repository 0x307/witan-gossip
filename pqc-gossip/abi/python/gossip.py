"""
witan-gossip Python host bindings.

Uses wasmtime-py to load and call the WASM component compiled from
pqc-gossip/src with target wasm32-unknown-unknown.

ABI convention (wasm-bindgen style):
  - Strings are passed as (ptr: i32, len: i32) pairs in WASM linear memory.
  - Byte slices are passed as (ptr: i32, len: i32) pairs.
  - Return values use an out-pointer pattern written to a 12-byte slot:
      [0..4]  ok_flag: i32  (1 = Ok, 0 = Err)
      [4..8]  val_ptr: i32  (pointer to value or error string)
      [8..12] val_len: i32  (byte length of value or error string)
  - Memory is allocated via __wbindgen_malloc and freed via __wbindgen_free.

Build the WASM binary first:
    cd pqc-gossip && cargo build --target wasm32-unknown-unknown --release

Install dependencies:
    pip install wasmtime

Usage:
    from gossip import GossipClient
    client = GossipClient(wasm_path="pqc_gossip.wasm")
    client.init({})
    msg_id = client.publish(0, b"hello world")
    print(msg_id.hex())
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Optional, Union

from wasmtime import Engine, Instance, Linker, Memory, Module, Store


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class GossipError(Exception):
    """Raised when the WASM component returns a GossipError variant."""


class GossipMemoryError(Exception):
    """Raised on WASM linear memory access violations."""


# ─────────────────────────────────────────────────────────────────────────────
# GossipClient
# ─────────────────────────────────────────────────────────────────────────────


class GossipClient:
    """Python host bindings for the witan-gossip WASM component.

    All methods correspond 1:1 to exported WASM functions.
    GossipClient is NOT thread-safe; use a threading.Lock if you need
    to call it from multiple threads.

    Args:
        wasm_path: Path to the compiled .wasm binary file.
        wasm_bytes: Raw WASM binary bytes (alternative to wasm_path).

    Raises:
        ValueError: If neither wasm_path nor wasm_bytes is provided.
        FileNotFoundError: If wasm_path does not exist.
        RuntimeError: If the WASM module fails to instantiate.
    """

    def __init__(
        self,
        wasm_path: Optional[Union[str, Path]] = None,
        wasm_bytes: Optional[bytes] = None,
    ) -> None:
        if wasm_path is None and wasm_bytes is None:
            raise ValueError("Either wasm_path or wasm_bytes must be provided")

        if wasm_bytes is None:
            wasm_path = Path(wasm_path)
            if not wasm_path.exists():
                raise FileNotFoundError(f"WASM binary not found: {wasm_path}")
            wasm_bytes = wasm_path.read_bytes()

        self._engine = Engine()
        self._store = Store(self._engine)
        module = Module(self._engine, wasm_bytes)
        linker = Linker(self._engine)
        self._instance: Instance = linker.instantiate(self._store, module)

        # Retrieve the exported linear memory.
        mem_export = self._instance.exports(self._store).get("memory")
        if mem_export is None:
            raise RuntimeError("WASM module has no 'memory' export")
        if not isinstance(mem_export, Memory):
            raise RuntimeError("'memory' export is not a Memory")
        self._memory: Memory = mem_export

    # ── Memory helpers ────────────────────────────────────────────────────────

    def _mem_data(self) -> memoryview:
        """Return a memoryview of the WASM linear memory."""
        return self._memory.data_ptr(self._store)

    def _malloc(self, length: int) -> int:
        """Allocate length bytes in WASM memory via __wbindgen_malloc."""
        fn = self._instance.exports(self._store)["__wbindgen_malloc"]
        result = fn(self._store, max(length, 1), 1)
        return int(result)

    def _free(self, ptr: int, length: int) -> None:
        """Free WASM memory at ptr of length bytes via __wbindgen_free."""
        fn = self._instance.exports(self._store)["__wbindgen_free"]
        fn(self._store, ptr, max(length, 1), 1)

    def _write_bytes(self, ptr: int, data: bytes) -> None:
        """Write data into WASM linear memory at ptr."""
        mem = self._memory.data_ptr(self._store)
        mem_size = self._memory.data_len(self._store)
        end = ptr + len(data)
        if end > mem_size:
            raise GossipMemoryError(
                f"write out of bounds: ptr={ptr} len={len(data)} mem_size={mem_size}"
            )
        # Use ctypes to write into the memory buffer
        import ctypes
        ctypes.memmove(
            ctypes.cast(mem, ctypes.c_void_p).value + ptr,
            data,
            len(data),
        )

    def _read_bytes(self, ptr: int, length: int) -> bytes:
        """Read length bytes from WASM linear memory at ptr."""
        import ctypes
        mem = self._memory.data_ptr(self._store)
        mem_size = self._memory.data_len(self._store)
        end = ptr + length
        if end > mem_size:
            raise GossipMemoryError(
                f"read out of bounds: ptr={ptr} len={length} mem_size={mem_size}"
            )
        buf = (ctypes.c_uint8 * length).from_address(
            ctypes.cast(mem, ctypes.c_void_p).value + ptr
        )
        return bytes(buf)

    def _read_result_slot(self, ret_ptr: int) -> tuple[int, int, int]:
        """Read the 12-byte result slot at ret_ptr.

        Returns:
            (ok_flag, val_ptr, val_len)
        """
        raw = self._read_bytes(ret_ptr, 12)
        ok_flag, val_ptr, val_len = struct.unpack_from("<iii", raw, 0)
        return ok_flag, val_ptr, val_len

    def _alloc_ret_slot(self) -> int:
        """Allocate a 12-byte return slot in WASM memory."""
        return self._malloc(12)

    def _write_str(self, s: str) -> tuple[int, int]:
        """Write a string into WASM memory. Returns (ptr, len)."""
        b = s.encode("utf-8")
        ptr = self._malloc(max(len(b), 1))
        if b:
            self._write_bytes(ptr, b)
        return ptr, len(b)

    def _write_slice(self, data: bytes) -> tuple[int, int]:
        """Write a byte slice into WASM memory. Returns (ptr, len)."""
        if not data:
            ptr = self._malloc(1)
            return ptr, 0
        ptr = self._malloc(len(data))
        self._write_bytes(ptr, data)
        return ptr, len(data)

    def _result_unit(self, ret_ptr: int) -> None:
        """Interpret a result slot as Result<(), String>."""
        ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
        if ok_flag == 1:
            return
        err_bytes = self._read_bytes(val_ptr, val_len)
        raise GossipError(err_bytes.decode("utf-8", errors="replace"))

    def _result_string(self, ret_ptr: int) -> str:
        """Interpret a result slot as Result<String, String>."""
        ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
        b = self._read_bytes(val_ptr, val_len)
        s = b.decode("utf-8", errors="replace")
        if ok_flag == 1:
            return s
        raise GossipError(s)

    def _result_bytes(self, ret_ptr: int) -> bytes:
        """Interpret a result slot as Result<Vec<u8>, String>."""
        ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
        if ok_flag == 1:
            return self._read_bytes(val_ptr, val_len)
        err_bytes = self._read_bytes(val_ptr, val_len)
        raise GossipError(err_bytes.decode("utf-8", errors="replace"))

    def _call(self, fn_name: str, *args):
        """Call a WASM exported function by name."""
        exports = self._instance.exports(self._store)
        fn = exports.get(fn_name)
        if fn is None:
            raise RuntimeError(f"WASM export not found: {fn_name}")
        return fn(self._store, *args)

    # ── Public API ────────────────────────────────────────────────────────────

    def init(self, config: Union[dict, str] = "{}") -> None:
        """Initialize the gossip engine with a JSON configuration.

        Must be called exactly once before any other method.
        Pass ``{}`` or an empty dict to use all defaults.

        Args:
            config: Configuration as a dict or JSON string. Supported keys:
                node_id, kem_seed_hex, sig_seed_hex, key_epoch, mesh_n,
                mesh_n_low, mesh_n_high, heartbeat_ms, max_message_bytes,
                dedup_cache_secs, quorum_fraction, replay_window_ms, default_ttl.

        Raises:
            GossipError: If the config is invalid or already initialized.
        """
        if isinstance(config, dict):
            config = json.dumps(config)

        ret_ptr = self._alloc_ret_slot()
        str_ptr, str_len = self._write_str(config)
        try:
            self._call("gossip_init", ret_ptr, str_ptr, str_len)
            self._result_unit(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(str_ptr, max(str_len, 1))

    def publish(self, payload_type: int, payload: bytes) -> bytes:
        """Publish a message to the gossip mesh.

        Args:
            payload_type: Payload type discriminant.
                0=Transaction, 1=BlockProposal, 2=FinalityVote,
                3=StateSync, 4=PeerDiscovery.
            payload: Raw message bytes (max 1MB by default).

        Returns:
            32-byte message ID (SHA-256 of payload_type_byte || payload).

        Raises:
            GossipError: If the component is not initialized or payload is invalid.
        """
        ret_ptr = self._alloc_ret_slot()
        buf_ptr, buf_len = self._write_slice(payload)
        try:
            self._call("gossip_publish", ret_ptr, payload_type, buf_ptr, buf_len)
            result = self._result_bytes(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(buf_ptr, max(buf_len, 1))

        if len(result) != 32:
            raise GossipError(f"expected 32-byte message_id, got {len(result)} bytes")
        return result

    def connect_peer(self, peer_addr: str) -> bytes:
        """Initiate a PQC handshake with a peer.

        Returns the probe bytes that the host must transmit to the peer.
        The host must then call :meth:`process_handshake_bytes` as responses arrive.

        Args:
            peer_addr: Network address of the peer (e.g. "192.168.1.10:9000").

        Returns:
            Probe bytes to send to the peer.

        Raises:
            GossipError: If the component is not initialized.
        """
        ret_ptr = self._alloc_ret_slot()
        str_ptr, str_len = self._write_str(peer_addr)
        try:
            self._call("gossip_connect_peer", ret_ptr, str_ptr, str_len)
            return self._result_bytes(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(str_ptr, max(str_len, 1))

    def disconnect_peer(self, peer_addr: str) -> None:
        """Disconnect from a peer and remove their session.

        Args:
            peer_addr: Network address of the peer.

        Raises:
            GossipError: If the peer is not found.
        """
        ret_ptr = self._alloc_ret_slot()
        str_ptr, str_len = self._write_str(peer_addr)
        try:
            self._call("gossip_disconnect_peer", ret_ptr, str_ptr, str_len)
            self._result_unit(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(str_ptr, max(str_len, 1))

    def get_peers(self) -> list[dict]:
        """Get the list of currently connected peers.

        Returns:
            List of peer dicts with keys: addr, node_id, session_id,
            established_at_ms.

        Raises:
            GossipError: If the component is not initialized.
        """
        ret_ptr = self._alloc_ret_slot()
        try:
            self._call("gossip_get_peers", ret_ptr)
            peers_json = self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
        return json.loads(peers_json)

    def get_node_identity(self) -> dict:
        """Get the node's public identity.

        Returns:
            Dict with keys: node_id (64-char hex), kem_public_key_json,
            sig_public_key_hex (3904-char hex), key_epoch.

        Raises:
            GossipError: If the component is not initialized.
        """
        ret_ptr = self._alloc_ret_slot()
        try:
            self._call("gossip_get_node_identity", ret_ptr)
            identity_json = self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
        return json.loads(identity_json)

    def verify_envelope(self, envelope_bytes: bytes) -> bool:
        """Verify a received GossipEnvelope (bincode-encoded bytes).

        Checks: bincode deserialization, message_id hash, ML-DSA-65 signature,
        timestamp within ±30s, and TTL > 0.

        Args:
            envelope_bytes: Bincode-encoded GossipEnvelope bytes.

        Returns:
            True if all checks pass, False otherwise.

        Raises:
            GossipError: On deserialization or crypto errors.
        """
        ret_ptr = self._alloc_ret_slot()
        buf_ptr, buf_len = self._write_slice(envelope_bytes)
        try:
            self._call("gossip_verify_envelope", ret_ptr, buf_ptr, buf_len)
            ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
            if ok_flag == 1:
                b = self._read_bytes(val_ptr, val_len)
                return bool(b[0]) if b else False
            err_bytes = self._read_bytes(val_ptr, val_len)
            raise GossipError(err_bytes.decode("utf-8", errors="replace"))
        finally:
            self._free(ret_ptr, 12)
            self._free(buf_ptr, max(buf_len, 1))

    def encode_envelope(self, payload_type: int, payload: bytes) -> bytes:
        """Encode a new signed GossipEnvelope to bincode bytes.

        Builds the envelope, signs it with the node's ML-DSA-65 key,
        and returns the bincode-encoded bytes ready for transmission.

        Args:
            payload_type: Payload type discriminant (0–4).
            payload: Raw message bytes.

        Returns:
            Bincode-encoded, signed GossipEnvelope bytes.

        Raises:
            GossipError: If the component is not initialized or encoding fails.
        """
        ret_ptr = self._alloc_ret_slot()
        buf_ptr, buf_len = self._write_slice(payload)
        try:
            self._call("gossip_encode_envelope", ret_ptr, payload_type, buf_ptr, buf_len)
            return self._result_bytes(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(buf_ptr, max(buf_len, 1))

    def decode_envelope(self, envelope_bytes: bytes) -> dict:
        """Decode a GossipEnvelope from bincode bytes.

        Args:
            envelope_bytes: Bincode-encoded GossipEnvelope bytes.

        Returns:
            Dict representation of the GossipEnvelope. Signature bytes
            are hex-encoded strings in the output.

        Raises:
            GossipError: If deserialization fails.
        """
        ret_ptr = self._alloc_ret_slot()
        buf_ptr, buf_len = self._write_slice(envelope_bytes)
        try:
            self._call("gossip_decode_envelope", ret_ptr, buf_ptr, buf_len)
            envelope_json = self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(buf_ptr, max(buf_len, 1))
        return json.loads(envelope_json)

    def get_stats(self) -> dict:
        """Get runtime statistics.

        Returns:
            Dict with keys: messages_published, messages_received,
            messages_deduplicated, messages_dropped, active_peers,
            mesh_peers, dedup_cache_size, handshakes_completed,
            handshakes_failed.

        Raises:
            GossipError: If the component is not initialized.
        """
        ret_ptr = self._alloc_ret_slot()
        try:
            self._call("gossip_get_stats", ret_ptr)
            stats_json = self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
        return json.loads(stats_json)

    def process_handshake_bytes(self, peer_addr: str, data: bytes) -> Optional[bytes]:
        """Process incoming handshake bytes from a peer.

        The host calls this when it receives bytes from a peer during the
        handshake phase. Returns optional response bytes to send back, or
        None if the handshake is complete or no response is needed.

        Args:
            peer_addr: Network address of the peer.
            data: Raw handshake bytes received from the peer.

        Returns:
            Response bytes to send back, or None.

        Raises:
            GossipError: On handshake protocol violations.
        """
        ret_ptr = self._alloc_ret_slot()
        addr_ptr, addr_len = self._write_str(peer_addr)
        buf_ptr, buf_len = self._write_slice(data)
        try:
            self._call(
                "gossip_process_handshake_bytes",
                ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len,
            )
            ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
            if ok_flag == 1:
                if val_len == 0:
                    return None
                return self._read_bytes(val_ptr, val_len)
            err_bytes = self._read_bytes(val_ptr, val_len)
            raise GossipError(err_bytes.decode("utf-8", errors="replace"))
        finally:
            self._free(ret_ptr, 12)
            self._free(addr_ptr, max(addr_len, 1))
            self._free(buf_ptr, max(buf_len, 1))

    def create_handshake_init(self, peer_addr: str) -> bytes:
        """Create handshake init bytes to send to a peer.

        Alias for :meth:`connect_peer` — returns the probe bytes for the
        host to transmit to initiate the PQC handshake.

        Args:
            peer_addr: Network address of the peer.

        Returns:
            Probe bytes to send to the peer.
        """
        return self.connect_peer(peer_addr)

    def get_session(self, peer_addr: str) -> dict:
        """Get session info for a connected peer.

        Args:
            peer_addr: Network address of the peer.

        Returns:
            Dict with keys: peer_addr, peer_node_id, session_id,
            established_at_ms, is_active.

        Raises:
            GossipError: If no session exists for the peer.
        """
        ret_ptr = self._alloc_ret_slot()
        str_ptr, str_len = self._write_str(peer_addr)
        try:
            self._call("gossip_get_session", ret_ptr, str_ptr, str_len)
            session_json = self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(str_ptr, max(str_len, 1))
        return json.loads(session_json)

    def rotate_keys(self) -> str:
        """Rotate node identity keys.

        Returns the new node ID as a 64-char hex string.

        .. warning::
            Key rotation invalidates all existing peer sessions.
            Peers will need to re-handshake after rotation.

        Returns:
            New node ID (64-char hex).

        Raises:
            GossipError: If the component is not initialized.
        """
        ret_ptr = self._alloc_ret_slot()
        try:
            self._call("gossip_rotate_keys", ret_ptr)
            return self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)

    def get_version(self) -> str:
        """Get the protocol version string.

        Returns:
            Version string (e.g. "0.1.0").
        """
        ret_ptr = self._alloc_ret_slot()
        try:
            self._call("gossip_get_version", ret_ptr)
            return self._result_string(ret_ptr)
        finally:
            self._free(ret_ptr, 12)

    def now_ms(self) -> int:
        """Get the current Unix timestamp in milliseconds from the WASM component.

        Returns:
            Unix timestamp in milliseconds.
        """
        result = self._call("gossip_now_ms")
        return int(result)

    def build_handshake_ack(self, peer_addr: str, probe_bytes: bytes) -> bytes:
        """Build the server-side handshake ACK (step 2 of 4).

        Called by a node acting as server when it receives a probe.
        Returns the ACK bytes to send back to the client.

        Args:
            peer_addr: Network address of the client peer.
            probe_bytes: The HandshakeProbe bytes received from the client.

        Returns:
            HandshakeAck bytes to send back to the client.

        Raises:
            GossipError: On handshake protocol violations.
        """
        ret_ptr = self._alloc_ret_slot()
        addr_ptr, addr_len = self._write_str(peer_addr)
        buf_ptr, buf_len = self._write_slice(probe_bytes)
        try:
            self._call(
                "gossip_build_handshake_ack",
                ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len,
            )
            return self._result_bytes(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(addr_ptr, max(addr_len, 1))
            self._free(buf_ptr, max(buf_len, 1))

    def build_finish_ack(self, peer_addr: str, finish_bytes: bytes) -> bytes:
        """Build the server-side finish ACK (step 4 of 4).

        Called by a node acting as server when it receives the finish probe.
        Returns the finish ACK bytes and completes the session.

        Args:
            peer_addr: Network address of the client peer.
            finish_bytes: The HandshakeFinish bytes received from the client.

        Returns:
            HandshakeFinishAck bytes to send back to the client.

        Raises:
            GossipError: On handshake protocol violations.
        """
        ret_ptr = self._alloc_ret_slot()
        addr_ptr, addr_len = self._write_str(peer_addr)
        buf_ptr, buf_len = self._write_slice(finish_bytes)
        try:
            self._call(
                "gossip_build_finish_ack",
                ret_ptr, addr_ptr, addr_len, buf_ptr, buf_len,
            )
            return self._result_bytes(ret_ptr)
        finally:
            self._free(ret_ptr, 12)
            self._free(addr_ptr, max(addr_len, 1))
            self._free(buf_ptr, max(buf_len, 1))

    def verify_signature(
        self,
        public_key_bytes: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Verify a standalone ML-DSA-65 signature.

        Useful for the host to verify node identity claims independently.

        Args:
            public_key_bytes: ML-DSA-65 public key (1952 bytes).
            message: Message bytes that were signed.
            signature: ML-DSA-65 signature (3309 bytes).
            context: Signature context string as bytes.

        Returns:
            True if the signature is valid.

        Raises:
            GossipError: On cryptographic errors.
        """
        ret_ptr = self._alloc_ret_slot()
        pk_ptr, pk_len = self._write_slice(public_key_bytes)
        msg_ptr, msg_len = self._write_slice(message)
        sig_ptr, sig_len = self._write_slice(signature)
        ctx_ptr, ctx_len = self._write_slice(context)
        try:
            self._call(
                "gossip_verify_signature",
                ret_ptr,
                pk_ptr, pk_len,
                msg_ptr, msg_len,
                sig_ptr, sig_len,
                ctx_ptr, ctx_len,
            )
            ok_flag, val_ptr, val_len = self._read_result_slot(ret_ptr)
            if ok_flag == 1:
                b = self._read_bytes(val_ptr, val_len)
                return bool(b[0]) if b else False
            err_bytes = self._read_bytes(val_ptr, val_len)
            raise GossipError(err_bytes.decode("utf-8", errors="replace"))
        finally:
            self._free(ret_ptr, 12)
            self._free(pk_ptr, max(pk_len, 1))
            self._free(msg_ptr, max(msg_len, 1))
            self._free(sig_ptr, max(sig_len, 1))
            self._free(ctx_ptr, max(ctx_len, 1))
