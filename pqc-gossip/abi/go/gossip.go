// Package gossip provides Go host bindings for the witan-gossip WASM component.
//
// Uses github.com/bytecodealliance/wasmtime-go to load and call the WASM binary
// compiled from pqc-gossip/src with target wasm32-unknown-unknown.
//
// ABI convention (wasm-bindgen style):
//   - Strings are passed as (ptr int32, len int32) pairs in WASM linear memory.
//   - Byte slices are passed as (ptr int32, len int32) pairs.
//   - Return values use an out-pointer pattern written to a 12-byte slot:
//     [0..4]  ok_flag int32  (1 = Ok, 0 = Err)
//     [4..8]  val_ptr int32  (pointer to value or error string)
//     [8..12] val_len int32  (byte length of value or error string)
//   - Memory is allocated via __wbindgen_malloc and freed via __wbindgen_free.
//
// Build the WASM binary first:
//
//	cd pqc-gossip && cargo build --target wasm32-unknown-unknown --release
package gossip

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/bytecodealliance/wasmtime-go/v25"
)

// ─────────────────────────────────────────────────────────────────────────────
// GossipClient
// ─────────────────────────────────────────────────────────────────────────────

// GossipClient wraps the witan-gossip WASM component.
//
// All methods correspond 1:1 to exported WASM functions.
// GossipClient is NOT safe for concurrent use; protect with a sync.Mutex
// if you need to call it from multiple goroutines.
type GossipClient struct {
	engine   *wasmtime.Engine
	store    *wasmtime.Store
	instance *wasmtime.Instance
	memory   *wasmtime.Memory
}

// NewGossipClientFromFile loads the WASM component from a file path.
//
// Example:
//
//	client, err := gossip.NewGossipClientFromFile("pqc_gossip.wasm")
func NewGossipClientFromFile(wasmPath string) (*GossipClient, error) {
	data, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("gossip: read wasm file: %w", err)
	}
	return NewGossipClientFromBytes(data)
}

// NewGossipClientFromBytes loads the WASM component from raw bytes.
//
// Example:
//
//	//go:embed pqc_gossip.wasm
//	var wasmBytes []byte
//
//	client, err := gossip.NewGossipClientFromBytes(wasmBytes)
func NewGossipClientFromBytes(wasmBytes []byte) (*GossipClient, error) {
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)

	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("gossip: compile wasm module: %w", err)
	}

	linker := wasmtime.NewLinker(engine)
	instance, err := linker.Instantiate(store, module)
	if err != nil {
		return nil, fmt.Errorf("gossip: instantiate wasm module: %w", err)
	}

	// Retrieve the exported linear memory.
	memExport := instance.GetExport(store, "memory")
	if memExport == nil {
		return nil, fmt.Errorf("gossip: wasm module has no 'memory' export")
	}
	memory := memExport.Memory()
	if memory == nil {
		return nil, fmt.Errorf("gossip: 'memory' export is not a memory")
	}

	return &GossipClient{
		engine:   engine,
		store:    store,
		instance: instance,
		memory:   memory,
	}, nil
}

// Close releases resources held by the GossipClient.
// After Close, the client must not be used.
func (c *GossipClient) Close() {
	if c.store != nil {
		c.store.Close()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory helpers
// ─────────────────────────────────────────────────────────────────────────────

// malloc allocates len bytes in WASM linear memory via __wbindgen_malloc.
func (c *GossipClient) malloc(length int32) (int32, error) {
	fn := c.instance.GetFunc(c.store, "__wbindgen_malloc")
	if fn == nil {
		return 0, fmt.Errorf("gossip: __wbindgen_malloc not found")
	}
	result, err := fn.Call(c.store, length, int32(1))
	if err != nil {
		return 0, fmt.Errorf("gossip: __wbindgen_malloc: %w", err)
	}
	ptr, ok := result.(int32)
	if !ok {
		return 0, fmt.Errorf("gossip: __wbindgen_malloc returned non-i32")
	}
	return ptr, nil
}

// free releases WASM memory at ptr of length bytes via __wbindgen_free.
func (c *GossipClient) free(ptr, length int32) error {
	fn := c.instance.GetFunc(c.store, "__wbindgen_free")
	if fn == nil {
		return fmt.Errorf("gossip: __wbindgen_free not found")
	}
	_, err := fn.Call(c.store, ptr, length, int32(1))
	if err != nil {
		return fmt.Errorf("gossip: __wbindgen_free: %w", err)
	}
	return nil
}

// memData returns a slice of the WASM linear memory.
func (c *GossipClient) memData() []byte {
	return c.memory.UnsafeData(c.store)
}

// writeBytes writes data into WASM linear memory at ptr.
func (c *GossipClient) writeBytes(ptr int32, data []byte) error {
	mem := c.memData()
	start := int(ptr)
	end := start + len(data)
	if end > len(mem) {
		return fmt.Errorf("gossip: write out of bounds: ptr=%d len=%d mem_size=%d",
			ptr, len(data), len(mem))
	}
	copy(mem[start:end], data)
	return nil
}

// readBytes reads length bytes from WASM linear memory at ptr.
func (c *GossipClient) readBytes(ptr, length int32) ([]byte, error) {
	mem := c.memData()
	start := int(ptr)
	end := start + int(length)
	if end > len(mem) {
		return nil, fmt.Errorf("gossip: read out of bounds: ptr=%d len=%d mem_size=%d",
			ptr, length, len(mem))
	}
	result := make([]byte, length)
	copy(result, mem[start:end])
	return result, nil
}

// readResultSlot reads the 12-byte result slot at retPtr:
//
//	[0..4]  ok_flag int32
//	[4..8]  val_ptr int32
//	[8..12] val_len int32
func (c *GossipClient) readResultSlot(retPtr int32) (okFlag, valPtr, valLen int32, err error) {
	mem := c.memData()
	base := int(retPtr)
	if base+12 > len(mem) {
		return 0, 0, 0, fmt.Errorf("gossip: result slot out of bounds: ret_ptr=%d", retPtr)
	}
	okFlag = int32(binary.LittleEndian.Uint32(mem[base : base+4]))
	valPtr = int32(binary.LittleEndian.Uint32(mem[base+4 : base+8]))
	valLen = int32(binary.LittleEndian.Uint32(mem[base+8 : base+12]))
	return okFlag, valPtr, valLen, nil
}

// allocRetSlot allocates a 12-byte return slot in WASM memory.
func (c *GossipClient) allocRetSlot() (int32, error) {
	return c.malloc(12)
}

// writeStr writes a string into WASM memory and returns (ptr, len).
func (c *GossipClient) writeStr(s string) (ptr, length int32, err error) {
	b := []byte(s)
	size := int32(len(b))
	if size == 0 {
		size = 1
	}
	ptr, err = c.malloc(size)
	if err != nil {
		return 0, 0, err
	}
	if len(b) > 0 {
		if err = c.writeBytes(ptr, b); err != nil {
			return 0, 0, err
		}
	}
	return ptr, int32(len(b)), nil
}

// writeSlice writes a byte slice into WASM memory and returns (ptr, len).
func (c *GossipClient) writeSlice(data []byte) (ptr, length int32, err error) {
	if len(data) == 0 {
		ptr, err = c.malloc(1)
		return ptr, 0, err
	}
	ptr, err = c.malloc(int32(len(data)))
	if err != nil {
		return 0, 0, err
	}
	if err = c.writeBytes(ptr, data); err != nil {
		return 0, 0, err
	}
	return ptr, int32(len(data)), nil
}

// resultUnit interprets a result slot as Result<(), String>.
func (c *GossipClient) resultUnit(retPtr int32) error {
	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	if err != nil {
		return err
	}
	if okFlag == 1 {
		return nil
	}
	errBytes, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return err
	}
	return fmt.Errorf("gossip component error: %s", string(errBytes))
}

// resultString interprets a result slot as Result<String, String>.
func (c *GossipClient) resultString(retPtr int32) (string, error) {
	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	if err != nil {
		return "", err
	}
	b, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return "", err
	}
	s := string(b)
	if okFlag == 1 {
		return s, nil
	}
	return "", fmt.Errorf("gossip component error: %s", s)
}

// resultBytes interprets a result slot as Result<Vec<u8>, String>.
func (c *GossipClient) resultBytesSlot(retPtr int32) ([]byte, error) {
	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	if err != nil {
		return nil, err
	}
	if okFlag == 1 {
		return c.readBytes(valPtr, valLen)
	}
	errBytes, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("gossip component error: %s", string(errBytes))
}

// maxI32 returns the larger of two int32 values.
func maxI32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

// Init initializes the gossip engine with a JSON configuration string.
//
// Must be called exactly once before any other method.
// Pass "{}" to use all defaults.
//
// Returns an error if the config is invalid or the component has already
// been initialized.
func (c *GossipClient) Init(configJSON string) error {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return err
	}
	strPtr, strLen, err := c.writeStr(configJSON)
	if err != nil {
		return err
	}

	fn := c.instance.GetFunc(c.store, "gossip_init")
	if fn == nil {
		return fmt.Errorf("gossip: gossip_init not found")
	}
	if _, err = fn.Call(c.store, retPtr, strPtr, strLen); err != nil {
		return fmt.Errorf("gossip: gossip_init call: %w", err)
	}

	result := c.resultUnit(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(strPtr, maxI32(strLen, 1))
	return result
}

// Publish publishes a message to the gossip mesh.
//
// Returns the 32-byte message ID.
//
// payloadType values: 0=Transaction, 1=BlockProposal, 2=FinalityVote,
// 3=StateSync, 4=PeerDiscovery.
func (c *GossipClient) Publish(payloadType uint8, payload []byte) ([32]byte, error) {
	var msgID [32]byte

	retPtr, err := c.allocRetSlot()
	if err != nil {
		return msgID, err
	}
	bufPtr, bufLen, err := c.writeSlice(payload)
	if err != nil {
		return msgID, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_publish")
	if fn == nil {
		return msgID, fmt.Errorf("gossip: gossip_publish not found")
	}
	if _, err = fn.Call(c.store, retPtr, int32(payloadType), bufPtr, bufLen); err != nil {
		return msgID, fmt.Errorf("gossip: gossip_publish call: %w", err)
	}

	b, err := c.resultBytesSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	if err != nil {
		return msgID, err
	}
	if len(b) != 32 {
		return msgID, fmt.Errorf("gossip: expected 32-byte message_id, got %d bytes", len(b))
	}
	copy(msgID[:], b)
	return msgID, nil
}

// ConnectPeer initiates a PQC handshake with a peer.
//
// Returns the probe bytes that the host must transmit to the peer.
// The host must then call ProcessHandshakeBytes as responses arrive.
func (c *GossipClient) ConnectPeer(peerAddr string) ([]byte, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return nil, err
	}
	strPtr, strLen, err := c.writeStr(peerAddr)
	if err != nil {
		return nil, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_connect_peer")
	if fn == nil {
		return nil, fmt.Errorf("gossip: gossip_connect_peer not found")
	}
	if _, err = fn.Call(c.store, retPtr, strPtr, strLen); err != nil {
		return nil, fmt.Errorf("gossip: gossip_connect_peer call: %w", err)
	}

	result, err := c.resultBytesSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(strPtr, maxI32(strLen, 1))
	return result, err
}

// DisconnectPeer disconnects from a peer and removes their session.
func (c *GossipClient) DisconnectPeer(peerAddr string) error {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return err
	}
	strPtr, strLen, err := c.writeStr(peerAddr)
	if err != nil {
		return err
	}

	fn := c.instance.GetFunc(c.store, "gossip_disconnect_peer")
	if fn == nil {
		return fmt.Errorf("gossip: gossip_disconnect_peer not found")
	}
	if _, err = fn.Call(c.store, retPtr, strPtr, strLen); err != nil {
		return fmt.Errorf("gossip: gossip_disconnect_peer call: %w", err)
	}

	result := c.resultUnit(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(strPtr, maxI32(strLen, 1))
	return result
}

// GetPeers returns the list of currently connected peers as a JSON string.
//
// JSON format: [{"addr":"...","node_id":"...","session_id":"...","established_at_ms":...}]
func (c *GossipClient) GetPeers() (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_get_peers")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_get_peers not found")
	}
	if _, err = fn.Call(c.store, retPtr); err != nil {
		return "", fmt.Errorf("gossip: gossip_get_peers call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	return result, err
}

// GetNodeIdentity returns the node's public identity as a JSON string.
//
// JSON format:
//
//	{
//	  "node_id": "hex...",
//	  "kem_public_key_json": "{...}",
//	  "sig_public_key_hex": "hex...",
//	  "key_epoch": "ephemeral-runtime"
//	}
func (c *GossipClient) GetNodeIdentity() (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_get_node_identity")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_get_node_identity not found")
	}
	if _, err = fn.Call(c.store, retPtr); err != nil {
		return "", fmt.Errorf("gossip: gossip_get_node_identity call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	return result, err
}

// VerifyEnvelope verifies a received GossipEnvelope (bincode-encoded bytes).
//
// Checks: bincode deserialization, message_id hash, ML-DSA-65 signature,
// timestamp within ±30s, and TTL > 0.
//
// Returns true if all checks pass.
func (c *GossipClient) VerifyEnvelope(envelopeBytes []byte) (bool, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return false, err
	}
	bufPtr, bufLen, err := c.writeSlice(envelopeBytes)
	if err != nil {
		return false, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_verify_envelope")
	if fn == nil {
		return false, fmt.Errorf("gossip: gossip_verify_envelope not found")
	}
	if _, err = fn.Call(c.store, retPtr, bufPtr, bufLen); err != nil {
		return false, fmt.Errorf("gossip: gossip_verify_envelope call: %w", err)
	}

	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	if err != nil {
		return false, err
	}
	if okFlag == 1 {
		b, err := c.readBytes(valPtr, valLen)
		if err != nil {
			return false, err
		}
		if len(b) == 0 {
			return false, nil
		}
		return b[0] != 0, nil
	}
	errBytes, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return false, err
	}
	return false, fmt.Errorf("gossip component error: %s", string(errBytes))
}

// EncodeEnvelope encodes a new signed GossipEnvelope to bincode bytes.
//
// Builds the envelope, signs it with the node's ML-DSA-65 key,
// and returns the bincode-encoded bytes ready for transmission.
func (c *GossipClient) EncodeEnvelope(payloadType uint8, payload []byte) ([]byte, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return nil, err
	}
	bufPtr, bufLen, err := c.writeSlice(payload)
	if err != nil {
		return nil, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_encode_envelope")
	if fn == nil {
		return nil, fmt.Errorf("gossip: gossip_encode_envelope not found")
	}
	if _, err = fn.Call(c.store, retPtr, int32(payloadType), bufPtr, bufLen); err != nil {
		return nil, fmt.Errorf("gossip: gossip_encode_envelope call: %w", err)
	}

	result, err := c.resultBytesSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	return result, err
}

// DecodeEnvelope decodes a GossipEnvelope from bincode bytes to a JSON string.
//
// Signature bytes are hex-encoded in the JSON output.
func (c *GossipClient) DecodeEnvelope(envelopeBytes []byte) (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}
	bufPtr, bufLen, err := c.writeSlice(envelopeBytes)
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_decode_envelope")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_decode_envelope not found")
	}
	if _, err = fn.Call(c.store, retPtr, bufPtr, bufLen); err != nil {
		return "", fmt.Errorf("gossip: gossip_decode_envelope call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	return result, err
}

// GetStats returns runtime statistics as a JSON string.
//
// JSON fields match the GossipStats struct in pqc-gossip/src/types.rs.
func (c *GossipClient) GetStats() (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_get_stats")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_get_stats not found")
	}
	if _, err = fn.Call(c.store, retPtr); err != nil {
		return "", fmt.Errorf("gossip: gossip_get_stats call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	return result, err
}

// ProcessHandshakeBytes processes incoming handshake bytes from a peer.
//
// The host calls this when it receives bytes from a peer during the handshake
// phase. Returns optional response bytes to send back (nil if no response
// needed or handshake is complete).
func (c *GossipClient) ProcessHandshakeBytes(peerAddr string, data []byte) ([]byte, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return nil, err
	}
	addrPtr, addrLen, err := c.writeStr(peerAddr)
	if err != nil {
		return nil, err
	}
	bufPtr, bufLen, err := c.writeSlice(data)
	if err != nil {
		return nil, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_process_handshake_bytes")
	if fn == nil {
		return nil, fmt.Errorf("gossip: gossip_process_handshake_bytes not found")
	}
	if _, err = fn.Call(c.store, retPtr, addrPtr, addrLen, bufPtr, bufLen); err != nil {
		return nil, fmt.Errorf("gossip: gossip_process_handshake_bytes call: %w", err)
	}

	// Result<Option<Vec<u8>>, GossipError>: val_len=0 means None
	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(addrPtr, maxI32(addrLen, 1))
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	if err != nil {
		return nil, err
	}
	if okFlag == 1 {
		if valLen == 0 {
			return nil, nil
		}
		return c.readBytes(valPtr, valLen)
	}
	errBytes, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("gossip component error: %s", string(errBytes))
}

// CreateHandshakeInit creates handshake init bytes to send to a peer.
//
// Alias for ConnectPeer — returns the probe bytes for the host to transmit
// to initiate the PQC handshake.
func (c *GossipClient) CreateHandshakeInit(peerAddr string) ([]byte, error) {
	return c.ConnectPeer(peerAddr)
}

// GetSession returns session info for a peer as a JSON string.
func (c *GossipClient) GetSession(peerAddr string) (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}
	strPtr, strLen, err := c.writeStr(peerAddr)
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_get_session")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_get_session not found")
	}
	if _, err = fn.Call(c.store, retPtr, strPtr, strLen); err != nil {
		return "", fmt.Errorf("gossip: gossip_get_session call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(strPtr, maxI32(strLen, 1))
	return result, err
}

// RotateKeys rotates node identity keys and returns the new node ID (64-char hex).
//
// WARNING: Key rotation invalidates all existing peer sessions.
// Peers will need to re-handshake after rotation.
func (c *GossipClient) RotateKeys() (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_rotate_keys")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_rotate_keys not found")
	}
	if _, err = fn.Call(c.store, retPtr); err != nil {
		return "", fmt.Errorf("gossip: gossip_rotate_keys call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	return result, err
}

// GetVersion returns the protocol version string (e.g. "0.1.0").
func (c *GossipClient) GetVersion() (string, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return "", err
	}

	fn := c.instance.GetFunc(c.store, "gossip_get_version")
	if fn == nil {
		return "", fmt.Errorf("gossip: gossip_get_version not found")
	}
	if _, err = fn.Call(c.store, retPtr); err != nil {
		return "", fmt.Errorf("gossip: gossip_get_version call: %w", err)
	}

	result, err := c.resultString(retPtr)
	_ = c.free(retPtr, 12)
	return result, err
}

// NowMs returns the current Unix timestamp in milliseconds from the WASM component.
func (c *GossipClient) NowMs() (uint64, error) {
	fn := c.instance.GetFunc(c.store, "gossip_now_ms")
	if fn == nil {
		return 0, fmt.Errorf("gossip: gossip_now_ms not found")
	}
	result, err := fn.Call(c.store)
	if err != nil {
		return 0, fmt.Errorf("gossip: gossip_now_ms call: %w", err)
	}
	ts, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("gossip: gossip_now_ms returned unexpected type")
	}
	return uint64(ts), nil
}

// BuildHandshakeAck builds the server-side handshake ACK (step 2 of 4).
//
// Called by a node acting as server when it receives a probe.
// Returns the ACK bytes to send back to the client.
func (c *GossipClient) BuildHandshakeAck(peerAddr string, probeBytes []byte) ([]byte, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return nil, err
	}
	addrPtr, addrLen, err := c.writeStr(peerAddr)
	if err != nil {
		return nil, err
	}
	bufPtr, bufLen, err := c.writeSlice(probeBytes)
	if err != nil {
		return nil, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_build_handshake_ack")
	if fn == nil {
		return nil, fmt.Errorf("gossip: gossip_build_handshake_ack not found")
	}
	if _, err = fn.Call(c.store, retPtr, addrPtr, addrLen, bufPtr, bufLen); err != nil {
		return nil, fmt.Errorf("gossip: gossip_build_handshake_ack call: %w", err)
	}

	result, err := c.resultBytesSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(addrPtr, maxI32(addrLen, 1))
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	return result, err
}

// BuildFinishAck builds the server-side finish ACK (step 4 of 4).
//
// Called by a node acting as server when it receives the finish probe.
// Returns the finish ACK bytes and completes the session.
func (c *GossipClient) BuildFinishAck(peerAddr string, finishBytes []byte) ([]byte, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return nil, err
	}
	addrPtr, addrLen, err := c.writeStr(peerAddr)
	if err != nil {
		return nil, err
	}
	bufPtr, bufLen, err := c.writeSlice(finishBytes)
	if err != nil {
		return nil, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_build_finish_ack")
	if fn == nil {
		return nil, fmt.Errorf("gossip: gossip_build_finish_ack not found")
	}
	if _, err = fn.Call(c.store, retPtr, addrPtr, addrLen, bufPtr, bufLen); err != nil {
		return nil, fmt.Errorf("gossip: gossip_build_finish_ack call: %w", err)
	}

	result, err := c.resultBytesSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(addrPtr, maxI32(addrLen, 1))
	_ = c.free(bufPtr, maxI32(bufLen, 1))
	return result, err
}

// VerifySignature verifies a standalone ML-DSA-65 signature.
//
// Useful for the host to verify node identity claims independently.
func (c *GossipClient) VerifySignature(publicKeyBytes, message, signature, context []byte) (bool, error) {
	retPtr, err := c.allocRetSlot()
	if err != nil {
		return false, err
	}
	pkPtr, pkLen, err := c.writeSlice(publicKeyBytes)
	if err != nil {
		return false, err
	}
	msgPtr, msgLen, err := c.writeSlice(message)
	if err != nil {
		return false, err
	}
	sigPtr, sigLen, err := c.writeSlice(signature)
	if err != nil {
		return false, err
	}
	ctxPtr, ctxLen, err := c.writeSlice(context)
	if err != nil {
		return false, err
	}

	fn := c.instance.GetFunc(c.store, "gossip_verify_signature")
	if fn == nil {
		return false, fmt.Errorf("gossip: gossip_verify_signature not found")
	}
	if _, err = fn.Call(c.store, retPtr, pkPtr, pkLen, msgPtr, msgLen, sigPtr, sigLen, ctxPtr, ctxLen); err != nil {
		return false, fmt.Errorf("gossip: gossip_verify_signature call: %w", err)
	}

	okFlag, valPtr, valLen, err := c.readResultSlot(retPtr)
	_ = c.free(retPtr, 12)
	_ = c.free(pkPtr, maxI32(pkLen, 1))
	_ = c.free(msgPtr, maxI32(msgLen, 1))
	_ = c.free(sigPtr, maxI32(sigLen, 1))
	_ = c.free(ctxPtr, maxI32(ctxLen, 1))
	if err != nil {
		return false, err
	}
	if okFlag == 1 {
		b, err := c.readBytes(valPtr, valLen)
		if err != nil {
			return false, err
		}
		if len(b) == 0 {
			return false, nil
		}
		return b[0] != 0, nil
	}
	errBytes, err := c.readBytes(valPtr, valLen)
	if err != nil {
		return false, err
	}
	return false, fmt.Errorf("gossip component error: %s", string(errBytes))
}
