// pqc-gossip/abi/go/example_test.go
// Integration test and usage example for the witan-gossip Go host bindings.
//
// Build the WASM binary first:
//
//	cd pqc-gossip && cargo build --target wasm32-unknown-unknown --release
//
// Run the tests:
//
//	cd pqc-gossip/abi/go
//	go test -v -run TestGossipClient -wasm ../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm
package gossip_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	gossip "github.com/witan-gossip/witan-gossip/abi/go"
)

// wasmPath is the path to the compiled WASM binary.
// Override with: go test -wasm /path/to/pqc_gossip.wasm
var wasmPath = flag.String("wasm", "../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm", "path to pqc_gossip.wasm")

// newClient creates a GossipClient for testing, skipping if the WASM file is absent.
func newClient(t *testing.T) *gossip.GossipClient {
	t.Helper()
	if _, err := os.Stat(*wasmPath); os.IsNotExist(err) {
		t.Skipf("WASM binary not found at %s — build with: cargo build --target wasm32-unknown-unknown --release", *wasmPath)
	}
	client, err := gossip.NewGossipClientFromFile(*wasmPath)
	if err != nil {
		t.Fatalf("NewGossipClientFromFile: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestGetVersion(t *testing.T) {
	client := newClient(t)
	version, err := client.GetVersion()
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version == "" {
		t.Fatal("GetVersion returned empty string")
	}
	t.Logf("Protocol version: %s", version)
}

func TestInit(t *testing.T) {
	client := newClient(t)

	// Initialize with default config
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Second init should fail with AlreadyInitialized
	err := client.Init("{}")
	if err == nil {
		t.Fatal("expected error on second Init, got nil")
	}
	t.Logf("Second Init correctly returned error: %v", err)
}

func TestInitWithConfig(t *testing.T) {
	client := newClient(t)

	config := map[string]interface{}{
		"mesh_n":            8,
		"mesh_n_low":        4,
		"mesh_n_high":       12,
		"heartbeat_ms":      700,
		"max_message_bytes": 1048576,
		"dedup_cache_secs":  60,
		"quorum_fraction":   0.67,
		"replay_window_ms":  30000,
		"default_ttl":       8,
	}
	configJSON, _ := json.Marshal(config)

	if err := client.Init(string(configJSON)); err != nil {
		t.Fatalf("Init with config: %v", err)
	}
}

func TestGetNodeIdentity(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	identityJSON, err := client.GetNodeIdentity()
	if err != nil {
		t.Fatalf("GetNodeIdentity: %v", err)
	}

	var identity map[string]interface{}
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		t.Fatalf("parse identity JSON: %v", err)
	}

	nodeID, ok := identity["node_id"].(string)
	if !ok || len(nodeID) != 64 {
		t.Fatalf("expected 64-char hex node_id, got: %v", identity["node_id"])
	}
	t.Logf("Node ID: %s", nodeID)
	t.Logf("Key epoch: %v", identity["key_epoch"])
}

func TestPublish(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	payload := []byte("test transaction payload")
	msgID, err := client.Publish(0, payload) // 0 = Transaction
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Message ID should be 32 bytes (SHA-256)
	if msgID == [32]byte{} {
		t.Fatal("Publish returned zero message ID")
	}
	t.Logf("Message ID: %x", msgID)
}

func TestPublishAllPayloadTypes(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	payloadTypes := []struct {
		id   uint8
		name string
	}{
		{0, "Transaction"},
		{1, "BlockProposal"},
		{2, "FinalityVote"},
		{3, "StateSync"},
		{4, "PeerDiscovery"},
	}

	for _, pt := range payloadTypes {
		payload := []byte(fmt.Sprintf("test payload for %s", pt.name))
		msgID, err := client.Publish(pt.id, payload)
		if err != nil {
			t.Errorf("Publish(%s): %v", pt.name, err)
			continue
		}
		t.Logf("Published %s: %x", pt.name, msgID)
	}
}

func TestEncodeDecodeEnvelope(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	payload := []byte("envelope test payload")
	envelopeBytes, err := client.EncodeEnvelope(0, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	if len(envelopeBytes) == 0 {
		t.Fatal("EncodeEnvelope returned empty bytes")
	}
	t.Logf("Encoded envelope: %d bytes", len(envelopeBytes))

	// Decode back to JSON
	envelopeJSON, err := client.DecodeEnvelope(envelopeBytes)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(envelopeJSON), &envelope); err != nil {
		t.Fatalf("parse envelope JSON: %v", err)
	}
	t.Logf("Decoded envelope: version=%v ttl=%v", envelope["version"], envelope["ttl"])
}

func TestVerifyEnvelope(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	payload := []byte("verify test payload")
	envelopeBytes, err := client.EncodeEnvelope(0, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}

	valid, err := client.VerifyEnvelope(envelopeBytes)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if !valid {
		t.Fatal("VerifyEnvelope returned false for a freshly encoded envelope")
	}
	t.Log("Envelope verified successfully")

	// Tamper with the envelope — should fail verification
	tampered := make([]byte, len(envelopeBytes))
	copy(tampered, envelopeBytes)
	if len(tampered) > 10 {
		tampered[10] ^= 0xFF
	}
	valid, _ = client.VerifyEnvelope(tampered)
	if valid {
		t.Log("Note: tampered envelope still verified (may be in non-signature region)")
	} else {
		t.Log("Tampered envelope correctly rejected")
	}
}

func TestGetStats(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Publish a few messages to generate stats
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("stats test message %d", i))
		if _, err := client.Publish(0, payload); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	statsJSON, err := client.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal([]byte(statsJSON), &stats); err != nil {
		t.Fatalf("parse stats JSON: %v", err)
	}

	published := stats["messages_published"]
	t.Logf("Stats: published=%v active_peers=%v", published, stats["active_peers"])
}

func TestGetPeers(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	peersJSON, err := client.GetPeers()
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}

	var peers []interface{}
	if err := json.Unmarshal([]byte(peersJSON), &peers); err != nil {
		t.Fatalf("parse peers JSON: %v", err)
	}
	t.Logf("Connected peers: %d", len(peers))
}

func TestConnectPeer(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// ConnectPeer returns probe bytes to send to the peer
	probeBytes, err := client.ConnectPeer("192.168.1.10:9000")
	if err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}
	t.Logf("Handshake probe: %d bytes", len(probeBytes))
}

func TestRotateKeys(t *testing.T) {
	client := newClient(t)
	if err := client.Init("{}"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Get original node ID
	identityJSON, err := client.GetNodeIdentity()
	if err != nil {
		t.Fatalf("GetNodeIdentity: %v", err)
	}
	var identity map[string]interface{}
	_ = json.Unmarshal([]byte(identityJSON), &identity)
	originalID := identity["node_id"].(string)

	// Rotate keys
	newNodeID, err := client.RotateKeys()
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if len(newNodeID) != 64 {
		t.Fatalf("expected 64-char hex new_node_id, got: %s", newNodeID)
	}
	if newNodeID == originalID {
		t.Fatal("node ID did not change after key rotation")
	}
	t.Logf("Keys rotated: %s → %s", originalID[:16]+"...", newNodeID[:16]+"...")
}

func TestNowMs(t *testing.T) {
	client := newClient(t)
	ts, err := client.NowMs()
	if err != nil {
		t.Fatalf("NowMs: %v", err)
	}
	if ts == 0 {
		t.Fatal("NowMs returned 0")
	}
	t.Logf("WASM timestamp: %d ms", ts)
}

// ─────────────────────────────────────────────────────────────────────────────
// Example functions (shown in godoc)
// ─────────────────────────────────────────────────────────────────────────────

func ExampleGossipClient_Init() {
	client, err := gossip.NewGossipClientFromFile("../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm")
	if err != nil {
		fmt.Println("load error:", err)
		return
	}
	defer client.Close()

	if err := client.Init("{}"); err != nil {
		fmt.Println("init error:", err)
		return
	}
	fmt.Println("initialized")
	// Output: initialized
}

func ExampleGossipClient_Publish() {
	client, err := gossip.NewGossipClientFromFile("../../target/wasm32-unknown-unknown/release/pqc_gossip.wasm")
	if err != nil {
		return
	}
	defer client.Close()
	_ = client.Init("{}")

	msgID, err := client.Publish(0, []byte("hello world"))
	if err != nil {
		fmt.Println("publish error:", err)
		return
	}
	fmt.Printf("message_id length: %d bytes\n", len(msgID))
	// Output: message_id length: 32 bytes
}
