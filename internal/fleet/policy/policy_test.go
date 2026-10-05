package policy

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
)

// --- Mock MQTT Client ---

type mockMQTTClient struct {
	mu        sync.Mutex
	connected bool
	published []mockMsg
	pubErr    error
}

type mockMsg struct {
	Topic   string
	Payload []byte
	QoS     byte
}

func (m *mockMQTTClient) Connect(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = true
	return nil
}

func (m *mockMQTTClient) Subscribe(_ context.Context, _ string, _ byte, _ func(mqtt.Message)) error {
	return nil
}

func (m *mockMQTTClient) Publish(_ context.Context, topic string, qos byte, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pubErr != nil {
		return m.pubErr
	}
	p := make([]byte, len(payload))
	copy(p, payload)
	m.published = append(m.published, mockMsg{Topic: topic, Payload: p, QoS: qos})
	return nil
}

func (m *mockMQTTClient) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *mockMQTTClient) getPublished() []mockMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]mockMsg, len(m.published))
	copy(result, m.published)
	return result
}

// --- Signer Tests ---

func TestHMACSignerSignVerifyRoundTrip(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-long!!")
	signer, err := NewHMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("policy blob data for signing test")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != 32 {
		t.Fatalf("signature length = %d, want 32", len(sig))
	}

	if err := signer.Verify(data, sig); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestHMACSignerVerifyRejectsWrongData(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-long!!")
	signer, err := NewHMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("original data")
	sig, _ := signer.Sign(data)

	if err := signer.Verify([]byte("tampered data"), sig); err == nil {
		t.Fatal("expected Verify to fail with tampered data")
	}
}

func TestHMACSignerVerifyRejectsWrongSignature(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-long!!")
	signer, err := NewHMACSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("some data")
	sig, _ := signer.Sign(data)

	// Flip a bit in the signature
	sig[0] ^= 0xFF

	if err := signer.Verify(data, sig); err == nil {
		t.Fatal("expected Verify to fail with corrupted signature")
	}
}

func TestHMACSignerEmptyKeyRejected(t *testing.T) {
	_, err := NewHMACSigner([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestHMACSignerFromEnvDevFallback(t *testing.T) {
	// Without DCLAW_OTA_SIGNING_KEY set, should use dev fallback
	signer, err := NewHMACSignerFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if err := signer.Verify(data, sig); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// --- PolicyStore Tests ---

func TestMemoryPolicyStoreSaveAndGet(t *testing.T) {
	store := NewMemoryPolicyStore()

	blob := []byte{0x00, 0x01, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}
	sig := []byte{0xDE, 0xAD}

	err := store.SavePolicy(1, 2, 1, blob, sig, "standard")
	if err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	latest, err := store.GetLatestPolicy(1, 2)
	if err != nil {
		t.Fatalf("GetLatestPolicy: %v", err)
	}
	if latest == nil {
		t.Fatal("expected non-nil latest policy")
	}
	if latest.Version != 1 {
		t.Errorf("Version = %d, want 1", latest.Version)
	}
	if latest.Profile != "standard" {
		t.Errorf("Profile = %q, want standard", latest.Profile)
	}
}

func TestMemoryPolicyStoreVersionConflict(t *testing.T) {
	store := NewMemoryPolicyStore()

	blob := []byte{0x00, 0x01}
	err := store.SavePolicy(1, 1, 5, blob, nil, "minimal")
	if err != nil {
		t.Fatal(err)
	}

	// Same version should fail
	err = store.SavePolicy(1, 1, 5, blob, nil, "minimal")
	if err == nil {
		t.Fatal("expected error for duplicate version")
	}
}

func TestMemoryPolicyStoreListVersions(t *testing.T) {
	store := NewMemoryPolicyStore()

	for v := uint32(1); v <= 5; v++ {
		blob := []byte{byte(v)}
		if err := store.SavePolicy(10, 20, v, blob, nil, "standard"); err != nil {
			t.Fatal(err)
		}
	}

	versions, err := store.ListVersions(10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 5 {
		t.Fatalf("len(versions) = %d, want 5", len(versions))
	}

	// Should be sorted descending
	for i := 0; i < len(versions)-1; i++ {
		if versions[i].Version <= versions[i+1].Version {
			t.Errorf("versions not sorted descending: %d <= %d at index %d",
				versions[i].Version, versions[i+1].Version, i)
		}
	}
}

func TestMemoryPolicyStoreLatestVersion(t *testing.T) {
	store := NewMemoryPolicyStore()

	store.SavePolicy(1, 1, 3, []byte{3}, nil, "standard")
	store.SavePolicy(1, 1, 1, []byte{1}, nil, "standard")
	store.SavePolicy(1, 1, 7, []byte{7}, nil, "standard")

	latest, err := store.GetLatestPolicy(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != 7 {
		t.Errorf("latest version = %d, want 7", latest.Version)
	}
}

func TestMemoryPolicyStoreGetPolicyNotFound(t *testing.T) {
	store := NewMemoryPolicyStore()

	rec, err := store.GetPolicy(1, 1, 99)
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		t.Fatal("expected nil for non-existent policy")
	}
}

func TestMemoryPolicyStoreMarkDistributed(t *testing.T) {
	store := NewMemoryPolicyStore()
	store.SavePolicy(1, 1, 1, []byte{0x01}, nil, "standard")

	if err := store.MarkDistributed(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	rec, _ := store.GetPolicy(1, 1, 1)
	if rec == nil {
		t.Fatal("expected policy record")
	}
	if !rec.Distributed {
		t.Error("expected Distributed=true after MarkDistributed")
	}
}

func TestMemoryPolicyStoreMarkDistributedNotFound(t *testing.T) {
	store := NewMemoryPolicyStore()

	err := store.MarkDistributed(1, 1, 99)
	if err == nil {
		t.Fatal("expected error for non-existent version")
	}
}

// --- PolicyHeader Tests ---

func TestParseHeader(t *testing.T) {
	blob := make([]byte, 8)
	binary.BigEndian.PutUint16(blob[0:2], 42)  // version
	binary.BigEndian.PutUint16(blob[2:4], 100) // payload_len
	binary.BigEndian.PutUint16(blob[4:6], 5)   // canary_baseline

	hdr, err := ParseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Version != 42 {
		t.Errorf("Version = %d, want 42", hdr.Version)
	}
	if hdr.PayloadLen != 100 {
		t.Errorf("PayloadLen = %d, want 100", hdr.PayloadLen)
	}
	if hdr.CanaryBaseline != 5 {
		t.Errorf("CanaryBaseline = %d, want 5", hdr.CanaryBaseline)
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestBuildPolicyBlob(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	blob := BuildPolicyBlob(10, 5, payload)

	if len(blob) != HeaderSize+len(payload) {
		t.Fatalf("blob length = %d, want %d", len(blob), HeaderSize+len(payload))
	}

	hdr, err := ParseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Version != 10 {
		t.Errorf("Version = %d, want 10", hdr.Version)
	}
	if hdr.PayloadLen != 3 {
		t.Errorf("PayloadLen = %d, want 3", hdr.PayloadLen)
	}
	if hdr.CanaryBaseline != 5 {
		t.Errorf("CanaryBaseline = %d, want 5", hdr.CanaryBaseline)
	}
}

// --- Service Tests ---

func newTestService() (*Service, *mockMQTTClient, *MemoryPolicyStore) {
	mc := &mockMQTTClient{}
	store := NewMemoryPolicyStore()
	signer, _ := NewHMACSigner([]byte("test-key-for-unit-tests-32bytes!"))

	svc := NewService(store, signer, mc, &Config{
		CompilerPath: "", // disable compiler for unit tests
	})
	return svc, mc, store
}

func TestServiceSign(t *testing.T) {
	svc, _, _ := newTestService()

	blob := BuildPolicyBlob(1, 5, []byte{0x01, 0x02, 0x03})
	signed, err := svc.Sign(blob)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Signed blob = original blob + 32 bytes HMAC
	expectedLen := len(blob) + 32
	if len(signed) != expectedLen {
		t.Fatalf("signed length = %d, want %d", len(signed), expectedLen)
	}

	// Verify the signature portion
	sig := signed[len(blob):]
	if err := svc.signer.Verify(blob, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestServiceSignTooShort(t *testing.T) {
	svc, _, _ := newTestService()

	_, err := svc.Sign([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestServiceDistribute(t *testing.T) {
	svc, mc, _ := newTestService()
	mc.Connect(context.Background())

	blob := BuildPolicyBlob(5, 3, []byte{0xAA, 0xBB})
	signed, _ := svc.Sign(blob)

	err := svc.Distribute(context.Background(), 1, 2, signed)
	if err != nil {
		t.Fatalf("Distribute: %v", err)
	}

	published := mc.getPublished()
	if len(published) != 1 {
		t.Fatalf("published = %d, want 1", len(published))
	}

	expectedTopic := "defenseclaw/1/2/ota/policy"
	if published[0].Topic != expectedTopic {
		t.Errorf("topic = %q, want %q", published[0].Topic, expectedTopic)
	}

	if published[0].QoS != 1 {
		t.Errorf("QoS = %d, want 1", published[0].QoS)
	}
}

func TestServiceDistributeTooShort(t *testing.T) {
	svc, _, _ := newTestService()
	err := svc.Distribute(context.Background(), 1, 1, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for too-short signed policy")
	}
}

func TestServiceDistributePublishError(t *testing.T) {
	svc, mc, _ := newTestService()
	mc.pubErr = fmt.Errorf("broker unreachable")

	blob := BuildPolicyBlob(1, 5, []byte{0x01})
	signed, _ := svc.Sign(blob)

	err := svc.Distribute(context.Background(), 1, 1, signed)
	if err == nil {
		t.Fatal("expected error when MQTT publish fails")
	}
}

func TestServiceDistributeEmergency(t *testing.T) {
	svc, mc, _ := newTestService()
	mc.Connect(context.Background())

	err := svc.DistributeEmergency(context.Background(), 10, 20, EmergencyFlushCache)
	if err != nil {
		t.Fatalf("DistributeEmergency: %v", err)
	}

	published := mc.getPublished()
	if len(published) != 1 {
		t.Fatalf("published = %d, want 1", len(published))
	}

	expectedTopic := "defenseclaw/10/20/ota/emergency"
	if published[0].Topic != expectedTopic {
		t.Errorf("topic = %q, want %q", published[0].Topic, expectedTopic)
	}

	msg := published[0].Payload
	if len(msg) != EmergencyMsgSize {
		t.Fatalf("message size = %d, want %d", len(msg), EmergencyMsgSize)
	}

	// Verify sequence = 1 (first call)
	seq := binary.BigEndian.Uint32(msg[0:4])
	if seq != 1 {
		t.Errorf("sequence = %d, want 1", seq)
	}

	// Verify command byte
	if msg[8] != uint8(EmergencyFlushCache) {
		t.Errorf("command = %d, want %d", msg[8], EmergencyFlushCache)
	}

	// Verify signature over first 44 bytes
	if err := svc.signer.Verify(msg[:44], msg[44:76]); err != nil {
		t.Fatalf("emergency signature verification failed: %v", err)
	}
}

func TestServiceDistributeEmergencySequenceIncreases(t *testing.T) {
	svc, mc, _ := newTestService()
	mc.Connect(context.Background())

	for i := 0; i < 5; i++ {
		if err := svc.DistributeEmergency(context.Background(), 1, 1, EmergencyEnterLockdown); err != nil {
			t.Fatalf("emergency %d: %v", i, err)
		}
	}

	published := mc.getPublished()
	if len(published) != 5 {
		t.Fatalf("published = %d, want 5", len(published))
	}

	for i, msg := range published {
		seq := binary.BigEndian.Uint32(msg.Payload[0:4])
		expectedSeq := uint32(i + 1)
		if seq != expectedSeq {
			t.Errorf("message %d: seq = %d, want %d", i, seq, expectedSeq)
		}
	}
}

func TestServiceDistributeEmergencyPublishError(t *testing.T) {
	svc, mc, _ := newTestService()
	mc.pubErr = fmt.Errorf("connection lost")

	err := svc.DistributeEmergency(context.Background(), 1, 1, EmergencyFlushCache)
	if err == nil {
		t.Fatal("expected error when MQTT publish fails")
	}
}

func TestServiceDistributeEmergencyAllCommands(t *testing.T) {
	cmds := []EmergencyCommand{
		EmergencyFlushCache,
		EmergencyRevokeSessions,
		EmergencyEnterLockdown,
	}

	for _, cmd := range cmds {
		svc, mc, _ := newTestService()
		mc.Connect(context.Background())

		if err := svc.DistributeEmergency(context.Background(), 1, 1, cmd); err != nil {
			t.Fatalf("cmd %d: %v", cmd, err)
		}

		published := mc.getPublished()
		if published[0].Payload[8] != uint8(cmd) {
			t.Errorf("cmd %d: payload command = %d", cmd, published[0].Payload[8])
		}
	}
}

// --- Full round-trip: build blob, sign, verify, distribute ---

func TestFullSignDistributeRoundTrip(t *testing.T) {
	svc, mc, store := newTestService()
	mc.Connect(context.Background())

	// Build a policy blob manually (no Python compiler needed)
	payload := []byte{
		0x02,       // 2 severity rules
		0x04, 0x01, // critical -> block
		0x03, 0x01, // high -> block
		0x00,                               // 0 sequence rules
		0x01,                               // 1 destination
		0x0F,                               // length 15
		'a', 'p', 'i', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, // content_inspection disabled
		0x00, // 0 content rules
		0x00, // no SSRF flags
	}
	blob := BuildPolicyBlob(1, 5, payload)

	// Sign
	signed, err := svc.Sign(blob)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Store
	sig := signed[len(blob):]
	if err := store.SavePolicy(1, 1, 1, blob, sig, "standard"); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	// Distribute
	if err := svc.Distribute(context.Background(), 1, 1, signed); err != nil {
		t.Fatalf("Distribute: %v", err)
	}

	// Verify what was published
	published := mc.getPublished()
	if len(published) != 1 {
		t.Fatalf("published = %d, want 1", len(published))
	}

	// Parse the header from published payload
	hdr, err := ParseHeader(published[0].Payload)
	if err != nil {
		t.Fatalf("ParseHeader on published: %v", err)
	}
	if hdr.Version != 1 {
		t.Errorf("published version = %d, want 1", hdr.Version)
	}

	// Verify the HMAC in the published payload
	pubBlob := published[0].Payload[:len(blob)]
	pubSig := published[0].Payload[len(blob):]
	if err := svc.signer.Verify(pubBlob, pubSig); err != nil {
		t.Fatalf("published signature verification failed: %v", err)
	}

	// Mark distributed
	if err := store.MarkDistributed(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	rec, _ := store.GetPolicy(1, 1, 1)
	if !rec.Distributed {
		t.Error("expected Distributed=true")
	}
}

// --- Hex decoder tests ---

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
		err   bool
	}{
		{"deadbeef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"DEADBEEF", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"00ff", []byte{0x00, 0xff}, false},
		{"", []byte{}, false},
		{"0", nil, true},   // odd length
		{"zz", nil, true},  // invalid char
	}

	for _, tc := range tests {
		got, err := decodeHex(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("decodeHex(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("decodeHex(%q) error: %v", tc.input, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("decodeHex(%q) len = %d, want %d", tc.input, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("decodeHex(%q)[%d] = %02x, want %02x", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
