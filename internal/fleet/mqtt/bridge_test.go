package mqtt

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// --- Mock MQTT Client ---

type mockClient struct {
	mu           sync.Mutex
	connected    bool
	handlers     map[string]func(Message)
	published    []Message
	connectErr   error
	subscribeErr error
	publishErr   error
}

func newMockClient() *mockClient {
	return &mockClient{
		handlers: make(map[string]func(Message)),
	}
}

func (m *mockClient) Connect(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockClient) Subscribe(_ context.Context, topicFilter string, _ byte, handler func(Message)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subscribeErr != nil {
		return m.subscribeErr
	}
	m.handlers[topicFilter] = handler
	return nil
}

func (m *mockClient) Publish(_ context.Context, topic string, qos byte, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.publishErr != nil {
		return m.publishErr
	}
	m.published = append(m.published, Message{Topic: topic, Payload: payload, QoS: qos})
	return nil
}

func (m *mockClient) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

// simulateMessage dispatches a message to the registered handler that matches the topic filter.
func (m *mockClient) simulateMessage(topic string, payload []byte, qos byte) {
	m.mu.Lock()
	// Find the handler that matches - try exact match first, then wildcard matching
	var handler func(Message)
	for filter, h := range m.handlers {
		if topicMatchesFilter(topic, filter) {
			handler = h
			break
		}
	}
	m.mu.Unlock()

	if handler != nil {
		handler(Message{Topic: topic, Payload: payload, QoS: qos})
	}
}

func (m *mockClient) getPublished() []Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Message, len(m.published))
	copy(result, m.published)
	return result
}

// topicMatchesFilter does simple MQTT wildcard matching for + (single level).
func topicMatchesFilter(topic, filter string) bool {
	if topic == filter {
		return true
	}

	tParts := splitTopic(topic)
	fParts := splitTopic(filter)

	if len(tParts) != len(fParts) {
		return false
	}

	for i, fp := range fParts {
		if fp == "+" {
			continue
		}
		if fp != tParts[i] {
			return false
		}
	}
	return true
}

func splitTopic(t string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '/' {
			parts = append(parts, t[start:i])
			start = i + 1
		}
	}
	parts = append(parts, t[start:])
	return parts
}

// --- Helper functions ---

func makeHeartbeatPayload(deviceID uint32, policyVer uint16, deniedCount uint16, flags uint8) []byte {
	data := make([]byte, 32)
	binary.BigEndian.PutUint32(data[0:4], deviceID)
	binary.BigEndian.PutUint32(data[4:8], 3600) // uptime
	binary.BigEndian.PutUint16(data[8:10], policyVer)
	binary.BigEndian.PutUint16(data[10:12], 1) // fw_version
	binary.BigEndian.PutUint16(data[12:14], deniedCount)
	binary.BigEndian.PutUint16(data[14:16], 100)    // allowed
	binary.BigEndian.PutUint16(data[16:18], 5)      // warned
	binary.BigEndian.PutUint16(data[18:20], 2)      // escalated
	data[20] = 85                                   // cache_hit_pct
	data[21] = 3                                    // session_count
	binary.BigEndian.PutUint64(data[22:30], 0xDEAD) // audit hmac
	data[30] = flags
	data[31] = 0 // reserved
	return data
}

func makeVerdictRequestPayload(requestID uint16, toolName string) []byte {
	vr := &VerdictRequest{
		RequestID:    requestID,
		ToolHash:     [32]byte{0xAA, 0xBB, 0xCC},
		ToolName:     toolName,
		CapFlags:     0x04, // EXEC_SHELL
		SessionRisk:  2,
		SessionCaps:  0x04,
		Destination:  "api.example.com",
		Direction:    0, // REQUEST
		ContentScope: 2, // USER_INPUT
		Content:      "test content",
		Findings:     0,
	}
	return EncodeVerdictRequestCBOR(vr)
}

// --- Tests ---

func TestParseTopicValid(t *testing.T) {
	tests := []struct {
		topic  string
		tenant uint16
		fleet  uint16
		device uint32
		suffix string
	}{
		{"defenseclaw/1/2/42/heartbeat", 1, 2, 42, "heartbeat"},
		{"defenseclaw/100/200/999/verdict/req", 100, 200, 999, "verdict/req"},
		{"defenseclaw/0/0/0/heartbeat", 0, 0, 0, "heartbeat"},
	}

	for _, tc := range tests {
		parts, err := ParseTopic(tc.topic)
		if err != nil {
			t.Fatalf("ParseTopic(%q) error: %v", tc.topic, err)
		}
		if parts.TenantID != tc.tenant {
			t.Errorf("tenant = %d, want %d", parts.TenantID, tc.tenant)
		}
		if parts.FleetID != tc.fleet {
			t.Errorf("fleet = %d, want %d", parts.FleetID, tc.fleet)
		}
		if parts.DeviceID != tc.device {
			t.Errorf("device = %d, want %d", parts.DeviceID, tc.device)
		}
		if parts.Suffix != tc.suffix {
			t.Errorf("suffix = %q, want %q", parts.Suffix, tc.suffix)
		}
	}
}

func TestParseTopicInvalid(t *testing.T) {
	bad := []string{
		"other/1/2/3/heartbeat",
		"defenseclaw/abc/2/3/heartbeat",
		"defenseclaw/1/abc/3/heartbeat",
		"defenseclaw/1/2/abc/heartbeat",
		"defenseclaw/1/2",
		"",
	}
	for _, topic := range bad {
		_, err := ParseTopic(topic)
		if err == nil {
			t.Errorf("ParseTopic(%q) should have failed", topic)
		}
	}
}

func TestDecodeHeartbeat(t *testing.T) {
	payload := makeHeartbeatPayload(42, 5, 10, 0)
	hw, err := DecodeHeartbeat(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hw.DeviceID != 42 {
		t.Errorf("DeviceID = %d, want 42", hw.DeviceID)
	}
	if hw.PolicyVersion != 5 {
		t.Errorf("PolicyVersion = %d, want 5", hw.PolicyVersion)
	}
	if hw.DeniedCount != 10 {
		t.Errorf("DeniedCount = %d, want 10", hw.DeniedCount)
	}
	if hw.CacheHitPct != 85 {
		t.Errorf("CacheHitPct = %d, want 85", hw.CacheHitPct)
	}
}

func TestDecodeHeartbeatBadSize(t *testing.T) {
	_, err := DecodeHeartbeat(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte heartbeat")
	}
}

func TestVerdictRequestRoundTrip(t *testing.T) {
	orig := &VerdictRequest{
		RequestID:    1234,
		ToolHash:     [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		ToolName:     "curl",
		CapFlags:     0x08,
		SessionRisk:  3,
		SessionCaps:  0x0C,
		Destination:  "evil.com",
		Direction:    0,
		ContentScope: 2,
		Content:      "GET /secrets",
		Findings:     0x01,
	}

	encoded := EncodeVerdictRequestCBOR(orig)
	decoded, err := DecodeVerdictRequest(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if decoded.RequestID != orig.RequestID {
		t.Errorf("RequestID = %d, want %d", decoded.RequestID, orig.RequestID)
	}
	if decoded.ToolHash != orig.ToolHash {
		t.Error("ToolHash mismatch")
	}
	if decoded.ToolName != orig.ToolName {
		t.Errorf("ToolName = %q, want %q", decoded.ToolName, orig.ToolName)
	}
	if decoded.CapFlags != orig.CapFlags {
		t.Errorf("CapFlags = %d, want %d", decoded.CapFlags, orig.CapFlags)
	}
	if decoded.Destination != orig.Destination {
		t.Errorf("Destination = %q, want %q", decoded.Destination, orig.Destination)
	}
	if decoded.Content != orig.Content {
		t.Errorf("Content = %q, want %q", decoded.Content, orig.Content)
	}
}

func TestEncodeVerdictResponse(t *testing.T) {
	resp := &VerdictResponse{
		RequestID: 0x0102,
		Action:    1, // Block
		Severity:  3, // High
		TTL:       120,
		Reason:    6, // Cloud block
		Flags:     0,
		ServerTS:  1700000000,
		HMACTag:   [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	data := EncodeVerdictResponse(resp)
	if len(data) != 16 {
		t.Fatalf("response length = %d, want 16", len(data))
	}

	if binary.BigEndian.Uint16(data[0:2]) != 0x0102 {
		t.Error("request_id mismatch")
	}
	if data[2] != 1 {
		t.Errorf("action = %d, want 1", data[2])
	}
	if data[3] != 3 {
		t.Errorf("severity = %d, want 3", data[3])
	}
}

func TestBridgeHeartbeatRouting(t *testing.T) {
	mc := newMockClient()
	fm := manager.New(nil)
	fm.RegisterDevice(1, 2, 42, "sbc", "1.0.0", 1, 0xFF)

	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	bridge := NewBridge(mc, fm, cache)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	// Give the bridge time to subscribe
	time.Sleep(50 * time.Millisecond)

	// Simulate a heartbeat from device 42 in tenant=1, fleet=2
	payload := makeHeartbeatPayload(42, 7, 15, 0)
	mc.simulateMessage("defenseclaw/1/2/42/heartbeat", payload, 0)

	// Give the handler time to process
	time.Sleep(50 * time.Millisecond)

	// Verify the heartbeat was processed
	hb, verds, errs := bridge.Stats()
	if hb != 1 {
		t.Errorf("heartbeats processed = %d, want 1", hb)
	}
	if verds != 0 {
		t.Errorf("verdicts processed = %d, want 0", verds)
	}
	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}

	// Verify the fleet manager received it
	dev, ok := fm.GetDevice(manager.ComposeID(1, 2, 42))
	if !ok {
		t.Fatal("device not found after heartbeat")
	}
	if dev.PolicyVersion != 7 {
		t.Errorf("PolicyVersion = %d, want 7", dev.PolicyVersion)
	}

	cancel()
	<-errCh
}

func TestBridgeVerdictRequestRouting(t *testing.T) {
	mc := newMockClient()
	fm := manager.New(nil)
	fm.RegisterDevice(10, 20, 100, "mcu", "2.0.0", 1, 0x0F)

	pipelineCalled := false
	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		pipelineCalled = true
		return verdict.ActionBlock, 3 // Block with high severity
	})

	bridge := NewBridge(mc, fm, cache)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Simulate a verdict request
	payload := makeVerdictRequestPayload(42, "wget")
	mc.simulateMessage("defenseclaw/10/20/100/verdict/req", payload, 1)

	time.Sleep(50 * time.Millisecond)

	_, verds, errs := bridge.Stats()
	if verds != 1 {
		t.Errorf("verdicts processed = %d, want 1", verds)
	}
	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}
	if !pipelineCalled {
		t.Error("pipeline was not called for cache miss")
	}

	// Check that a response was published
	published := mc.getPublished()
	if len(published) != 1 {
		t.Fatalf("published messages = %d, want 1", len(published))
	}

	expectedTopic := "defenseclaw/10/20/100/verdict/resp"
	if published[0].Topic != expectedTopic {
		t.Errorf("response topic = %q, want %q", published[0].Topic, expectedTopic)
	}
	if len(published[0].Payload) != 16 {
		t.Errorf("response payload length = %d, want 16", len(published[0].Payload))
	}

	// Verify response content
	respPayload := published[0].Payload
	if respPayload[2] != 1 { // Action = Block
		t.Errorf("response action = %d, want 1 (Block)", respPayload[2])
	}
	if respPayload[3] != 3 { // Severity = High
		t.Errorf("response severity = %d, want 3 (High)", respPayload[3])
	}

	cancel()
	<-errCh
}

func TestBridgeHandlesDecodeError(t *testing.T) {
	mc := newMockClient()
	fm := manager.New(nil)
	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	bridge := NewBridge(mc, fm, cache)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Send a malformed heartbeat (wrong size)
	mc.simulateMessage("defenseclaw/1/1/1/heartbeat", []byte{0x01, 0x02}, 0)

	time.Sleep(50 * time.Millisecond)

	_, _, errs := bridge.Stats()
	if errs != 1 {
		t.Errorf("errors = %d, want 1", errs)
	}

	cancel()
	<-errCh
}

func TestBridgeConnectError(t *testing.T) {
	mc := newMockClient()
	mc.connectErr = fmt.Errorf("connection refused")

	fm := manager.New(nil)
	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	bridge := NewBridge(mc, fm, cache)

	err := bridge.Start(context.Background())
	if err == nil {
		t.Fatal("expected error from Start when connect fails")
	}
}

func TestBridgeStop(t *testing.T) {
	mc := newMockClient()
	fm := manager.New(nil)
	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	bridge := NewBridge(mc, fm, cache)

	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // Stop will call its own cancel

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Stop should trigger shutdown
	bridge.Stop()

	select {
	case <-errCh:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("bridge.Start did not return after Stop()")
	}

	mc.mu.Lock()
	connected := mc.connected
	mc.mu.Unlock()
	if connected {
		t.Error("client should be disconnected after Stop()")
	}
}

func TestBridgeMultipleHeartbeats(t *testing.T) {
	mc := newMockClient()
	fm := manager.New(nil)
	fm.RegisterDevice(1, 1, 1, "sbc", "1.0.0", 1, 0xFF)
	fm.RegisterDevice(1, 1, 2, "mcu", "1.0.0", 1, 0x0F)

	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	bridge := NewBridge(mc, fm, cache)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Send heartbeats for both devices
	for i := 0; i < 10; i++ {
		deviceID := uint32(1 + i%2)
		payload := makeHeartbeatPayload(deviceID, uint16(5+i), uint16(i), 0)
		mc.simulateMessage(
			fmt.Sprintf("defenseclaw/1/1/%d/heartbeat", deviceID),
			payload, 0,
		)
	}

	time.Sleep(100 * time.Millisecond)

	hb, _, errs := bridge.Stats()
	if hb != 10 {
		t.Errorf("heartbeats processed = %d, want 10", hb)
	}
	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}

	cancel()
	<-errCh
}
