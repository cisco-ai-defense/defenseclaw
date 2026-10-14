package fleet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	fleetmqtt "github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

const testFleetToken = "test-token-for-fleet-api"

// authedRequest creates an httptest request with the fleet API Bearer token.
func authedRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer "+testFleetToken)
	if method == "POST" {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	return req
}

func setupAPIWithT(t *testing.T) *API {
	t.Helper()
	t.Setenv("DCLAW_FLEET_API_TOKEN", testFleetToken)

	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(_, _ uint16, h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	return NewAPI(context.Background(), mgr, cache)
}

func TestGetFleetHealth(t *testing.T) {
	api := setupAPIWithT(t)
	req := authedRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"total_devices":1`) {
		t.Fatalf("response missing total_devices: %s", w.Body.String())
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	api := setupAPIWithT(t)
	req := authedRequest("GET", "/devices/999", nil)
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetDeviceInvalidID(t *testing.T) {
	api := setupAPIWithT(t)
	req := authedRequest("GET", "/devices/invalid", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid id", w.Code)
	}
}

func TestPushThreatIntel(t *testing.T) {
	api := setupAPIWithT(t)
	// Use valid 64-char hex strings (32 bytes decoded)
	hash := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	body := `{"new_deny_hashes":["abc123"],"revoke_allow_hashes":["` + hash + `"],"emergency":false}`
	req := authedRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
}

func TestPushThreatIntelInvalidHex(t *testing.T) {
	api := setupAPIWithT(t)
	body := `{"new_deny_hashes":[],"revoke_allow_hashes":["not-valid-hex"],"emergency":false}`
	req := authedRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid hex", w.Code)
	}
}

func TestPushThreatIntelWrongLength(t *testing.T) {
	api := setupAPIWithT(t)
	// Valid hex but only 4 bytes, not 32
	body := `{"new_deny_hashes":[],"revoke_allow_hashes":["deadbeef"],"emergency":false}`
	req := authedRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for wrong hash length", w.Code)
	}
}

func TestSendCommand(t *testing.T) {
	api := setupAPIWithT(t)
	// Device 42 in tenant=1, fleet=1 has composite ID = ComposeID(1, 1, 42)
	devID := manager.ComposeID(1, 1, 42)
	body := `{"command":"reboot"}`
	req := authedRequest("POST", fmt.Sprintf("/devices/%d/command", devID), strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	// Without an MQTT client, the command cannot be dispatched.
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body: %s", w.Code, w.Body.String())
	}
}

func TestSendCommandNotFound(t *testing.T) {
	api := setupAPIWithT(t)
	body := `{"command":"reboot"}`
	req := authedRequest("POST", "/devices/999/command", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestSendCommandInvalid(t *testing.T) {
	api := setupAPIWithT(t)
	devID := manager.ComposeID(1, 1, 42)
	body := `{"command":"self-destruct"}`
	req := authedRequest("POST", fmt.Sprintf("/devices/%d/command", devID), strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSendCommandEmpty(t *testing.T) {
	api := setupAPIWithT(t)
	devID := manager.ComposeID(1, 1, 42)
	body := `{"command":""}`
	req := authedRequest("POST", fmt.Sprintf("/devices/%d/command", devID), strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSendCommandWithMQTT(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", testFleetToken)
	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(_, _ uint16, h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	mc := &apiMockMQTTClient{}
	api := NewAPI(context.Background(), mgr, cache, WithMQTTClient(mc))

	devID := manager.ComposeID(1, 1, 42)
	body := `{"command":"diagnostics"}`
	req := authedRequest("POST", fmt.Sprintf("/devices/%d/command", devID), strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body: %s", w.Code, w.Body.String())
	}

	mc.mu.Lock()
	pubs := len(mc.published)
	mc.mu.Unlock()
	if pubs != 1 {
		t.Fatalf("published messages = %d, want 1", pubs)
	}

	mc.mu.Lock()
	topic := mc.published[0].Topic
	mc.mu.Unlock()
	expected := "defenseclaw/1/1/42/cmd/request"
	if topic != expected {
		t.Fatalf("topic = %q, want %q", topic, expected)
	}
}

func TestDecommissionBatch(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", testFleetToken)
	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 10, "sbc", "1.0.0", 5, 0xFF)
	mgr.RegisterDevice(1, 1, 20, "mcu", "1.0.0", 5, 0x0F)
	mgr.RegisterDevice(1, 1, 30, "sbc", "2.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(_, _ uint16, h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	api := NewAPI(context.Background(), mgr, cache)

	body := `{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":10},{"tenant_id":1,"fleet_id":1,"device_id":20},{"tenant_id":1,"fleet_id":1,"device_id":999}]}`
	req := authedRequest("POST", "/devices/decommission-batch", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"decommissioned":2`) {
		t.Fatalf("expected 2 decommissioned: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"not_found"`) {
		t.Fatalf("expected not_found in response: %s", w.Body.String())
	}

	// Verify devices are actually removed
	devices := mgr.ListDevices()
	if len(devices) != 1 {
		t.Fatalf("remaining devices = %d, want 1", len(devices))
	}
}

func TestDecommissionBatchEmpty(t *testing.T) {
	api := setupAPIWithT(t)
	body := `{"devices":[]}`
	req := authedRequest("POST", "/devices/decommission-batch", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestListDevicesReturnsList(t *testing.T) {
	api := setupAPIWithT(t)
	req := authedRequest("GET", "/devices", nil)
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Must contain both "devices" array and "summary" object
	if !strings.Contains(w.Body.String(), `"devices"`) {
		t.Fatalf("response missing devices key: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"summary"`) {
		t.Fatalf("response missing summary key: %s", w.Body.String())
	}
}

// --- Mock MQTT Client for API tests ---

type apiMockMQTTClient struct {
	mu        sync.Mutex
	published []struct {
		Topic   string
		Payload []byte
	}
}

func (m *apiMockMQTTClient) Connect(_ context.Context) error { return nil }
func (m *apiMockMQTTClient) Subscribe(_ context.Context, _ string, _ byte, _ func(fleetmqtt.Message)) error {
	return nil
}
func (m *apiMockMQTTClient) Publish(_ context.Context, topic string, _ byte, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := make([]byte, len(payload))
	copy(p, payload)
	m.published = append(m.published, struct {
		Topic   string
		Payload []byte
	}{Topic: topic, Payload: p})
	return nil
}
func (m *apiMockMQTTClient) Disconnect() error { return nil }

func setupAPIWithPolicyT(t *testing.T) *API {
	t.Helper()
	t.Setenv("DCLAW_FLEET_API_TOKEN", testFleetToken)

	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(_, _ uint16, h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	mc := &apiMockMQTTClient{}
	store := policy.NewMemoryPolicyStore()
	signer, _ := policy.NewHMACSigner([]byte("test-key-for-api-tests-32bytes!!"))
	svc := policy.NewService(store, signer, mc, nil)

	return NewAPI(context.Background(), mgr, cache, WithPolicyService(svc))
}

func TestPolicyVersionsEndpoint(t *testing.T) {
	api := setupAPIWithPolicyT(t)

	req := authedRequest("GET", "/policy/versions?tenant_id=1&fleet_id=1", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"versions"`) {
		t.Fatalf("response missing versions key: %s", w.Body.String())
	}
}

func TestPolicyVersionsInvalidTenant(t *testing.T) {
	api := setupAPIWithPolicyT(t)

	req := authedRequest("GET", "/policy/versions?tenant_id=abc&fleet_id=1", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestEmergencyEndpoint(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"tenant_id":1,"fleet_id":2,"command":"BLOCK_ALL"}`
	req := authedRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"distributed"`) {
		t.Fatalf("response missing distributed status: %s", w.Body.String())
	}
}

func TestEmergencyEndpointEnterLockdown(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"tenant_id":1,"fleet_id":2,"command":"ENTER_LOCKDOWN"}`
	req := authedRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestEmergencyEndpointRevokeSessions(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"tenant_id":1,"fleet_id":2,"command":"REVOKE_SESSIONS"}`
	req := authedRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestEmergencyEndpointUnknownCommand(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"tenant_id":1,"fleet_id":2,"command":"SELF_DESTRUCT"}`
	req := authedRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestEmergencyEndpointMissingIDs(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"command":"BLOCK_ALL"}`
	req := authedRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPushPolicyMissingFields(t *testing.T) {
	api := setupAPIWithPolicyT(t)
	body := `{"tenant_id":1,"fleet_id":2}`
	req := authedRequest("POST", "/policy/push", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestPolicyEndpointsWithoutService(t *testing.T) {
	// API without policy service should return 501 for policy endpoints
	api := setupAPIWithT(t)

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/policy/push", `{"tenant_id":1,"fleet_id":1,"policy_yaml":"test","profile":"standard"}`},
		{"GET", "/policy/versions?tenant_id=1&fleet_id=1", ""},
		{"POST", "/policy/emergency", `{"tenant_id":1,"fleet_id":1,"command":"BLOCK_ALL"}`},
	}

	for _, tc := range tests {
		var req *http.Request
		if tc.body != "" {
			req = authedRequest(tc.method, tc.path, strings.NewReader(tc.body))
		} else {
			req = authedRequest(tc.method, tc.path, nil)
		}
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: status = %d, want 501", tc.method, tc.path, w.Code)
		}
	}
}

func TestSimulatePolicyWithoutService(t *testing.T) {
	api := setupAPIWithT(t)
	req := authedRequest("POST", "/policy/simulate", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	// Without policy service, simulate returns 200 with status message
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not configured") {
		t.Fatalf("expected 'not configured' in response: %s", w.Body.String())
	}
}

func TestEmptyTokenRejectsAllAuthenticatedRequests(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")

	mgr := manager.New(nil)
	cache := verdict.NewCache(100, func(_, _ uint16, h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionBlock, 3
	})
	api := NewAPI(context.Background(), mgr, cache)

	// With empty server token, all requests should be rejected (auth disabled = fail-closed)
	for _, path := range []string{"/health", "/devices"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer any-token")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401 with empty server token, got %d", path, w.Code)
		}
	}
}
