package fleet

import (
	"context"
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

func setupAPI() *API {
	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	return NewAPI(mgr, cache)
}

func TestGetFleetHealth(t *testing.T) {
	api := setupAPI()
	req := httptest.NewRequest("GET", "/fleet/health", nil)
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
	api := setupAPI()
	req := httptest.NewRequest("GET", "/devices/999", nil)
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetDeviceInvalidID(t *testing.T) {
	api := setupAPI()
	req := httptest.NewRequest("GET", "/devices/invalid", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid id", w.Code)
	}
}

func TestPushThreatIntel(t *testing.T) {
	api := setupAPI()
	// Use valid 64-char hex strings (32 bytes decoded)
	hash := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	body := `{"new_deny_hashes":["abc123"],"revoke_allow_hashes":["` + hash + `"],"emergency":false}`
	req := httptest.NewRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
}

func TestPushThreatIntelInvalidHex(t *testing.T) {
	api := setupAPI()
	body := `{"new_deny_hashes":[],"revoke_allow_hashes":["not-valid-hex"],"emergency":false}`
	req := httptest.NewRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid hex", w.Code)
	}
}

func TestPushThreatIntelWrongLength(t *testing.T) {
	api := setupAPI()
	// Valid hex but only 4 bytes, not 32
	body := `{"new_deny_hashes":[],"revoke_allow_hashes":["deadbeef"],"emergency":false}`
	req := httptest.NewRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for wrong hash length", w.Code)
	}
}

func TestSendCommand(t *testing.T) {
	api := setupAPI()
	body := `{"command":"reboot"}`
	req := httptest.NewRequest("POST", "/devices/123/command", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
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

func (m *apiMockMQTTClient) Connect(_ context.Context) error   { return nil }
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

func setupAPIWithPolicy() *API {
	mgr := manager.New(nil)
	mgr.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 5, 0xFF)

	cache := verdict.NewCache(100, func(h [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})

	mc := &apiMockMQTTClient{}
	store := policy.NewMemoryPolicyStore()
	signer, _ := policy.NewHMACSigner([]byte("test-key-for-api-tests-32bytes!!"))
	svc := policy.NewService(store, signer, mc, nil)

	return NewAPI(mgr, cache, WithPolicyService(svc))
}

func TestPolicyVersionsEndpoint(t *testing.T) {
	api := setupAPIWithPolicy()

	req := httptest.NewRequest("GET", "/policy/versions?tenant_id=1&fleet_id=1", nil)
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
	api := setupAPIWithPolicy()

	req := httptest.NewRequest("GET", "/policy/versions?tenant_id=abc&fleet_id=1", nil)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestEmergencyEndpoint(t *testing.T) {
	api := setupAPIWithPolicy()
	body := `{"tenant_id":1,"fleet_id":2,"command":"FLUSH_CACHE"}`
	req := httptest.NewRequest("POST", "/policy/emergency", strings.NewReader(body))
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
	api := setupAPIWithPolicy()
	body := `{"tenant_id":1,"fleet_id":2,"command":"ENTER_LOCKDOWN"}`
	req := httptest.NewRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestEmergencyEndpointRevokeSessions(t *testing.T) {
	api := setupAPIWithPolicy()
	body := `{"tenant_id":1,"fleet_id":2,"command":"REVOKE_SESSIONS"}`
	req := httptest.NewRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestEmergencyEndpointUnknownCommand(t *testing.T) {
	api := setupAPIWithPolicy()
	body := `{"tenant_id":1,"fleet_id":2,"command":"SELF_DESTRUCT"}`
	req := httptest.NewRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestEmergencyEndpointMissingIDs(t *testing.T) {
	api := setupAPIWithPolicy()
	body := `{"command":"FLUSH_CACHE"}`
	req := httptest.NewRequest("POST", "/policy/emergency", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPushPolicyMissingFields(t *testing.T) {
	api := setupAPIWithPolicy()
	body := `{"tenant_id":1,"fleet_id":2}`
	req := httptest.NewRequest("POST", "/policy/push", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestPolicyEndpointsWithoutService(t *testing.T) {
	// API without policy service should return 501 for policy endpoints
	api := setupAPI()

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/policy/push", `{"tenant_id":1,"fleet_id":1,"policy_yaml":"test","profile":"standard"}`},
		{"GET", "/policy/versions?tenant_id=1&fleet_id=1", ""},
		{"POST", "/policy/emergency", `{"tenant_id":1,"fleet_id":1,"command":"FLUSH_CACHE"}`},
	}

	for _, tc := range tests {
		var req *http.Request
		if tc.body != "" {
			req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		} else {
			req = httptest.NewRequest(tc.method, tc.path, nil)
		}
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: status = %d, want 501", tc.method, tc.path, w.Code)
		}
	}
}

func TestSimulatePolicyWithoutService(t *testing.T) {
	api := setupAPI()
	req := httptest.NewRequest("POST", "/policy/simulate", strings.NewReader(`{}`))
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
