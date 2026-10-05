package fleet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
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
