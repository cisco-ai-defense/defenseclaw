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
	body := `{"new_deny_hashes":["abc"],"revoke_allow_hashes":["def"],"emergency":false}`
	req := httptest.NewRequest("POST", "/threat-intel/push", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
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
