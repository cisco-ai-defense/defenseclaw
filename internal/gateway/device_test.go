package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// readOpenClawGatewayToken and isAuthError are in client.go — tests go here
// because they relate to the device/auth repair flow.

func TestRepairPairing(t *testing.T) {
	device, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "device.key"))
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	sandboxHome := t.TempDir()

	t.Run("creates paired.json from scratch", func(t *testing.T) {
		home := t.TempDir()
		if err := device.RepairPairing(home); err != nil {
			t.Fatalf("repair pairing: %v", err)
		}

		pairedPath := filepath.Join(home, ".openclaw", "devices", "paired.json")
		data, err := os.ReadFile(pairedPath)
		if err != nil {
			t.Fatalf("read paired.json: %v", err)
		}

		var paired map[string]interface{}
		if err := json.Unmarshal(data, &paired); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		entry, ok := paired[device.DeviceID].(map[string]interface{})
		if !ok {
			t.Fatalf("device entry not found for id=%s", device.DeviceID)
		}
		if entry["clientId"] != "gateway-client" {
			t.Errorf("clientId = %v, want gateway-client", entry["clientId"])
		}
		if entry["displayName"] != "defenseclaw-sidecar" {
			t.Errorf("displayName = %v, want defenseclaw-sidecar", entry["displayName"])
		}
		if entry["publicKey"] != device.PublicKeyBase64URL() {
			t.Errorf("publicKey mismatch")
		}
	})

	t.Run("preserves existing devices", func(t *testing.T) {
		devicesDir := filepath.Join(sandboxHome, ".openclaw", "devices")
		os.MkdirAll(devicesDir, 0o755)
		existing := map[string]interface{}{
			"other-device": map[string]interface{}{
				"deviceId":    "other-device",
				"displayName": "ui-client",
			},
		}
		data, _ := json.MarshalIndent(existing, "", "  ")
		os.WriteFile(filepath.Join(devicesDir, "paired.json"), data, 0o644)

		if err := device.RepairPairing(sandboxHome); err != nil {
			t.Fatalf("repair pairing: %v", err)
		}

		data, _ = os.ReadFile(filepath.Join(devicesDir, "paired.json"))
		var paired map[string]interface{}
		json.Unmarshal(data, &paired)

		if _, ok := paired["other-device"]; !ok {
			t.Error("existing device entry was lost")
		}
		if _, ok := paired[device.DeviceID]; !ok {
			t.Error("sidecar device entry not added")
		}
	})
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("connect rejected (token_missing)"), true},
		{fmt.Errorf("gateway: connect: unauthorized (UNAUTHORIZED)"), true},
		{fmt.Errorf("unauthorized: gateway token mismatch (provide gateway auth token) (INVALID_REQUEST)"), true},
		{fmt.Errorf("token_mismatch"), true},
		{fmt.Errorf("Pairing_Required"), true},
		{fmt.Errorf("device not paired with gateway"), true},
		{fmt.Errorf("connection refused"), false},
		{fmt.Errorf("timeout"), false},
	}
	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			if got := isAuthError(tt.err); got != tt.want {
				t.Errorf("isAuthError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestReadOpenClawGatewayToken(t *testing.T) {
	t.Run("reads token from openclaw.json", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".openclaw")
		os.MkdirAll(dir, 0o755)
		cfg := `{"gateway":{"auth":{"token":"secret-abc-123"}}}`
		os.WriteFile(filepath.Join(dir, "openclaw.json"), []byte(cfg), 0o644)

		token, ok := readOpenClawGatewayToken(home)
		if !ok || token != "secret-abc-123" {
			t.Errorf("got (%q, %v), want (secret-abc-123, true)", token, ok)
		}
	})

	t.Run("returns false when file missing", func(t *testing.T) {
		_, ok := readOpenClawGatewayToken(t.TempDir())
		if ok {
			t.Error("expected false for missing file")
		}
	})

	t.Run("returns false when token empty", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".openclaw")
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "openclaw.json"), []byte(`{"gateway":{}}`), 0o644)

		_, ok := readOpenClawGatewayToken(home)
		if ok {
			t.Error("expected false for empty token")
		}
	})
}
