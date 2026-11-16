package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeSetupRemovesAnExporterThatSendsTheGatewayToken is GAP-0035: a
// Claude Code exporter whose headers carry the install's gateway master token
// is DefenseClaw's (a known product credential), so Setup removes it; an
// operator collector with its own bearer is kept byte for byte.
func TestClaudeSetupRemovesAnExporterThatSendsTheGatewayToken(t *testing.T) {
	gatewayToken := strings.Repeat("g1", 32)
	for _, tc := range []struct {
		name    string
		headers string
		product bool
	}{
		{name: "gateway token, encoded", headers: "authorization=Bearer%20" + gatewayToken, product: true},
		{name: "gateway token, plain", headers: "x-tenant=ops,authorization=Bearer " + gatewayToken, product: true},
		{name: "operator bearer", headers: "authorization=Bearer " + otlpSecretOperatorHex},
	} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				pinClaudeUpgradeTestOwner(t, dir)
				settingsPath := filepath.Join(dir, "settings.json")
				prior := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = settingsPath
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
				operator := map[string]interface{}{
					"OTEL_METRICS_EXPORTER":               "otlp",
					"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:18998/v1/metrics",
					"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  tc.headers,
				}
				writeClaudeUpgradeSettings(t, settingsPath, map[string]interface{}{"model": "opus", "env": operator})
				opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19082", APIToken: "test-hook-token", GatewayToken: gatewayToken, GOOS: goos}
				if err := NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
					t.Fatalf("setup: %v", err)
				}
				raw, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				got := readClaudeUpgradeEnv(t, settingsPath)
				if tc.product {
					if otlpSecretLeaked(string(raw), gatewayToken) {
						t.Fatalf("exporter that sends the gateway token kept:\n%s", raw)
					}
					if got["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] == "http://127.0.0.1:18998/v1/metrics" {
						t.Fatalf("route to the unverified port kept:\n%s", raw)
					}
					return
				}
				for key, want := range operator {
					if got[key] != want {
						t.Errorf("operator %s = %q, want %q", key, got[key], want)
					}
				}
			})
		}
	}
}
