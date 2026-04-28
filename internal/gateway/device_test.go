package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

	t.Run("platform matches runtime.GOOS so OpenClaw doesn't flag metadata-upgrade", func(t *testing.T) {
		// Regression: device.go used to hard-code platform="linux"
		// in the paired.json entry, but the connect handshake
		// (client.go) always reports runtime.GOOS — so on macOS the
		// two disagreed and OpenClaw rejected every connect with
		// `pairing required: device identity changed and must be
		// re-approved (NOT_PAIRED)`, leaving the gateway link stuck
		// in RECONNECTING forever even with auto-repair active.
		// If you ever change the platform field, update the
		// handshake too — the two MUST agree byte-for-byte.
		home := t.TempDir()
		if err := device.RepairPairing(home); err != nil {
			t.Fatalf("repair pairing: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(home, ".openclaw", "devices", "paired.json"))
		if err != nil {
			t.Fatalf("read paired.json: %v", err)
		}
		var paired map[string]map[string]interface{}
		if err := json.Unmarshal(data, &paired); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		entry, ok := paired[device.DeviceID]
		if !ok {
			t.Fatalf("device entry missing for id=%s", device.DeviceID)
		}
		got, _ := entry["platform"].(string)
		if got != runtime.GOOS {
			t.Errorf("platform = %q, want runtime.GOOS = %q\n\nThis is the metadata-upgrade regression: hardcoding the platform makes paired.json disagree with the connect handshake on every non-Linux host, causing an infinite NOT_PAIRED loop.", got, runtime.GOOS)
		}
		if got == "linux" && runtime.GOOS != "linux" {
			t.Fatalf("platform was hardcoded to %q on a non-linux host (runtime.GOOS=%q) — this is the exact regression that caused the gateway RECONNECTING bug; do not revert", got, runtime.GOOS)
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
	// The first cases below are the EXACT wire formats OpenClaw emits
	// (see node_modules/openclaw/dist/connect-error-details-*.js Ee
	// and Se). Past regression: isAuthError used to look for
	// "pairing_required" (underscore) and "not paired" (lowercased
	// phrase), neither of which match these messages, so the
	// auto-repair code path went dead. Keep these literals — they
	// are copy-paste from production gateway.log.
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

		// Real OpenClaw NOT_PAIRED messages — the four sub-reasons
		// (not-paired, metadata-upgrade, role-upgrade, scope-upgrade)
		// — must all trigger auto-repair. Anything less leaves the
		// gateway flapping in RECONNECTING.
		{fmt.Errorf("gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)"), true},
		{fmt.Errorf("gateway: connect handshake: pairing required: device identity changed and must be re-approved (NOT_PAIRED)"), true},
		{fmt.Errorf("gateway: connect handshake: pairing required: device is asking for a higher role than currently approved (NOT_PAIRED)"), true},
		{fmt.Errorf("gateway: connect handshake: pairing required: device is asking for more scopes than currently approved (NOT_PAIRED)"), true},
		{fmt.Errorf("websocket: close 1008 (policy violation): pairing required: device identity changed and must be re-approved (requestId: eabe39af-7a72-4331-8271-03e16e635db2)"), true},

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

// TestReadZeptoClawProviderKeys_FromConfigJSON — plan E1 / item 6.
//
// Documents the per-connector mechanism: ZeptoClaw stores upstream
// API keys *per provider* in `~/.zeptoclaw/config.json` (NOT in a
// single auth.token field like OpenClaw's openclaw.json). The Setup
// flow parses that file, captures pristine providers in a backup,
// and exposes the captured keys via ProviderSnapshot() — which is
// what audit/scan/AIBOM consumers read.
//
// We exercise the public path: Setup → ProviderSnapshot. The proxy
// URL is a stub (Setup just substitutes api_base in the on-disk
// config; no network calls happen).
func TestReadZeptoClawProviderKeys_FromConfigJSON(t *testing.T) {
	tmpHome := t.TempDir()
	zcDir := filepath.Join(tmpHome, ".zeptoclaw")
	if err := os.MkdirAll(zcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(zcDir, "config.json")
	cfg := `{
		"providers": {
			"openai":   {"api_base": "https://api.openai.com",      "api_key": "sk-zc-openai-test"},
			"anthropic":{"api_base": "https://api.anthropic.com",   "api_key": "ant-zc-test"}
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := connector.ZeptoClawConfigPathOverride
	connector.ZeptoClawConfigPathOverride = cfgPath
	t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prev })

	dataDir := t.TempDir()

	// SubprocessSandbox enforcement requires writing to dataDir/shims —
	// fully self-contained inside the tmpdir. No network or external
	// binaries are touched in Setup.
	c := connector.NewZeptoClawConnector()
	opts := connector.SetupOpts{
		DataDir:   dataDir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "tok",
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("zeptoclaw Setup: %v", err)
	}

	snap := c.ProviderSnapshot()
	if got, want := len(snap), 2; got != want {
		t.Fatalf("ProviderSnapshot len = %d, want %d (snap=%+v)", got, want, snap)
	}
	if oa, ok := snap["openai"]; !ok || oa.APIKey != "sk-zc-openai-test" {
		t.Errorf("openai key not captured: got %+v", snap["openai"])
	}
	if an, ok := snap["anthropic"]; !ok || an.APIKey != "ant-zc-test" {
		t.Errorf("anthropic key not captured: got %+v", snap["anthropic"])
	}
}

// TestReadClaudeCodeAPIKey_FromAnthropicEnv — plan E1 / item 6.
//
// Documents the per-connector mechanism: Claude Code reads its
// upstream API key from the ANTHROPIC_API_KEY environment variable
// (NOT from a config file). The gateway honors the same convention
// via ResolveAPIKey, which means Anthropic's CLI and DefenseClaw's
// proxy share the same env-var contract.
func TestReadClaudeCodeAPIKey_FromAnthropicEnv(t *testing.T) {
	t.Run("reads from environment", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-claude-key")
		got := ResolveAPIKey("ANTHROPIC_API_KEY", "")
		if got != "sk-ant-test-claude-key" {
			t.Errorf("ResolveAPIKey(ANTHROPIC_API_KEY) = %q, want sk-ant-test-claude-key", got)
		}
	})
	t.Run("returns empty when not set", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		got := ResolveAPIKey("ANTHROPIC_API_KEY", "")
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

// TestReadCodexAPIKey_FromOpenAIEnv — plan E1 / item 6.
//
// Documents the per-connector mechanism: Codex reads its upstream
// API key from the OPENAI_API_KEY environment variable. This is
// distinct from OpenClaw (config-file-based) and ZeptoClaw
// (per-provider config-file). When `~/.codex/config.toml` is in play
// it patches the *base URL* (S8.1), but the auth credential itself
// remains env-var sourced.
func TestReadCodexAPIKey_FromOpenAIEnv(t *testing.T) {
	t.Run("reads from environment", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "sk-test-codex-key")
		got := ResolveAPIKey("OPENAI_API_KEY", "")
		if got != "sk-test-codex-key" {
			t.Errorf("ResolveAPIKey(OPENAI_API_KEY) = %q, want sk-test-codex-key", got)
		}
	})
	t.Run("returns empty when not set", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "")
		got := ResolveAPIKey("OPENAI_API_KEY", "")
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

// TestPersistRefreshedToken covers the on-disk side of the auth
// auto-repair path. When the sidecar refreshes Gateway.Token from
// openclaw.json in-memory, consumers of the old token (hook scripts
// reading hooks/.token, operator scripts sourcing .env) must see the
// new value or they'll 401 on every call until the next full sidecar
// restart.
func TestPersistRefreshedToken(t *testing.T) {
	t.Run("rewrites existing token lines in .env", func(t *testing.T) {
		dir := t.TempDir()
		envPath := filepath.Join(dir, ".env")
		original := "DEFENSECLAW_LLM_KEY=sk-or-v1-keep-me\n" +
			"OPENCLAW_GATEWAY_TOKEN=old-stale-token\n" +
			"DEFENSECLAW_GATEWAY_TOKEN=\"old-stale-token\"\n"
		os.WriteFile(envPath, []byte(original), 0o600)

		if err := persistRefreshedToken(dir, "new-fresh-token"); err != nil {
			t.Fatalf("persistRefreshedToken: %v", err)
		}

		got, _ := os.ReadFile(envPath)
		content := string(got)
		for _, want := range []string{
			"DEFENSECLAW_LLM_KEY=sk-or-v1-keep-me\n",
			"OPENCLAW_GATEWAY_TOKEN=new-fresh-token\n",
			"DEFENSECLAW_GATEWAY_TOKEN=new-fresh-token\n",
		} {
			if !containsLine(content, want) {
				t.Errorf(".env missing line %q\nfile:\n%s", want, content)
			}
		}
		if containsLine(content, "old-stale-token") {
			t.Errorf(".env still contains old token\nfile:\n%s", content)
		}
	})

	t.Run("appends token lines when .env missing the keys", func(t *testing.T) {
		dir := t.TempDir()
		envPath := filepath.Join(dir, ".env")
		os.WriteFile(envPath, []byte("DEFENSECLAW_LLM_KEY=sk-existing\n"), 0o600)

		if err := persistRefreshedToken(dir, "appended-token"); err != nil {
			t.Fatalf("persistRefreshedToken: %v", err)
		}

		content, _ := os.ReadFile(envPath)
		s := string(content)
		if !containsLine(s, "OPENCLAW_GATEWAY_TOKEN=appended-token\n") {
			t.Errorf("missing OPENCLAW_GATEWAY_TOKEN line\nfile:\n%s", s)
		}
		if !containsLine(s, "DEFENSECLAW_GATEWAY_TOKEN=appended-token\n") {
			t.Errorf("missing DEFENSECLAW_GATEWAY_TOKEN line\nfile:\n%s", s)
		}
	})

	t.Run("creates .env when it doesn't exist", func(t *testing.T) {
		dir := t.TempDir()
		if err := persistRefreshedToken(dir, "brand-new-token"); err != nil {
			t.Fatalf("persistRefreshedToken: %v", err)
		}
		content, err := os.ReadFile(filepath.Join(dir, ".env"))
		if err != nil {
			t.Fatalf(".env not created: %v", err)
		}
		if !containsLine(string(content), "OPENCLAW_GATEWAY_TOKEN=brand-new-token\n") {
			t.Errorf(".env content: %s", content)
		}
	})

	t.Run("rewrites hooks/.token with new value", func(t *testing.T) {
		dir := t.TempDir()
		hookDir := filepath.Join(dir, "hooks")
		os.MkdirAll(hookDir, 0o755)
		tokenPath := filepath.Join(hookDir, ".token")
		os.WriteFile(tokenPath, []byte(`DEFENSECLAW_GATEWAY_TOKEN="old-stale"`+"\n"), 0o600)

		if err := persistRefreshedToken(dir, "hook-refreshed"); err != nil {
			t.Fatalf("persistRefreshedToken: %v", err)
		}

		content, _ := os.ReadFile(tokenPath)
		s := string(content)
		if !containsLine(s, `DEFENSECLAW_GATEWAY_TOKEN="hook-refreshed"`+"\n") {
			t.Errorf("hooks/.token content:\n%s", s)
		}

		info, err := os.Stat(tokenPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("hooks/.token perm = %v, want 0600", info.Mode().Perm())
		}
	})

	t.Run("silently skips hooks/.token when hooks dir missing", func(t *testing.T) {
		dir := t.TempDir()
		if err := persistRefreshedToken(dir, "tok"); err != nil {
			t.Errorf("should not error when hooks dir missing: %v", err)
		}
	})
}

// containsLine reports whether haystack contains needle as a full line
// (handles leading lines, embedded lines, trailing lines without
// requiring exact-file-content equality).
func containsLine(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		// prefix or embedded match
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					if i == 0 || haystack[i-1] == '\n' {
						return true
					}
				}
			}
			return false
		})())
}
