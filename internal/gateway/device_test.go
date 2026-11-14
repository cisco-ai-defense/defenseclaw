package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// readOpenClawGatewayToken and isAuthError are in client.go — tests go here
// because they relate to the connect-rejection flow.

// GAP-0592: a pairing or token rejection never writes OpenClaw's pairing
// state. The sidecar used to rewrite <home>/.openclaw/devices/paired.json
// and grant itself operator.read, write, admin and approvals.
func TestConnectRejectionNeverWritesOpenClawPairingState(t *testing.T) {
	home := t.TempDir()
	dataDir := testenv.PrivateTempDir(t)
	devicesDir := filepath.Join(home, ".openclaw", "devices")
	if err := os.MkdirAll(devicesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pairedPath := filepath.Join(devicesDir, "paired.json")
	original := []byte(`{"other-device":{"deviceId":"other-device","scopes":["operator.read"]}}` + "\n")
	if err := os.WriteFile(pairedPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(&config.GatewayConfig{
		Token:         "boot-token",
		ClawHome:      home,
		DeviceKeyFile: filepath.Join(dataDir, "device.key"),
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, rejection := range []error{
		errors.New("gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)"),
		errors.New("gateway: connect handshake: pairing required: device identity changed and must be re-approved (NOT_PAIRED)"),
		errors.New("gateway: connect handshake: pairing required: device is asking for more scopes than currently approved (NOT_PAIRED)"),
		errors.New("connect rejected (token_missing)"),
	} {
		if hint := client.handleConnectRejection(rejection); hint == "" {
			t.Errorf("handleConnectRejection(%v) gave no operator step", rejection)
		}
	}
	got, err := os.ReadFile(pairedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("paired.json changed after connect rejections:\n got: %s\nwant: %s", got, original)
	}
	entries, err := os.ReadDir(devicesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("devices directory holds %d entries, want only paired.json", len(entries))
	}

	fresh := t.TempDir()
	client.cfg.ClawHome = fresh
	client.handleConnectRejection(errors.New("gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)"))
	if _, err := os.Stat(filepath.Join(fresh, ".openclaw")); !os.IsNotExist(err) {
		t.Fatalf("a pairing rejection created OpenClaw state in a fresh home: %v", err)
	}
}

// GAP-0592: a pairing rejection names OpenClaw's own approval step and the
// device to approve; a token rejection names the token step; any other
// failure has no operator step.
func TestConnectRejectionOperatorStep(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	client, err := NewClient(&config.GatewayConfig{
		Token:         "boot-token",
		DeviceKeyFile: filepath.Join(dataDir, "device.key"),
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, rejection := range []string{
		"gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)",
		"gateway: connect handshake: pairing required: device is asking for a higher role than currently approved (NOT_PAIRED)",
		"gateway: connect handshake: pairing required: device is asking for more scopes than currently approved (NOT_PAIRED)",
		"websocket: close 1008 (policy violation): pairing required: device identity changed and must be re-approved (requestId: eabe39af-7a72-4331-8271-03e16e635db2)",
		"device token does not cover the requested scopes (AUTH_SCOPE_MISMATCH)",
	} {
		hint := client.handleConnectRejection(errors.New(rejection))
		for _, want := range []string{"openclaw devices list", "openclaw devices approve <requestId>", client.device.DeviceID, "keeps retrying"} {
			if !strings.Contains(hint, want) {
				t.Errorf("%s: hint %q does not contain %q", rejection, hint, want)
			}
		}
	}
	for _, rejection := range []string{"connect rejected (token_missing)", "unauthorized: gateway token mismatch (provide gateway auth token) (INVALID_REQUEST)"} {
		if hint := client.handleConnectRejection(errors.New(rejection)); hint != openClawTokenRejectedHint {
			t.Errorf("%s: hint = %q, want the token step", rejection, hint)
		}
	}
	for _, failure := range []string{"connection refused", "timeout"} {
		if hint := client.handleConnectRejection(errors.New(failure)); hint != "" {
			t.Errorf("%s: hint = %q, want none", failure, hint)
		}
	}
}

func TestIsAuthError(t *testing.T) {
	// The first cases below are the EXACT wire formats OpenClaw emits
	// (see node_modules/openclaw/dist/connect-error-details-*.js Ee
	// and Se). Past regression: isAuthError used to look for
	// "pairing_required" (underscore) and "not paired" (lowercased
	// phrase), neither of which match these messages. Keep these literals — they
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

		// Real OpenClaw NOT_PAIRED messages. Role-upgrade and
		// scope-upgrade rejections are not token failures: they need an
		// OpenClaw approval (openClawPairingApprovalNeeded).
		{fmt.Errorf("gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)"), true},
		{fmt.Errorf("gateway: connect handshake: pairing required: device identity changed and must be re-approved (NOT_PAIRED)"), true},
		{fmt.Errorf("gateway: connect handshake: pairing required: device is asking for a higher role than currently approved (NOT_PAIRED)"), false},
		{fmt.Errorf("gateway: connect handshake: pairing required: device is asking for more scopes than currently approved (NOT_PAIRED)"), false},
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

		token, ok, err := readOpenClawGatewayToken(home)
		if !ok || token != "secret-abc-123" || err != nil {
			t.Errorf("got (%q, %v), want (secret-abc-123, true)", token, ok)
		}
	})

	t.Run("returns false when file missing", func(t *testing.T) {
		_, ok, _ := readOpenClawGatewayToken(t.TempDir())
		if ok {
			t.Error("expected false for missing file")
		}
	})

	t.Run("returns false when token empty", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".openclaw")
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "openclaw.json"), []byte(`{"gateway":{}}`), 0o644)

		_, ok, _ := readOpenClawGatewayToken(home)
		if ok {
			t.Error("expected false for empty token")
		}
	})

	// Issue #1404: OpenClaw stores gateway.auth.token as a SecretRef object.
	secretRef := func(t *testing.T, token string) string {
		t.Helper()
		home := t.TempDir()
		dir := filepath.Join(home, ".openclaw")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := `{"gateway":{"mode":"local","auth":{"mode":"token","token":` + token + `}}}`
		if err := os.WriteFile(filepath.Join(dir, "openclaw.json"), []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return home
	}

	t.Run("env SecretRef resolves from the environment", func(t *testing.T) {
		t.Setenv("DC_TEST_GH1404_TOKEN", "env-token-1404")
		home := secretRef(t, `{"source":"env","provider":"default","id":"DC_TEST_GH1404_TOKEN"}`)
		token, ok, err := readOpenClawGatewayToken(home)
		if !ok || token != "env-token-1404" || err != nil {
			t.Fatalf("got (%q, %v, %v), want (env-token-1404, true, nil)", token, ok, err)
		}
	})

	for name, ref := range map[string]string{
		"env SecretRef with the variable unset": `{"source":"env","provider":"default","id":"DC_TEST_GH1404_UNSET"}`,
		"store SecretRef":                       `{"source":"store","provider":"default","id":"OPENCLAW_GATEWAY_TOKEN"}`,
		"malformed SecretRef":                   `{"source":"env","id":"not a name"}`,
		"number":                                `42`,
	} {
		t.Run(name+" is never a token", func(t *testing.T) {
			t.Setenv("DC_TEST_GH1404_UNSET", "")
			home := secretRef(t, ref)
			token, ok, err := readOpenClawGatewayToken(home)
			if ok || token != "" || !errors.Is(err, errOpenClawTokenUnreadable) {
				t.Fatalf("got (%q, %v, %v), want (\"\", false, errOpenClawTokenUnreadable)", token, ok, err)
			}
			if !strings.Contains(err.Error(), "gateway.auth.token") {
				t.Fatalf("message %q must name the setting", err.Error())
			}
		})
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("ZeptoClaw is not certified on native Windows; platform gate coverage remains active")
	}
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

	// Subprocess shim enforcement requires writing to dataDir/shims —
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

// TestAdoptOpenClawTokenPersistence covers the on-disk side of auth repair
// under R-TOK: the token re-read from openclaw.json is saved only as
// OPENCLAW_GATEWAY_TOKEN in .env. The DefenseClaw gateway token line and
// hooks/.token are never touched.
func TestAdoptOpenClawTokenPersistence(t *testing.T) {
	adopt := func(t *testing.T, dir, token string) *Client {
		t.Helper()
		c := &Client{cfg: &config.GatewayConfig{Token: "master-token"}, dataDir: dir}
		c.adoptOpenClawToken(token)
		if got := c.wsToken(); got != token {
			t.Fatalf("wsToken = %q, want %q", got, token)
		}
		if c.cfg.Token != "master-token" {
			t.Fatalf("cfg.Token = %q, want master-token unchanged", c.cfg.Token)
		}
		return c
	}

	t.Run("rewrites the OpenClaw line and keeps the master", func(t *testing.T) {
		dir := t.TempDir()
		envPath := filepath.Join(dir, ".env")
		original := "DEFENSECLAW_LLM_KEY=sk-or-v1-keep-me\n" +
			"OPENCLAW_GATEWAY_TOKEN=old-stale-token\n" +
			"DEFENSECLAW_GATEWAY_TOKEN=\"master-token\"\n"
		os.WriteFile(envPath, []byte(original), 0o600)

		adopt(t, dir, "new-fresh-token")

		got, _ := os.ReadFile(envPath)
		content := string(got)
		for _, want := range []string{
			"DEFENSECLAW_LLM_KEY=sk-or-v1-keep-me\n",
			"OPENCLAW_GATEWAY_TOKEN=new-fresh-token\n",
			"DEFENSECLAW_GATEWAY_TOKEN=\"master-token\"\n",
		} {
			if !containsLine(content, want) {
				t.Errorf(".env missing line %q\nfile:\n%s", want, content)
			}
		}
		if strings.Contains(content, "old-stale-token") {
			t.Errorf(".env still contains old token\nfile:\n%s", content)
		}
	})

	t.Run("appends only the OpenClaw line when it is missing", func(t *testing.T) {
		dir := t.TempDir()
		envPath := filepath.Join(dir, ".env")
		os.WriteFile(envPath, []byte("DEFENSECLAW_LLM_KEY=sk-existing\n"), 0o600)

		adopt(t, dir, "appended-token")

		content, _ := os.ReadFile(envPath)
		s := string(content)
		if !containsLine(s, "OPENCLAW_GATEWAY_TOKEN=appended-token\n") {
			t.Errorf("missing OPENCLAW_GATEWAY_TOKEN line\nfile:\n%s", s)
		}
		if strings.Contains(s, "DEFENSECLAW_GATEWAY_TOKEN") {
			t.Errorf("adoption wrote DEFENSECLAW_GATEWAY_TOKEN\nfile:\n%s", s)
		}
	})

	t.Run("creates .env when it does not exist", func(t *testing.T) {
		dir := t.TempDir()
		adopt(t, dir, "brand-new-token")
		content, err := os.ReadFile(filepath.Join(dir, ".env"))
		if err != nil {
			t.Fatalf(".env not created: %v", err)
		}
		if !containsLine(string(content), "OPENCLAW_GATEWAY_TOKEN=brand-new-token\n") {
			t.Errorf(".env content: %s", content)
		}
	})

	t.Run("never rewrites hooks/.token", func(t *testing.T) {
		dir := t.TempDir()
		hookDir := filepath.Join(dir, "hooks")
		os.MkdirAll(hookDir, 0o755)
		tokenPath := filepath.Join(hookDir, ".token")
		before := `DEFENSECLAW_GATEWAY_TOKEN="master-token"` + "\n"
		os.WriteFile(tokenPath, []byte(before), 0o600)

		adopt(t, dir, "hook-refreshed")

		content, _ := os.ReadFile(tokenPath)
		if string(content) != before {
			t.Errorf("hooks/.token changed:\n%s", content)
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
