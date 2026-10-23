// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// otlpPeerMetadata is what the R5 peer listener kept: booleans, never a
// header value or a body.
type otlpPeerMetadata struct {
	bearer     bool
	markerSeen bool
}

// startOTLPPeer stands in for the other account's listener on the stale port.
func startOTLPPeer(t *testing.T) (*httptest.Server, func() []otlpPeerMetadata) {
	t.Helper()
	var mu sync.Mutex
	var seen []otlpPeerMetadata
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, otlpPeerMetadata{
			bearer:     strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "),
			markerSeen: bytes.Contains(body, []byte("SAR5_OTLP_CROSS_USER_MARKER")),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(peer.Close)
	return peer, func() []otlpPeerMetadata {
		mu.Lock()
		defer mu.Unlock()
		return append([]otlpPeerMetadata(nil), seen...)
	}
}

// exportLikeCodex sends one batch per configured OTLP-HTTP exporter, the way
// native Codex does at startup and after a turn.
func exportLikeCodex(t *testing.T, configPath string) {
	t.Helper()
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	otel, _ := cfg["otel"].(map[string]interface{})
	for _, key := range codexOtelExporterKeys {
		exporter, _ := otel[key].(map[string]interface{})
		otlpHTTP, _ := exporter["otlp-http"].(map[string]interface{})
		endpoint, _ := otlpHTTP["endpoint"].(string)
		if endpoint == "" {
			continue
		}
		headers := map[string]string{}
		if table, ok := otlpHTTP["headers"].(map[string]interface{}); ok {
			for name, value := range table {
				headers[name], _ = value.(string)
			}
		}
		postOTLP(t, endpoint, headers)
	}
}

// exportLikeClaudeCode follows Claude Code's documented environment: export
// only with CLAUDE_CODE_ENABLE_TELEMETRY=1 and an otlp exporter, to the signal
// endpoint, the base endpoint or the OTLP default.
func exportLikeClaudeCode(t *testing.T, settingsPath string) (defaultCollector bool) {
	t.Helper()
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	env, _ := settings["env"].(map[string]interface{})
	get := func(key string) string { value, _ := env[key].(string); return value }
	if get("CLAUDE_CODE_ENABLE_TELEMETRY") != "1" {
		return false
	}
	for _, signal := range []string{"LOGS", "METRICS", "TRACES"} {
		if !strings.Contains(get("OTEL_"+signal+"_EXPORTER"), "otlp") {
			continue
		}
		endpoint := get("OTEL_EXPORTER_OTLP_" + signal + "_ENDPOINT")
		if endpoint == "" && get("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
			endpoint = strings.TrimRight(get("OTEL_EXPORTER_OTLP_ENDPOINT"), "/") + "/v1/" + strings.ToLower(signal)
		}
		if endpoint == "" {
			// Another account can bind the OTLP default port as easily.
			defaultCollector = true
			continue
		}
		header := get("OTEL_EXPORTER_OTLP_" + signal + "_HEADERS")
		if header == "" {
			header = get("OTEL_EXPORTER_OTLP_HEADERS")
		}
		headers := map[string]string{}
		for _, part := range strings.Split(header, ",") {
			if name, value, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
				headers[name] = value
			}
		}
		postOTLP(t, endpoint, headers)
	}
	return defaultCollector
}

func postOTLP(t *testing.T, endpoint string, headers map[string]string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"resourceLogs":[{"body":"SAR5_OTLP_CROSS_USER_MARKER"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return // nothing listens: nothing is received either
	}
	_ = response.Body.Close()
}

// seedEarlierCodexNativeExporter writes the [otel] block an earlier per-user
// install rendered (released shape: /v1/<signal> URLs, paired product headers
// and a bearer) after that install captured the operator's preimage.
func seedEarlierCodexNativeExporter(t *testing.T, dir, configPath, apiAddr, goos string) {
	t.Helper()
	opts := SetupOpts{DataDir: dir, APIAddr: apiAddr, APIToken: "test-hook-token", GOOS: goos}
	if err := NewCodexConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("earlier Codex setup: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(data, &cfg); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("c", 64)
	legacy := map[string]interface{}{"log_user_prompt": true}
	for key, signal := range map[string]string{"exporter": "logs", "trace_exporter": "traces", "metrics_exporter": "metrics"} {
		legacy[key] = map[string]interface{}{"otlp-http": map[string]interface{}{
			"endpoint": "http://" + apiAddr + "/v1/" + signal,
			"protocol": "json",
			"headers": map[string]interface{}{
				"authorization":        "Bearer " + token,
				"x-defenseclaw-source": "codex",
				"x-defenseclaw-client": "codex-otel/1.0",
			},
		}}
	}
	cfg["otel"] = legacy
	out, err := editCodexOwnedTOML(data, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-codex.token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedEarlierClaudeCodeNativeExporter writes the env block an earlier per-user
// install rendered, with its restore metadata and scoped credential.
func seedEarlierClaudeCodeNativeExporter(t *testing.T, dir, settingsPath, apiAddr, goos string) {
	t.Helper()
	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: apiAddr, GOOS: goos}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("earlier Claude Code setup: %v", err)
	}
	legacy := opts
	legacy.ManagedEnterprise = true
	legacy.OTLPPathToken = strings.Repeat("b", 64)
	oldEnv := buildClaudeCodeOtelEnv(legacy)
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings["env"] = oldEnv
	if data, err = json.Marshal(settings); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := c.loadBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	backup.ManagedEnv = oldEnv
	if err := c.saveBackup(dir, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(legacy.OTLPPathToken), 0o600); err != nil {
		t.Fatal(err)
	}
}

func useCodexConfig(t *testing.T, path string) {
	t.Helper()
	prior := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = prior })
}

func useClaudeSettings(t *testing.T, path string) {
	t.Helper()
	prior := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = path
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
}

const operatorCodexConfig = "model = \"gpt-5\"\n[otel]\nlog_user_prompt = false\n" +
	"[otel.exporter.otlp-http]\nendpoint = \"https://collector.example.test/v1/logs\"\nprotocol = \"json\"\n"

// GAP-0836 (R5, metadata-only form): an earlier per-user install left Codex
// and Claude Code exporters, with their bearer, on that install's port. The
// managed gateway serves another port, so the other account that binds the
// stale one receives the prompt telemetry. Cleanup must leave nothing that
// sends there, nor fall back to the OTLP default port, and must restore the
// operator's own collector.
func TestUserNativeOTLPCleanupStopsDeliveryToAPeerOnTheStalePort(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			peer, seen := startOTLPPeer(t)
			stale := strings.TrimPrefix(peer.URL, "http://")
			codexPath := filepath.Join(dir, "codex", "config.toml")
			claudePath := filepath.Join(dir, "claude", "settings.json")
			for _, path := range []string{codexPath, claudePath} {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(codexPath, []byte(operatorCodexConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			useCodexConfig(t, codexPath)
			useClaudeSettings(t, claudePath)

			// The earlier per-user install: native exporters on its own port.
			seedEarlierCodexNativeExporter(t, dir, codexPath, stale, goos)
			seedEarlierClaudeCodeNativeExporter(t, dir, claudePath, stale, goos)
			exportLikeCodex(t, codexPath)
			exportLikeClaudeCode(t, claudePath)
			before := seen()
			bearers, markers := 0, 0
			for _, request := range before {
				if request.bearer {
					bearers++
				}
				if request.markerSeen {
					markers++
				}
			}
			if len(before) == 0 || bearers != len(before) || markers == 0 {
				t.Fatalf("repro precondition: the peer must receive bearer-bearing telemetry, got %d requests (%d bearer, %d marker)", len(before), bearers, markers)
			}

			managed := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true, GOOS: goos}
			for _, name := range []string{"codex", "claudecode"} {
				residue, err := UserNativeOTLPResidue(name, managed)
				if err != nil || len(residue) == 0 {
					t.Fatalf("%s: residue = %v, %v; want the stale exporter named", name, residue, err)
				}
				for _, field := range residue {
					if strings.Contains(field, stale) || strings.Contains(field, "Bearer") {
						t.Fatalf("%s: residue carries a value: %q", name, field)
					}
				}
				if _, err := RemoveUserNativeOTLP(name, managed); err != nil {
					t.Fatalf("%s: remove: %v", name, err)
				}
				if residue, err := UserNativeOTLPResidue(name, managed); err != nil || len(residue) != 0 {
					t.Fatalf("%s: residue after remove = %v, %v", name, residue, err)
				}
			}

			exportLikeCodex(t, codexPath)
			if exportLikeClaudeCode(t, claudePath) {
				t.Fatal("Claude Code still exports, now to the OTLP default port")
			}
			if after := seen(); len(after) != len(before) {
				t.Fatalf("the peer on the stale port received %d more requests after cleanup", len(after)-len(before))
			}
			for _, path := range []string{codexPath, claudePath} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), stale) || strings.Contains(string(data), "Bearer ") {
					t.Fatalf("%s keeps the stale endpoint or a bearer", filepath.Base(path))
				}
			}
			data, err := os.ReadFile(codexPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "https://collector.example.test/v1/logs") {
				t.Fatalf("operator collector was not restored:\n%s", data)
			}
			for _, scope := range []OTLPPathTokenScope{OTLPScopeCodex, OTLPScopeClaude} {
				if token, err := LoadOTLPPathToken(dir, scope); err != nil || token != "" {
					t.Fatalf("%s credential remains: present=%t err=%v", scope, token != "", err)
				}
			}
		})
	}
}

// The R5 host had no restore metadata for those exporters: the files below are
// the exact released shapes (unscoped /v1/<signal> URLs, paired product
// headers, a 64-hex bearer) on a port other than the managed gateway's.
func TestUserNativeOTLPCleanupRemovesReleasedShapesWithoutBackup(t *testing.T) {
	bearer := "Bearer " + strings.Repeat("a1", 32)
	dir := t.TempDir()
	codexPath := filepath.Join(dir, "config.toml")
	claudePath := filepath.Join(dir, "settings.json")
	useCodexConfig(t, codexPath)
	useClaudeSettings(t, claudePath)
	codex := "model = \"gpt-5\"\n[otel]\nlog_user_prompt = true\n"
	for _, pair := range [][2]string{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		codex += "[otel." + pair[0] + ".otlp-http]\nendpoint = 'http://127.0.0.1:19010/v1/" + pair[1] + "'\nprotocol = 'json'\n" +
			"[otel." + pair[0] + ".otlp-http.headers]\nauthorization = '" + bearer + "'\n" +
			"x-defenseclaw-source = 'codex'\nx-defenseclaw-client = 'codex-otel/1.0'\n"
	}
	if err := os.WriteFile(codexPath, []byte(codex), 0o600); err != nil {
		t.Fatal(err)
	}
	headers := "authorization=" + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	env := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY":        "1",
		"OTEL_LOGS_EXPORTER":                  "otlp",
		"OTEL_METRICS_EXPORTER":               "otlp",
		"OTEL_TRACES_EXPORTER":                "none",
		"OTEL_LOG_USER_PROMPTS":               "1",
		"OTEL_EXPORTER_OTLP_PROTOCOL":         "http/json",
		"OTEL_EXPORTER_OTLP_ENDPOINT":         "http://127.0.0.1:19010",
		"OTEL_EXPORTER_OTLP_HEADERS":          headers,
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    "http://127.0.0.1:19010/v1/logs",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS":     headers,
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:19010/v1/metrics",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  headers,
		"OTEL_SERVICE_NAME":                   "claudecode",
		"MY_TEAM_SETTING":                     "kept",
	}
	data, err := json.Marshal(map[string]interface{}{"env": env, "model": "opus"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	managed := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true}
	for _, name := range []string{"codex", "claudecode"} {
		if _, err := RemoveUserNativeOTLP(name, managed); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, path := range []string{codexPath, claudePath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, leftover := range []string{"19010", "Bearer", "x-defenseclaw", "log_user_prompt = true"} {
			if strings.Contains(string(data), leftover) {
				t.Fatalf("%s keeps %q:\n%s", filepath.Base(path), leftover, data)
			}
		}
	}
	data, err = os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	got := settings["env"].(map[string]interface{})
	if got["MY_TEAM_SETTING"] != "kept" || settings["model"] != "opus" || got["OTEL_TRACES_EXPORTER"] != "none" {
		t.Fatalf("unrelated settings changed: %v", settings)
	}
	if _, enabled := got["CLAUDE_CODE_ENABLE_TELEMETRY"]; enabled {
		t.Fatalf("Claude Code telemetry stays enabled with no DefenseClaw endpoint: %v", got)
	}
	if exportLikeClaudeCode(t, claudePath) {
		t.Fatal("Claude Code falls back to the OTLP default port")
	}
	data, err = os.ReadFile(codexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "model = \"gpt-5\"") {
		t.Fatalf("unrelated Codex setting changed:\n%s", data)
	}
}

// Only DefenseClaw's own markers authorize a change: an operator's exporters,
// including a loopback collector and prompt capture, and the closed per-user
// values Setup writes now stay byte for byte.
func TestUserNativeOTLPCleanupLeavesOperatorExportersAlone(t *testing.T) {
	dir := t.TempDir()
	codexPath := filepath.Join(dir, "config.toml")
	claudePath := filepath.Join(dir, "settings.json")
	useCodexConfig(t, codexPath)
	useClaudeSettings(t, claudePath)
	codex := "[otel]\nlog_user_prompt = true\n[otel.exporter.otlp-http]\nendpoint = 'http://127.0.0.1:4318/v1/logs'\n" +
		"protocol = 'json'\n[otel.exporter.otlp-http.headers]\nauthorization = 'Bearer " + strings.Repeat("c", 64) + "'\n"
	claude := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:4318","OTEL_EXPORTER_OTLP_HEADERS":"authorization=Bearer ` +
		strings.Repeat("c", 64) + `","OTEL_LOG_USER_PROMPTS":"1"}}`
	if err := os.WriteFile(codexPath, []byte(codex), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudePath, []byte(claude), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true}
	for _, name := range []string{"codex", "claudecode"} {
		if residue, err := UserNativeOTLPResidue(name, managed); err != nil || len(residue) != 0 {
			t.Fatalf("%s: operator exporter classified as DefenseClaw: %v %v", name, residue, err)
		}
		if removed, err := RemoveUserNativeOTLP(name, managed); err != nil || len(removed) != 0 {
			t.Fatalf("%s: removed %v, %v", name, removed, err)
		}
	}
	if data, _ := os.ReadFile(codexPath); string(data) != codex {
		t.Fatalf("operator Codex config changed:\n%s", data)
	}
	if data, _ := os.ReadFile(claudePath); string(data) != claude {
		t.Fatalf("operator Claude settings changed:\n%s", data)
	}

	// The per-user Setup of this release writes closed values only.
	perUser := t.TempDir()
	useClaudeSettings(t, filepath.Join(perUser, "settings.json"))
	useCodexConfig(t, filepath.Join(perUser, "config.toml"))
	opts := SetupOpts{DataDir: perUser, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token"}
	if err := NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := NewCodexConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"codex", "claudecode"} {
		if residue, err := UserNativeOTLPResidue(name, opts); err != nil || len(residue) != 0 {
			t.Fatalf("%s: current per-user setup reported as stale exporter: %v %v", name, residue, err)
		}
	}
}

// A header value that mixes an operator header with DefenseClaw's keeps the
// operator's part and loses the product markers and DefenseClaw's bearer.
func TestUserNativeOTLPCleanupKeepsOperatorHeadersBesideDefenseClawOnes(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, "settings.json")
	useClaudeSettings(t, claudePath)
	mixed := "x-tenant=acme,authorization=Bearer " + strings.Repeat("d", 64) + ",x-defenseclaw-source=claudecode"
	claude := `{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"` + mixed + `","OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example.test"}}`
	if err := os.WriteFile(claudePath, []byte(claude), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true}
	if _, err := RemoveUserNativeOTLP("claudecode", managed); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]map[string]string
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["env"]["OTEL_EXPORTER_OTLP_HEADERS"] != "x-tenant=acme" ||
		settings["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] != "https://collector.example.test" {
		t.Fatalf("mixed headers not narrowed to the operator's: %v", settings["env"])
	}
	if removed, err := RemoveUserNativeOTLP("claudecode", managed); err != nil || len(removed) != 0 {
		t.Fatalf("second cleanup changed settings again: %v %v", removed, err)
	}
}
