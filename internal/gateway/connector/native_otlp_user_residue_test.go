// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(strings.Repeat("a1", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
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
	if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(strings.Repeat("d", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
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

func TestClaudeNativeOTLPCleanupKeepsUnrelatedSignalEndpoint(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	useClaudeSettings(t, settingsPath)
	productLogs := "http://127.0.0.1:19010/v1/logs"
	operatorTraces := "http://127.0.0.1:4318/v1/traces"
	productHeaders := "x-defenseclaw-source=claudecode,x-defenseclaw-client=claudecode-otel/1.0"
	settings := map[string]interface{}{"env": map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY":       "1",
		"OTEL_LOGS_EXPORTER":                 "otlp",
		"OTEL_TRACES_EXPORTER":               "otlp",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":   productLogs,
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS":    productHeaders,
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": operatorTraces,
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  "x-operator=traces",
	}}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	backup := claudeCodeBackup{ManagedEnv: map[string]string{
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": productLogs,
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS":  productHeaders,
	}}
	if err := NewClaudeCodeConnector().saveBackup(dir, backup); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dir, ManagedEnterprise: true, APIAddr: "127.0.0.1:18970"}
	if _, err := RemoveUserNativeOTLP("claudecode", opts); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	env := got["env"]
	if env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] != operatorTraces || env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] != "x-operator=traces" {
		t.Fatalf("operator traces exporter changed: %v", env)
	}
	if env["OTEL_TRACES_EXPORTER"] != "otlp" || env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" ||
		env["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] != "http/protobuf" {
		t.Fatalf("operator traces exporter was disabled: %v", env)
	}
	if _, present := env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; present {
		t.Fatalf("product logs endpoint remains: %v", env)
	}
}

func TestClaudeNativeOTLPCleanupKeepsChangedAuthorization(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed=%t", changed), func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "settings.json")
			useClaudeSettings(t, settingsPath)
			product := strings.Repeat("a", 64)
			operator := strings.Repeat("b", 64)
			marked := func(token string) string {
				return "authorization=Bearer " + token + ",x-defenseclaw-source=claudecode,x-defenseclaw-client=claudecode-otel/1.0"
			}
			current := product
			if changed {
				current = operator
			}
			settings := map[string]interface{}{"env": map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.test",
				"OTEL_EXPORTER_OTLP_HEADERS":  marked(current),
			}}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			backup := claudeCodeBackup{ManagedEnv: map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": marked(product)}}
			if err := NewClaudeCodeConnector().saveBackup(dir, backup); err != nil {
				t.Fatal(err)
			}
			if _, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]map[string]string
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			want := ""
			if changed {
				want = "authorization=Bearer " + operator
			}
			if got["env"]["OTEL_EXPORTER_OTLP_HEADERS"] != want {
				t.Fatalf("Authorization after cleanup = %q, want %q", got["env"]["OTEL_EXPORTER_OTLP_HEADERS"], want)
			}
			if got["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] != "https://collector.example.test" {
				t.Fatalf("operator collector changed: %v", got["env"])
			}
		})
	}
}

func TestClaudeNativeOTLPInspectionDoesNotRequireUntrustedToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers string
		want    string
		residue bool
	}{
		{name: "operator collector", headers: "authorization=Bearer operator-value", want: "authorization=Bearer operator-value"},
		{name: "marked without authorization", headers: "x-defenseclaw-source=claudecode,x-operator=kept", want: "x-operator=kept", residue: true},
		{name: "marked with unmatched authorization", headers: "authorization=Bearer " + strings.Repeat("b", 64) + ",x-defenseclaw-source=claudecode", want: "authorization=Bearer " + strings.Repeat("b", 64), residue: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "settings.json")
			useClaudeSettings(t, settingsPath)
			settings := map[string]interface{}{"env": map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.test",
				"OTEL_EXPORTER_OTLP_HEADERS":  tc.headers,
			}}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			tokenPath, err := OTLPPathTokenFilePath(dir, OTLPScopeClaude)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
				t.Fatal(err)
			}
			// A malformed or untrusted token cannot prove ownership of the
			// Authorization value and must not break inspection.
			if err := os.WriteFile(tokenPath, []byte("invalid token"), 0o600); err != nil {
				t.Fatal(err)
			}
			residue, err := UserNativeOTLPResidue("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true})
			if err != nil {
				t.Fatal(err)
			}
			// The orphaned sidecar is always residue; only the marked
			// settings add an exporter field to the result.
			if (len(residue) > 1) != tc.residue || len(residue) == 0 {
				t.Fatalf("residue = %v, want marked settings %t", residue, tc.residue)
			}
			out, _, err := claudeCodeWithoutUserNativeOTLP(data, claudeCodeBackup{}, SetupOpts{DataDir: dir, ManagedEnterprise: true})
			if err != nil {
				t.Fatal(err)
			}
			if !tc.residue {
				if out != nil {
					t.Fatalf("operator collector was changed: %s", out)
				}
				return
			}
			var got map[string]map[string]string
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			if got["env"]["OTEL_EXPORTER_OTLP_HEADERS"] != tc.want || got["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] != "https://collector.example.test" {
				t.Fatalf("operator collector changed: %v", got["env"])
			}
		})
	}
}

// A product marker proves the marker and old loopback endpoint are ours, but
// does not prove an Authorization value without a matching backup or sidecar.
// Keep that value while disabling export so it cannot reach the retired port.
func TestClaudeNativeOTLPCleanupKeepsUnmatchedBearerOffRetiredPort(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	useClaudeSettings(t, settingsPath)
	peer, seen := startOTLPPeer(t)
	unmatched := strings.Repeat("d", 64)
	settings := map[string]interface{}{"env": map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"OTEL_LOGS_EXPORTER":           "otlp",
		"OTEL_EXPORTER_OTLP_ENDPOINT":  peer.URL,
		"OTEL_EXPORTER_OTLP_HEADERS":   "authorization=Bearer " + unmatched + ",x-defenseclaw-source=claudecode",
	}}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if fallback := exportLikeClaudeCode(t, settingsPath); fallback {
		t.Fatal("fixture did not export to its retired endpoint")
	}
	before := seen()
	if len(before) != 1 || !before[0].bearer {
		t.Fatalf("fixture did not send its bearer to the retired endpoint: %v", before)
	}
	out, removed, err := claudeCodeWithoutUserNativeOTLP(data, claudeCodeBackup{}, SetupOpts{DataDir: dir, ManagedEnterprise: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("retired exporter was not removed")
	}
	if err := os.WriteFile(settingsPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	data = out
	var got map[string]map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["env"]["OTEL_EXPORTER_OTLP_HEADERS"] != "authorization=Bearer "+unmatched ||
		got["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] != "" {
		t.Fatalf("unmatched credential or retired endpoint changed incorrectly: %v", got["env"])
	}
	if fallback := exportLikeClaudeCode(t, settingsPath); fallback || len(seen()) != len(before) {
		t.Fatalf("retired exporter still active: default=%t peer requests=%d", fallback, len(seen())-len(before))
	}
}

// growUserNativeOTLPFile pads path with valid filler past the check's read
// limit, keeping the DefenseClaw exporter in it, so only the size can make the
// check refuse it.
func growUserNativeOTLPFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", int(userNativeOTLPReadLimit))
	if strings.HasSuffix(path, ".toml") {
		data = append(data, []byte("\n# "+pad+"\n")...)
	} else {
		doc := map[string]interface{}{}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		doc["defenseclaw_test_pad"] = pad
		if data, err = json.Marshal(doc); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Managed Verify runs the residue check inside the shared Windows guardian on
// every reconcile, against files the account controls. An agent config or a
// setup backup past the read limit, whether real bytes or a huge sparse file,
// must be reported unverified without being read, and repair must refuse it
// without touching the file or the credential.
func TestUserNativeOTLPCheckRefusesOversizedFilesUnread(t *testing.T) {
	type target struct {
		connector string
		file      func(dir string) string
	}
	targets := []target{
		{"codex", func(dir string) string { return filepath.Join(dir, "codex", "config.toml") }},
		{"codex", func(dir string) string { return filepath.Join(dir, "codex_config_backup.json") }},
		{"claudecode", func(dir string) string { return filepath.Join(dir, "claude", "settings.json") }},
		{"claudecode", func(dir string) string { return filepath.Join(dir, "claudecode_backup.json") }},
	}
	for _, sparse := range []bool{false, true} {
		for _, tc := range targets {
			dir := t.TempDir()
			name := tc.connector + "/" + filepath.Base(tc.file(dir))
			if sparse {
				name += "/sparse"
			}
			t.Run(name, func(t *testing.T) {
				codexPath := filepath.Join(dir, "codex", "config.toml")
				claudePath := filepath.Join(dir, "claude", "settings.json")
				for _, path := range []string{codexPath, claudePath} {
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				useCodexConfig(t, codexPath)
				useClaudeSettings(t, claudePath)
				seedEarlierCodexNativeExporter(t, dir, codexPath, "127.0.0.1:19555", "windows")
				seedEarlierClaudeCodeNativeExporter(t, dir, claudePath, "127.0.0.1:19555", "windows")
				managed := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true, GOOS: "windows"}
				if residue, err := UserNativeOTLPResidue(tc.connector, managed); err != nil || len(residue) == 0 {
					t.Fatalf("precondition: residue = %v, %v", residue, err)
				}

				path := tc.file(dir)
				if sparse {
					// A terabyte the guardian would otherwise try to allocate.
					if err := makeSparseFile(path, 1<<40); err != nil {
						t.Skipf("no sparse file here: %v", err)
					}
				} else {
					growUserNativeOTLPFile(t, path)
				}
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				token, err := OTLPPathTokenFilePath(dir, map[string]OTLPPathTokenScope{"codex": OTLPScopeCodex, "claudecode": OTLPScopeClaude}[tc.connector])
				if err != nil {
					t.Fatal(err)
				}

				residue, err := UserNativeOTLPResidue(tc.connector, managed)
				if !errors.Is(err, errUserNativeOTLPFileTooLarge) {
					t.Fatalf("verify of an oversized %s = %v, %v; want it reported unverified", filepath.Base(path), residue, err)
				}
				if strings.Contains(err.Error(), dir) {
					t.Fatalf("error names the account path: %v", err)
				}
				if _, err := RemoveUserNativeOTLP(tc.connector, managed); !errors.Is(err, errUserNativeOTLPFileTooLarge) {
					t.Fatalf("repair of an oversized %s = %v; want it refused", filepath.Base(path), err)
				}
				after, err := os.Stat(path)
				if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
					t.Fatalf("repair touched the oversized file: %v", err)
				}
				if _, err := os.Lstat(token); err != nil {
					t.Fatalf("repair revoked the credential it could not prove unused: %v", err)
				}
			})
		}
	}
}

// The repair transform rereads the config under the larger compare-and-swap
// bound; a file that grew past the check's limit since the first read is
// refused there too.
func TestUserNativeOTLPTransformRefusesOversizedInput(t *testing.T) {
	big := bytes.Repeat([]byte(" "), int(userNativeOTLPReadLimit)+1)
	if _, _, err := codexWithoutUserNativeOTLP(big, codexConfigBackup{}, SetupOpts{}); !errors.Is(err, errUserNativeOTLPFileTooLarge) {
		t.Fatalf("Codex transform of oversized input: %v", err)
	}
	if _, _, err := claudeCodeWithoutUserNativeOTLP(big, claudeCodeBackup{}, SetupOpts{}); !errors.Is(err, errUserNativeOTLPFileTooLarge) {
		t.Fatalf("Claude Code transform of oversized input: %v", err)
	}
}
