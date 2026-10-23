// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1421: on a per-user Linux or macOS install Claude Code's native OTLP
// exporter gets its bearer from the otelHeadersHelper, which withholds it
// while another account holds the gateway API port and this account's
// gateway is stopped. Linux reads the holder from /proc/net/tcp*; the
// helper's argument replaces that folder here.
func TestClaudeCodeOTLPHeadersHelperWithholdsTheBearerFromAnotherAccountsListener(t *testing.T) {
	dir := t.TempDir()
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18960"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("ab", 32)
	if err := os.WriteFile(filepath.Join(hookDir, ".otlp-claudecode.token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(hookDir, claudeCodeOTLPHeadersHelperScript)
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	row := func(addr string, uid int) string {
		return fmt.Sprintf("   0: %s:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 4242 1 0 100 0 0 10 0\n", addr, uid)
	}
	own := os.Getuid()
	for _, test := range []struct {
		name, tcp, tcp6 string
		bearer          bool
	}{
		{name: "another account on 127.0.0.1", tcp: row("0100007F", own+4242)},
		{name: "another account on ::1", tcp6: row("00000000000000000000000001000000", own+4242)},
		{name: "this account", tcp: row("0100007F", own), bearer: true},
		{name: "free port", bearer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			net := filepath.Join(t.TempDir(), "net")
			if err := os.Mkdir(net, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"tcp": header + test.tcp, "tcp6": header + test.tcp6} {
				if err := os.WriteFile(filepath.Join(net, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", helper, net)
			cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+t.TempDir())
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("helper: %v\n%s", err, out)
			}
			var headers map[string]string
			if err := json.Unmarshal(out, &headers); err != nil {
				t.Fatalf("helper printed %q: %v", out, err)
			}
			if headers["x-defenseclaw-source"] != "claudecode" {
				t.Fatalf("headers = %v, want the claudecode source", headers)
			}
			got, sent := headers["authorization"]
			if sent != test.bearer || (sent && got != "Bearer "+token) {
				t.Fatalf("authorization = %q (sent %v), want sent %v", got, sent, test.bearer)
			}
		})
	}
}

// Setup writes the helper instead of a static bearer and records the
// operator's own helper; Teardown takes DefenseClaw's out and puts the
// operator's back. Token rotation probes the bearer the helper prints.
func TestClaudeCodeSetupUsesTheOTLPHeadersHelperAndTeardownRestoresTheOperatorsOwn(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude-settings", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"otelHeadersHelper": "/usr/local/bin/my-headers"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	read := func() map[string]interface{} {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		var settings map[string]interface{}
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatal(err)
		}
		return settings
	}
	settings := read()
	if got, want := settings["otelHeadersHelper"], filepath.Join(dir, "hooks", claudeCodeOTLPHeadersHelperScript); got != want {
		t.Fatalf("otelHeadersHelper = %v, want %s", got, want)
	}
	env, _ := settings["env"].(map[string]interface{})
	for _, key := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_HEADERS"} {
		value, _ := env[key].(string)
		if value == "" || strings.Contains(strings.ToLower(value), "authorization") {
			t.Fatalf("%s = %q, want the attribution headers without a bearer", key, value)
		}
	}
	if env[claudeCodeOTLPHeadersHelperDebounce] != claudeCodeOTLPHeadersHelperDebounceMS {
		t.Fatalf("%s = %v, want %s", claudeCodeOTLPHeadersHelperDebounce, env[claudeCodeOTLPHeadersHelperDebounce], claudeCodeOTLPHeadersHelperDebounceMS)
	}
	if _, err := os.Stat(filepath.Join(dir, "hooks", claudeCodeOTLPHeadersHelperScript)); err != nil {
		t.Fatalf("helper script: %v", err)
	}
	token, err := LoadOTLPPathToken(dir, OTLPScopeClaude)
	if err != nil || token == "" {
		t.Fatalf("scoped token = %q, %v", token, err)
	}
	probes, err := LoadClaudeCodeNativeOTLPProbes()
	if err != nil || len(probes) != 2 {
		t.Fatalf("probes = %v, %v", probes, err)
	}
	for _, probe := range probes {
		if probe.Headers.Get("Authorization") != "Bearer "+token {
			t.Fatalf("%s probe does not carry the helper's bearer", probe.Signal)
		}
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := read()["otelHeadersHelper"]; got != "/usr/local/bin/my-headers" {
		t.Fatalf("otelHeadersHelper after teardown = %v, want the operator's own", got)
	}
}
