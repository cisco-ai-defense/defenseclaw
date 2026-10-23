// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCursorHookInputFile(t *testing.T) {
	hookDir := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hook_event_name":"beforeSubmitPrompt","prompt":"hello"}`)
	path := filepath.Join(hookDir, ".cursor-input-test.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := openCursorHookInputFile(hookDir, path)
	if err != nil {
		t.Fatalf("openCursorHookInputFile: %v", err)
	}
	got, err := io.ReadAll(input)
	_ = input.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestOpenCursorHookInputFileRejectsUntrustedPaths(t *testing.T) {
	hookDir := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), ".cursor-input-outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if input, err := openCursorHookInputFile(hookDir, outside); err == nil {
		_ = input.Close()
		t.Fatal("accepted input outside the hooks directory")
	}
	wrongName := filepath.Join(hookDir, "payload.json")
	if err := os.WriteFile(wrongName, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if input, err := openCursorHookInputFile(hookDir, wrongName); err == nil {
		_ = input.Close()
		t.Fatal("accepted a non-managed filename")
	}
	oversized := filepath.Join(hookDir, ".cursor-input-oversized.json")
	f, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(cursorHookInputMaxBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	if input, err := openCursorHookInputFile(hookDir, oversized); err == nil {
		_ = input.Close()
		t.Fatal("accepted an oversized payload")
	}
}

// writeHookSidecarForTest writes a hooks/.hookcfg under home so buildHookOptions
// can resolve the gateway address + fail mode without per-install flags (the
// Windows command form).
func writeHookSidecarForTest(t *testing.T, home, body string) {
	t.Helper()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg"), []byte(body), 0o600); err != nil {
		t.Fatalf("write .hookcfg: %v", err)
	}
}

func TestBuildHookOptionsEnvWiring(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "secret")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "yes")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "closed")
	t.Setenv("DEFENSECLAW_TRACEPARENT", "tp-value")
	writeHookSidecarForTest(t, home, "DEFENSECLAW_FAIL_MODE=closed\n")

	opts := buildHookOptions("codex", "PreToolUse", "127.0.0.1:9999", "open")

	if opts.Connector != "codex" {
		t.Errorf("connector = %q", opts.Connector)
	}
	if opts.APIAddr != "127.0.0.1:9999" {
		t.Errorf("api addr = %q, want flag value", opts.APIAddr)
	}
	if opts.Token != "secret" {
		t.Errorf("token = %q", opts.Token)
	}
	if !opts.StrictAvailability {
		t.Error("strict availability not parsed from env")
	}
	// An old registered open flag cannot change the per-user closed mode.
	if opts.FailMode != "closed" {
		t.Errorf("fail mode = %q, want closed", opts.FailMode)
	}
	if opts.TraceParent != "tp-value" {
		t.Errorf("traceparent = %q", opts.TraceParent)
	}
	if opts.Home != home {
		t.Errorf("home = %q, want %q", opts.Home, home)
	}
	if opts.HookDir != filepath.Join(home, "hooks") {
		t.Errorf("hookDir = %q", opts.HookDir)
	}
}

func TestBuildHookOptionsDefaultAPIAddr(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	opts := buildHookOptions("cursor", "", "", "open")
	if opts.APIAddr == "" {
		t.Fatal("expected a default api addr when flag and env are empty")
	}
}

func TestHookCommandExposesOnlyHiddenContractBinding(t *testing.T) {
	cmd := newHookCmd()
	flag := cmd.Flags().Lookup("hook-contract")
	if flag == nil {
		t.Fatal("hook command is missing installer-bound contract flag")
	}
	if !flag.Hidden {
		t.Fatal("hook-contract must remain a hidden machine-facing flag")
	}
}

func TestBuildHookOptionsSidecarFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	// Ensure env does not mask the sidecar fallback path.
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	writeHookSidecarForTest(t, home, "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:12345\nDEFENSECLAW_FAIL_MODE=closed\n")

	// Empty flags + empty env: the sidecar supplies both values.
	opts := buildHookOptions("codex", "", "", "")
	if opts.APIAddr != "127.0.0.1:12345" {
		t.Errorf("api addr = %q, want sidecar value", opts.APIAddr)
	}
	if opts.FailMode != "closed" {
		t.Errorf("fail mode = %q, want sidecar value 'closed'", opts.FailMode)
	}
}

func TestBuildHookOptionsConnectorScopedSidecarMixedModes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	writeHookSidecarForTest(t, home, `{
  "version": 2,
  "gateway_addr": "127.0.0.1:12345",
  "fail_modes": {"claudecode": "closed", "codex": "open"},
  "fail_mode_sources": {"claudecode": "config", "codex": "config"}
}`)

	claude := buildHookOptions("claudecode", "", "", "")
	codex := buildHookOptions("codex", "", "", "")
	if claude.FailMode != "closed" || codex.FailMode != "closed" {
		t.Fatalf("mixed sidecar collapsed: Claude=%q Codex=%q", claude.FailMode, codex.FailMode)
	}
	if claude.APIAddr != "127.0.0.1:12345" || codex.APIAddr != claude.APIAddr {
		t.Fatalf("shared gateway address not preserved: Claude=%q Codex=%q", claude.APIAddr, codex.APIAddr)
	}
}

func TestBuildHookOptionsFlagAndEnvBeatSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	writeHookSidecarForTest(t, home, "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:12345\nDEFENSECLAW_FAIL_MODE=closed\n")

	// An explicit flag for the address wins over the sidecar.
	opts := buildHookOptions("codex", "", "127.0.0.1:7000", "")
	if opts.APIAddr != "127.0.0.1:7000" {
		t.Errorf("api addr = %q, want flag value over sidecar", opts.APIAddr)
	}

	// An inherited environment cannot reopen the installed closed mode
	// (GAP-0315).
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	opts = buildHookOptions("codex", "", "", "")
	if opts.FailMode != "closed" {
		t.Errorf("fail mode = %q, want the sidecar's closed over env 'open'", opts.FailMode)
	}
	if hookPreRunFailsClosed(hookFailureContext{connector: "kiro"}) != true {
		t.Error("pre-run failure: env 'open' reopened a closed kiro hook")
	}

	// An older installed open mode or explicit flag cannot open a per-user hook.
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:12345","fail_modes":{"codex":"open","kiro":"open"},"fail_mode_sources":{"codex":"config","kiro":"config"}}`)
	for _, env := range []string{"", " Closed ", "closed", "CLOSED"} {
		t.Setenv("DEFENSECLAW_FAIL_MODE", env)
		if opts = buildHookOptions("codex", "", "", ""); opts.FailMode != "closed" {
			t.Errorf("env %q: fail mode = %q, want closed", env, opts.FailMode)
		}
		if opts = buildHookOptions("codex", "", "", "open"); opts.FailMode != "closed" {
			t.Errorf("env %q: fail mode = %q, want closed", env, opts.FailMode)
		}
		if !hookPreRunFailsClosed(hookFailureContext{connector: "kiro"}) {
			t.Errorf("env %q: pre-run failure opened a kiro hook", env)
		}
	}

	// Upgrade path: 0.8.x and 1.0.2 open sidecars stay closed even if an older
	// config saved open. An inherited open cannot reopen another connector.
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	for _, body := range []string{
		"DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:12345\nDEFENSECLAW_FAIL_MODE=open\n",
		`{"version":2,"gateway_addr":"127.0.0.1:12345","fail_modes":{"codex":"open","claudecode":"closed"}}`,
	} {
		writeHookSidecarForTest(t, home, body)
		_ = os.Remove(filepath.Join(home, "config.yaml"))
		if opts = buildHookOptions("codex", "", "", ""); opts.FailMode != "closed" {
			t.Errorf("sidecar %q without a configured open: fail mode = %q, want closed", body, opts.FailMode)
		}
		if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("guardrail:\n  hook_fail_mode: open\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if opts = buildHookOptions("codex", "", "", ""); opts.FailMode != "closed" {
			t.Errorf("sidecar %q: fail mode = %q, want closed", body, opts.FailMode)
		}
	}
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	if opts = buildHookOptions("claudecode", "", "", ""); opts.FailMode != "closed" {
		t.Errorf("v2 sidecar closed claudecode: fail mode = %q, want closed over env open", opts.FailMode)
	}
}

func TestReadHookSidecarParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".hookcfg")
	body := "# comment line\nexport DEFENSECLAW_GATEWAY_ADDR=\"127.0.0.1:18970\"\nDEFENSECLAW_FAIL_MODE=closed\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readHookSidecarGatewayAddr(path); got != "127.0.0.1:18970" {
		t.Errorf("addr = %q", got)
	}
	if got := readHookSidecarGatewayAddr(filepath.Join(dir, "absent")); got != "" {
		t.Errorf("expected no address for missing file, got %q", got)
	}
}

// Every per-user native hook remains closed across legacy and malformed
// sidecar shapes, including a saved open from an older release.
func TestReadHookSidecarMalformedConnectorMapResolvesClosed(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"null-map", `{"version":2,"fail_modes":null,"legacy_fail_mode":"open"}`, "closed"},
		{"list-map", `{"version":2,"fail_modes":["open"],"legacy_fail_mode":"open"}`, "closed"},
		{"false-map", `{"version":2,"fail_modes":false,"legacy_fail_mode":"open"}`, "closed"},
		{"string-map", `{"version":2,"fail_modes":"open","legacy_fail_mode":"open"}`, "closed"},
		{"non-string-entry", `{"version":2,"fail_modes":{"codex":true},"legacy_fail_mode":"open"}`, "closed"},
		{"blank-entry", `{"version":2,"fail_modes":{"codex":""},"legacy_fail_mode":"open"}`, "closed"},
		{"space-entry", `{"version":2,"fail_modes":{"codex":" "},"legacy_fail_mode":"open"}`, "closed"},
		// Controls.
		{"missing-map-legacy-open", `{"version":2,"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`, "closed"},
		{"empty-map-legacy-open", `{"version":2,"fail_modes":{},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`, "closed"},
		{"peer-entry-legacy-open", `{"version":2,"fail_modes":{"claudecode":"closed"},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`, "closed"},
		{"own-entry-open", `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"},"legacy_fail_mode":"closed"}`, "closed"},
		// An open no config chose (w3-g3-upg) is closed.
		{"own-entry-open-unsourced", `{"version":2,"fail_modes":{"codex":"open"},"legacy_fail_mode":"closed"}`, "closed"},
		{"own-entry-closed", `{"version":2,"fail_modes":{"codex":"closed"},"legacy_fail_mode":"open"}`, "closed"},
		// 1.0.4 lead directive: JSON that does not parse, or is not a v2
		// sidecar, is malformed state and closed; it is never read as
		// KEY=value lines, where a stray line would otherwise open it.
		{"unparseable-json-with-a-flat-open-line", "{\"version\":2,\"fail_modes\":{\"codex\":\"open\"}\nDEFENSECLAW_FAIL_MODE=open\n", "closed"},
		{"brace-then-flat-open-line", "  {\nDEFENSECLAW_FAIL_MODE=open\n", "closed"},
		{"version-1", `{"version":1,"fail_modes":{"codex":"open"},"legacy_fail_mode":"open"}`, "closed"},
		{"version-string", `{"version":"2","fail_modes":{"codex":"open"}}`, "closed"},
		{"version-fraction", `{"version":2.5,"fail_modes":{"codex":"open"}}`, "closed"},
		{"no-version", `{"fail_modes":{"codex":"open"}}`, "closed"},
		{"array", `["DEFENSECLAW_FAIL_MODE=open"]`, "closed"},
		{"scalar", `"open"`, "closed"},
		{"empty-file", "", "closed"},
		// The 0.8.x KEY=value sidecar cannot reopen a per-user hook.
		{"flat-open-without-a-config-source", "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n", "closed"},
		{"flat-scoped-closed", "DEFENSECLAW_FAIL_MODE=open\nDEFENSECLAW_FAIL_MODE_CODEX=closed\n", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			writeHookSidecarForTest(t, home, tc.body)
			if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != tc.want {
				t.Fatalf("fail mode %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("missing-file", func(t *testing.T) {
		if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "closed" {
			t.Fatalf("fail mode %q, want closed", got)
		}
	})
}

func TestBuildHookOptionsRejectsNonLoopbackAddr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	// A compromised agent process points the hook at an attacker host to
	// exfiltrate the payload + bearer token. The native hook must ignore it
	// and fall back to the local gateway, matching the .sh hooks.
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "evil.example.com:443")

	opts := buildHookOptions("codex", "", "", "open")
	if opts.APIAddr == "evil.example.com:443" {
		t.Fatal("non-loopback gateway address from env must be rejected")
	}
	if !hookIsLoopbackAddr(opts.APIAddr) {
		t.Fatalf("fallback api addr %q is not loopback", opts.APIAddr)
	}

	// A non-loopback IP literal is likewise refused.
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "10.0.0.5:8787")
	opts = buildHookOptions("codex", "", "", "open")
	if !hookIsLoopbackAddr(opts.APIAddr) {
		t.Fatalf("fallback api addr %q is not loopback", opts.APIAddr)
	}
}

func TestHookIsLoopbackAddr(t *testing.T) {
	loopback := []string{
		"127.0.0.1:8787", "127.0.0.1", "localhost:9000", "LocalHost",
		"[::1]:8787", "::1", "127.5.6.7:1",
	}
	for _, a := range loopback {
		if !hookIsLoopbackAddr(a) {
			t.Errorf("hookIsLoopbackAddr(%q) = false, want true", a)
		}
	}
	remote := []string{
		"", "evil.example.com:443", "10.0.0.5:8787", "0.0.0.0:8787",
		":8787", "8.8.8.8", "192.168.1.10:80",
	}
	for _, a := range remote {
		if hookIsLoopbackAddr(a) {
			t.Errorf("hookIsLoopbackAddr(%q) = true, want false", a)
		}
	}
}

func TestHookCommandRegisteredAndHidden(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"hook"})
	if err != nil {
		t.Fatalf("hook command not found: %v", err)
	}
	if cmd.Name() != "hook" {
		t.Fatalf("found %q, want hook", cmd.Name())
	}
	if !cmd.Hidden {
		t.Error("hook command should be hidden")
	}
}

func TestNotifyCommandRegisteredAndHidden(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"notify"})
	if err != nil {
		t.Fatalf("notify command not found: %v", err)
	}
	if cmd.Name() != "notify" {
		t.Fatalf("found %q, want notify", cmd.Name())
	}
	if !cmd.Hidden {
		t.Error("notify command should be hidden")
	}
	if err := cmd.Args(cmd, nil); err == nil {
		t.Error("notify command accepted a missing Codex JSON payload")
	}
	if err := cmd.Args(cmd, []string{`{"type":"agent-turn-complete"}`}); err != nil {
		t.Errorf("notify command rejected one JSON payload argument: %v", err)
	}
}
