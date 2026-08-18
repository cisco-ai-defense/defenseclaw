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
	if opts.FailMode != "closed" {
		t.Errorf("fail mode = %q, want env override 'closed'", opts.FailMode)
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
  "fail_modes": {"claudecode": "closed", "codex": "open"}
}`)

	claude := buildHookOptions("claudecode", "", "", "")
	codex := buildHookOptions("codex", "", "", "")
	if claude.FailMode != "closed" || codex.FailMode != "open" {
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

	// The env var wins over the sidecar fail mode.
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	opts = buildHookOptions("codex", "", "", "")
	if opts.FailMode != "open" {
		t.Errorf("fail mode = %q, want env override 'open' over sidecar", opts.FailMode)
	}
}

func TestReadHookSidecarParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".hookcfg")
	body := "# comment line\nexport DEFENSECLAW_GATEWAY_ADDR=\"127.0.0.1:18970\"\nDEFENSECLAW_FAIL_MODE=closed\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readHookSidecar(path)
	if got["DEFENSECLAW_GATEWAY_ADDR"] != "127.0.0.1:18970" {
		t.Errorf("addr = %q", got["DEFENSECLAW_GATEWAY_ADDR"])
	}
	if got["DEFENSECLAW_FAIL_MODE"] != "closed" {
		t.Errorf("fail mode = %q", got["DEFENSECLAW_FAIL_MODE"])
	}
	// A missing file yields an empty map, not a nil-map panic.
	if m := readHookSidecar(filepath.Join(dir, "absent")); len(m) != 0 {
		t.Errorf("expected empty map for missing file, got %v", m)
	}
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
