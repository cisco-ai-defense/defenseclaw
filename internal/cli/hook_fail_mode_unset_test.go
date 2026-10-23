// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B-40 (B-01 merge review item 2): a Windows native per-user hook command
// carries no --fail-mode and relies on hooks/.hookcfg. A missing sidecar, a
// sidecar without the connector's mode and an empty or unknown value all
// resolve closed, as the config resolver does; only an explicit open opens.
func TestNativeHookFailModeWithoutAnExplicitOpenIsClosed(t *testing.T) {
	for _, test := range []struct {
		name, sidecar, flag, want string
	}{
		{name: "missing sidecar", want: "closed"},
		{name: "sidecar without the connector", sidecar: `{"version":2,"gateway_addr":"127.0.0.1:12345","fail_modes":{"codex":"open"}}`, want: "closed"},
		{name: "empty value", sidecar: `{"version":2,"fail_modes":{"claudecode":""}}`, want: "closed"},
		{name: "legacy sidecar without a mode", sidecar: "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:12345\n", want: "closed"},
		{name: "legacy empty value", sidecar: "DEFENSECLAW_FAIL_MODE=\n", want: "closed"},
		{name: "unknown value", sidecar: `{"version":2,"fail_modes":{"claudecode":"opne"}}`, want: "closed"},
		{name: "explicit open in the sidecar", sidecar: `{"version":2,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"}}`, want: "open"},
		{name: "explicit open flag", flag: "open", want: "open"},
		{name: "explicit closed flag over an open sidecar", sidecar: `{"version":2,"fail_modes":{"claudecode":"open"}}`, flag: "closed", want: "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
			t.Setenv("DEFENSECLAW_FAIL_MODE", "")
			if test.sidecar != "" {
				writeHookSidecarForTest(t, home, test.sidecar)
			}
			if got := buildHookOptions("claudecode", "PreToolUse", "", test.flag).FailMode; got != test.want {
				t.Fatalf("fail mode = %q, want %q", got, test.want)
			}
		})
	}
}

// A managed hook ignores an explicit open; Secure Client's hook command is
// unchanged (its native runtime is closed).
func TestManagedNativeHookIgnoresAnOpenFailMode(t *testing.T) {
	for _, secureClient := range []bool{false, true} {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		t.Setenv("DEFENSECLAW_FAIL_MODE", "")
		writeHookSidecarForTest(t, home, `{"version":2,"fail_modes":{"codex":"open"}}`)
		previous := secureClientHost
		secureClientHost = func() bool { return secureClient }
		opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "open", true)
		secureClientHost = previous
		if opts.FailMode != "closed" || !opts.ManagedEnterprise {
			t.Fatalf("secure client %v: managed hook fail mode = %q (managed %v), want closed", secureClient, opts.FailMode, opts.ManagedEnterprise)
		}
	}
}

// End to end: a per-user Kiro tool hook with no --fail-mode and no sidecar
// meets a failing gateway and blocks (exit 2, Kiro's veto); with an explicit
// open it goes ahead.
func TestNativeHookWithoutASidecarBlocksOnAGatewayFailure(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer gateway.Close()
	addr := strings.TrimPrefix(gateway.URL, "http://")
	payload := `{"hook_event_name":"preToolUse","tool_name":"shell"}`
	if code := runHookCommandForTest(t, payload, "--connector", "kiro", "--api-addr", addr); code != 2 {
		t.Fatalf("unset fail mode exit = %d, want 2 (blocked)", code)
	}
	if code := runHookCommandForTest(t, payload, "--connector", "kiro", "--api-addr", addr, "--fail-mode", "open"); code != 0 {
		t.Fatalf("explicit open exit = %d, want 0", code)
	}
}

// runHookCommandForTest runs the hook command in-process with no hook
// sidecar and payload on stdin, and returns the exit status hookexec chose.
func runHookCommandForTest(t *testing.T, payload string, args ...string) int {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "hooks", ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "")
	stdin := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(stdin, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previousStdin := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previousStdin })
	code := -1
	previousExit := hookProcessExit
	hookProcessExit = func(status int) { code = status }
	t.Cleanup(func() { hookProcessExit = previousExit })
	cmd := newHookCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("hook %v: %v", args, err)
	}
	if code < 0 {
		t.Fatalf("hook %v returned without an exit status", args)
	}
	return code
}
