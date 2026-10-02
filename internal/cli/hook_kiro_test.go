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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runKiroHookForTest runs the hook command in-process against gatewayURL
// with payload on stdin and returns the exit status hookexec chose.
func runKiroHookForTest(t *testing.T, gatewayAddr, payload string, args ...string) int {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "hooks", ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", home)
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
	cmd.SetArgs(append([]string{"--api-addr", gatewayAddr, "--fail-mode", "open"}, args...))
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

// The .kiro/hooks command runs end to end: the flag parses, the v3 marker
// reaches the gateway in the dialect header, and a block comes back as exit
// 2 (Kiro's veto). The CLI 2.x agent command carries no marker.
func TestKiroHookCommandRunsAndForwardsItsSurface(t *testing.T) {
	var gotDialect, gotLegacy, gotPath string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotDialect = r.Header.Get("X-DefenseClaw-Hook-Dialect")
		gotLegacy = r.Header.Get("X-DefenseClaw-Kiro-Surface")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"block","hook_output":{"decision":"block","reason":"marker rule matched"}}`)
	}))
	defer gateway.Close()
	addr := strings.TrimPrefix(gateway.URL, "http://")

	code := runKiroHookForTest(t, addr, `{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`,
		"--connector", "kiro", "--hook-surface", "v3")
	if code != 2 {
		t.Fatalf("v3 block exit = %d, want 2", code)
	}
	if gotPath != "/api/v1/kiro/hook" || gotDialect != "v3" || gotLegacy != "" {
		t.Fatalf("request path=%q dialect=%q legacy=%q, want /api/v1/kiro/hook, v3, none", gotPath, gotDialect, gotLegacy)
	}

	code = runKiroHookForTest(t, addr, `{"hook_event_name":"preToolUse","tool_name":"shell"}`,
		"--connector", "kiro")
	if code != 2 {
		t.Fatalf("CLI 2.x block exit = %d, want 2", code)
	}
	if gotDialect != "" {
		t.Fatalf("unmarked CLI 2.x command sent dialect %q", gotDialect)
	}
}

// A Kiro hook that fails before it can run (a flag it does not know, a value
// it does not list, a stray argument) must exit 2 so Kiro blocks instead of
// going ahead, when its policy is to fail closed: an administrator-managed
// hook, or fail mode closed from --fail-mode, the hook sidecar or
// DEFENSECLAW_FAIL_MODE. A fail-open Kiro hook and every other connector
// keep cobra's status 1; the fail-open policy itself is unchanged.
func TestHookPreRunFailureUsesTheConnectorsBlockingExit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		sidecar string
		want    int
	}{
		{name: "kiro fail closed, unknown flag", args: []string{"--connector", "kiro", "--not-a-hook-flag", "--fail-mode", "closed"}, want: 2},
		{name: "kiro managed, connector spelled with =", args: []string{"--connector=kiro", "--not-a-hook-flag", "--enterprise-managed"}, want: 2},
		{name: "kiro closed in the hook sidecar", args: []string{"--connector", "kiro", "--hook-surface", "v9"}, sidecar: `{"version":2,"fail_modes":{"kiro":"closed"}}`, want: 2},
		{name: "kiro fail open keeps 1", args: []string{"--connector", "kiro", "--not-a-hook-flag"}, want: 1},
		{name: "codex unknown flag", args: []string{"--connector", "codex", "--not-a-hook-flag", "--fail-mode", "closed"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_FAIL_MODE", "")
			if tc.sidecar != "" {
				if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, "hooks", ".hookcfg"), []byte(tc.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previous := hookRawArgs
			hookRawArgs = func() []string { return tc.args }
			t.Cleanup(func() { hookRawArgs = previous })
			cmd := newHookCmd()
			cmd.SetArgs(tc.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("hook %v succeeded, want a usage failure", tc.args)
			}
			if got := commandExitCode(err); got != tc.want {
				t.Fatalf("hook %v exit = %d, want %d (err=%v)", tc.args, got, tc.want, err)
			}
		})
	}
}
