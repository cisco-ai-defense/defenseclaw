// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rel-1-0-3 GAP-0343: the managed Hermes foreign-hook guard blocked a tool
// call and logged it with defenseclaw_log_hook_failure ... policy closed and
// no outcome, so hook-failures.jsonl read outcome=unknown for a call the hook
// blocked (the helper defaults the sixth argument to unknown). Every call of
// the helper in the guard names fail_closed, because the guard only ever
// blocks.
func TestForeignGuardHookFailureRecordsNameTheirOutcome(t *testing.T) {
	word := regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']+`)
	calls := 0
	for _, line := range strings.Split(shellHookForeignGuardBlock, "\n") {
		code := strings.TrimSpace(line)
		at := strings.Index(code, "defenseclaw_log_hook_failure ")
		if strings.HasPrefix(code, "#") || at < 0 {
			continue
		}
		calls++
		args := word.FindAllString(code[at+len("defenseclaw_log_hook_failure "):], -1)
		if len(args) != 6 || args[3] != "policy" || args[4] != "closed" || args[5] != "fail_closed" {
			t.Errorf("foreign guard log call without fail_closed as its outcome: %s", code)
		}
	}
	if calls != 2 {
		t.Fatalf("the foreign guard has %d defenseclaw_log_hook_failure calls, want 2 (lifecycle held, check failed)", calls)
	}
}

// The rendered guard, run with a stub helper, hands the helper the outcome on
// both of its block paths.
func TestForeignGuardBlocksLogFailClosedOutcome(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	dir := t.TempDir()
	guard := filepath.Join(dir, "guard")
	if err := os.WriteFile(guard, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	body := `PAYLOAD='{"hook_event_name":"pre_tool_call","session_id":"s1"}'
_dc_jq() { jq "$@"; }
defenseclaw_log_hook_failure() { printf 'LOG %s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-<none>}" >&2; }
hermes_block() { :; }
defenseclaw_hook_socket_trusted() { return 1; }
defenseclaw_json_escape() { printf '%s' "$1"; }
defenseclaw_managed_lifecycle_held() { [ "$HELD" = 1 ]; }
` + shellHookForeignGuard(guard) + "\necho allowed >&2\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, held, reason string }{
		{"check gave no answer", "0", "enterprise_foreign_hook_check_failed"},
		{"lifecycle held", "1", "managed lifecycle in progress"},
	} {
		cmd := exec.Command(bash, script)
		cmd.Env = append(os.Environ(), "HELD="+tc.held)
		out, _ := cmd.CombinedOutput()
		text := string(out)
		want := "LOG hermes|hermes-hook|"
		if !strings.Contains(text, want) || !strings.Contains(text, tc.reason) || !strings.Contains(text, "|policy|closed|fail_closed") {
			t.Errorf("%s: the guard's log call = %q, want %s... %s policy closed fail_closed", tc.name, text, want, tc.reason)
		}
		if strings.Contains(text, "allowed") {
			t.Errorf("%s: the guard let the call through: %q", tc.name, text)
		}
	}
}
