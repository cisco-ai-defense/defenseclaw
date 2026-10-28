// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// A per-user tool call whose shell spent 0.4 s before the request gives the
// helper the 2.6 s left after the startup reserve, not the 2 whole seconds
// that --max-time can carry (GAP-2279: a large benign Bash heredoc was closed
// at about 2.4 s). --max-time itself is unchanged, for an older helper.
func TestHostHookGivesTheHelperTheMillisecondsLeft(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	for _, d := range []string{binDir, hookDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "native-args")
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s %s\\n' \"${_DC_HOOK_POST_DEADLINE_MS:-none}\" \"$*\" > \"$DC_NATIVE_MARKER\"\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	recordGatewayHelperForTest(t, hookDir, binary)
	for _, tc := range []struct {
		name         string
		maxTime      int
		spentMS      int
		wantMaxTime  string
		minMS, maxMS int
	}{
		{"tool call, 0.4 s spent", 4, 400, "2", 2500, 2600},
		{"tool call, 1.2 s spent", 4, 1200, "2", 2000, 2000},
		{"other event, 0.4 s spent", 10, 400, "9", 9500, 9600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
curl() { echo leaked; }
now="${EPOCHREALTIME/[.,]/}"; _DC_HOOK_STARTED_US=$(( 10#$now - $3 * 1000 ))
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" "$4" '{"hook_event_name":"PreToolUse"}' -H 'Authorization: Bearer secret' >/dev/null && echo sent`
			cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir, strconv.Itoa(tc.spentMS), strconv.Itoa(tc.maxTime))
			cmd.Env = append(os.Environ(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home, "DC_NATIVE_MARKER="+marker)
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "sent" {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			got, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Fields(string(got))
			if len(fields) < 7 || fields[5] != tc.wantMaxTime {
				t.Fatalf("helper argv = %q, want --max-time %s", got, tc.wantMaxTime)
			}
			ms, err := strconv.Atoi(fields[0])
			if err != nil || ms < tc.minMS || ms > tc.maxMS {
				t.Fatalf("helper milliseconds = %q, want %d-%d", fields[0], tc.minMS, tc.maxMS)
			}
		})
	}
}
