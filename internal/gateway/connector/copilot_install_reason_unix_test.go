// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hookWithPrivateListenerTable points the pre-send listener check of a released
// per-user hook script (Copilot, Cursor or Antigravity, 1.0.0 to 1.0.3) at a
// private socket table in place of the host /proc/net.
// The 1.0.0 to 1.0.3 check walks the table one row at a time in Bash, and Linux
// answers each backward seek in /proc/net/tcp by replaying the table from its
// start, so one hook run costs time quadratic in the host's socket count (the
// current helper reads it once through grep, GAP-1756). On a host with many
// sockets, such as a shared build box running other test packages, the run
// passed the hook's own 5 CPU-second bound, was ended by SIGXCPU, and the test
// read that as "exit -1". The check takes the table directory as an argument
// for tests; the held port is bound and never listens, so on the host's table
// and on this one the check finds no listener and the hook goes on to deny.
func hookWithPrivateListenerTable(t *testing.T, hook []byte, netDir string) []byte {
	t.Helper()
	const call = `defenseclaw_api_listener_foreign "$API_ADDR"`
	if bytes.Count(hook, []byte(call)) != 1 {
		t.Fatalf("the released hook no longer calls %s exactly once", call)
	}
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// One listener on another port, so the check still reads a row to skip.
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	return bytes.Replace(hook, []byte(call), []byte(call+" "+shellSingleQuote(netDir)), 1)
}

// TestRefreshedReleasedCopilotHookNamesTheInstallWhileTheLockIsHeld: the
// installer's hold refreshes a published 1.0.0 to 1.0.3 per-user
// copilot-hook.sh to fail closed before it stops the gateway. While the lock
// is held its denial names the install or upgrade, the reason Copilot shows,
// as this release's hook does; without the lock it keeps the generic reason
// (GAP-2319). The call is denied either way.
func TestRefreshedReleasedCopilotHookNamesTheInstallWhileTheLockIsHeld(t *testing.T) {
	requireShellHookToolsForTest(t)
	current, err := hookFS.ReadFile("hooks/copilot-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(copilotInstallWindowReason)) {
		t.Fatal("copilotInstallWindowReason is not the reason this release's copilot-hook.sh gives during an install")
	}
	const generic = "DefenseClaw hook failed closed"
	addr := freeLoopbackAddrForOutageTest(t)
	for _, release := range []string{"1.0.0", "1.0.3"} {
		t.Run(release, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			hookDir := filepath.Join(dataDir, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"_hardening.sh", "copilot-hook.sh"} {
				body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.ReplaceAll(body, []byte(`API_ADDR="127.0.0.1:9"`), []byte(`API_ADDR="`+addr+`"`))
				if name == "copilot-hook.sh" {
					body = hookWithPrivateListenerTable(t, body, filepath.Join(home, "proc-net"))
				}
				if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=outage-test-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := RefreshHookFailModes(hookDir, func(string) string { return "open" }); err != nil {
				t.Fatal(err)
			}
			hook := filepath.Join(hookDir, "copilot-hook.sh")
			lock := filepath.Join(dataDir, ".install.lock")
			reason := func(t *testing.T, event string) string {
				t.Helper()
				cmd := exec.Command("bash", hook, "--event", event)
				cmd.Stdin = strings.NewReader(`{"sessionId":"s1","toolName":"bash","toolArgs":{"command":"ls"}}`)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				out, err := cmd.Output()
				if code := exitCodeOf(err); code != 0 {
					// exitCodeOf reports -1 both for a hook killed by a signal
					// and for a hook that never started; the error tells them
					// apart from a hook that really exited non-zero.
					t.Fatalf("%s: exit %d (%v) stdout=%q", event, code, err, out)
				}
				var answer map[string]any
				if err := json.Unmarshal(bytes.TrimSpace(out), &answer); err != nil {
					t.Fatalf("%s: stdout %q is not one JSON answer: %v", event, out, err)
				}
				field, text := "permissionDecision", "permissionDecisionReason"
				if event == "permissionRequest" {
					field, text = "behavior", "message"
				}
				if answer[field] != "deny" {
					t.Fatalf("%s: answer %v does not deny", event, answer)
				}
				got, _ := answer[text].(string)
				return got
			}
			for _, event := range []string{"preToolUse", "permissionRequest"} {
				if got := reason(t, event); got != generic {
					t.Fatalf("%s without a lock: reason %q, want %q", event, got, generic)
				}
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				if got := reason(t, event); got != copilotInstallWindowReason {
					t.Fatalf("%s while the install holds the lock: reason %q, want the install sentence", event, got)
				}
				// The early failures (here a missing token) name it too.
				token, _ := os.ReadFile(filepath.Join(hookDir, ".token"))
				if err := os.Remove(filepath.Join(hookDir, ".token")); err != nil {
					t.Fatal(err)
				}
				if got := reason(t, event); got != copilotInstallWindowReason {
					t.Fatalf("%s missing token while the lock is held: reason %q, want the install sentence", event, got)
				}
				if err := os.WriteFile(filepath.Join(hookDir, ".token"), token, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
