// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shellExitGuardFailures each break a hook after defenseclaw_harden_env has
// replaced the boot trap, the window GAP-1734 found unguarded outside Secure
// Client macOS. "unmarked exit 0" is what bash 3.2 (macOS /bin/bash) does
// after an unbound variable or a "." of a missing file: the script ends with
// status 0 without any exit of its own.
var shellExitGuardFailures = map[string]string{
	"set -e failure":    "false",
	"unbound variable":  `: "$_DC_TEST_UNSET_AFTER_HARDEN"`,
	"unmarked exit 0":   "builtin exit 0",
	"unmarked exit 1":   "builtin exit 1",
	"unmarked exit 2":   "builtin exit 2",
	"deliberate exit 3": "exit 3",
}

// breakHookAfterHardening keeps the real helper and makes
// defenseclaw_harden_env run FAIL once it has done its work.
func breakHookAfterHardening(t *testing.T, hookDir, fail string) {
	t.Helper()
	path := filepath.Join(hookDir, "_hardening.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\neval \"_dc_test_real_$(declare -f defenseclaw_harden_env)\"\n"+
		"defenseclaw_harden_env() {\n  _dc_test_real_defenseclaw_harden_env\n  : >\"${DEFENSECLAW_HOME}/harden-reached\"\n  "+fail+"\n}\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func renderShellExitGuardHook(t *testing.T, connectorName, failMode string, managed bool) (string, string) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	script := managedHookTestScripts[connectorName]
	// A standalone managed render: managed, not Secure Client.
	if err := writeHookScriptsCommonWithTransport(
		hookDir, "127.0.0.1:1", managedHookTestToken, failMode, HookFailModeSourceConfig,
		[]string{script}, managed, connectorName, true, "", "", false, false,
	); err != nil {
		t.Fatalf("render %s hook: %v", connectorName, err)
	}
	return dataDir, filepath.Join(hookDir, script)
}

// GAP-1734: a per-user or standalone managed Claude Code, Codex or Cursor
// hook that fails unexpectedly after hardening follows its fail mode, as the
// Secure Client macOS prologue does. Exit status 1 (or bash 3.2's 0) used to
// decide the outcome, and the agents read 1 as a non-blocking error: a
// fail-closed hook let the call run.
func TestShellHookUnexpectedFailureAfterHardeningFollowsFailMode(t *testing.T) {
	type profile struct {
		name     string
		managed  bool
		failMode string
	}
	profiles := []profile{
		// A per-user render bakes closed for every non-outage failure.
		{"per-user", false, "open"},
		{"standalone/closed", true, "closed"},
		{"standalone/open", true, "open"},
	}
	for connectorName := range managedHookTestScripts {
		for _, p := range profiles {
			for failureName, fail := range shellExitGuardFailures {
				t.Run(connectorName+"/"+p.name+"/"+failureName, func(t *testing.T) {
					dataDir, script := renderShellExitGuardHook(t, connectorName, p.failMode, p.managed)
					breakHookAfterHardening(t, filepath.Dir(script), fail)
					env := []string{}
					if !p.managed {
						env = append(env, "DEFENSECLAW_HOME="+dataDir)
					}
					run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`, env...)
					if _, err := os.Stat(filepath.Join(dataDir, "harden-reached")); err != nil {
						t.Fatalf("the hook ended before hardening (exit %d, stdout %q, stderr %q): the failure was not injected", run.exitCode, run.stdout, run.stderr)
					}
					closed := !p.managed || p.failMode == "closed"
					// GAP-1757: every unexpected failure, open or closed,
					// leaves one hook-failure record, as the Secure Client
					// macOS prologue does.
					outcome := `"outcome":"fail_open"`
					if closed {
						outcome = `"outcome":"fail_closed"`
					}
					record, _ := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
					if !strings.Contains(string(record), "unexpected hook failure") || !strings.Contains(string(record), outcome) {
						t.Errorf("hook-failures.jsonl = %q, want one unexpected-failure record with %s", record, outcome)
					}
					if !closed {
						// Fail mode open keeps the exit status (an unmarked 0
						// counts as 1): never a block, never an allow by
						// accident of bash's status. An unmarked 2 would be a
						// block: it answers 0, as the Secure Client macOS
						// prologue does (GAP-1756).
						want := 1
						switch failureName {
						case "deliberate exit 3":
							want = 3
						case "unmarked exit 2":
							want = 0
						}
						if run.exitCode != want {
							t.Fatalf("open exit = %d, want %d (stdout %q, stderr %q)", run.exitCode, want, run.stdout, run.stderr)
						}
						if strings.Contains(run.stdout, `"deny"`) {
							t.Fatalf("open stdout = %q, want no deny", run.stdout)
						}
						return
					}
					switch connectorName {
					case "cursor":
						if run.exitCode != 2 || !strings.Contains(run.stdout, `"permission":"deny"`) {
							t.Fatalf("closed cursor exit=%d stdout=%q, want 2 and the deny object (stderr %q)", run.exitCode, run.stdout, run.stderr)
						}
					case "codex":
						// Codex reads a non-zero UserPromptSubmit status as a
						// hook failure; the block is its deny object, per-user
						// (GAP-0949) and standalone managed (GAP-1755).
						if !codexBlockAnswer("PreToolUse", run.exitCode, run.stdout) {
							t.Fatalf("closed %s codex exit=%d stdout=%q, want 0 and the deny object (stderr %q)", p.name, run.exitCode, run.stdout, run.stderr)
						}
					default:
						if run.exitCode != 2 || !strings.Contains(run.stderr, managedHookBlockSentence) {
							t.Fatalf("closed %s exit=%d stderr=%q, want 2 and the block sentence (stdout %q)", connectorName, run.exitCode, run.stderr, run.stdout)
						}
					}
				})
			}
		}
	}
}

// The guard is rendered into every per-user and standalone managed Claude
// Code, Codex and Cursor hook, and into no Secure Client render (Secure
// Client macOS keeps its managed prologue; the other Secure Client renders
// keep their pinned bytes).
func TestShellExitGuardRenderedOutsideSecureClientOnly(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		previous := managedShellGuardGOOS
		managedShellGuardGOOS = goos
		for connectorName, script := range managedHookTestScripts {
			for _, c := range []struct {
				name                  string
				managed, secureClient bool
				want                  bool
			}{
				{"per-user", false, false, true},
				{"standalone", true, false, true},
				{"secure-client", true, true, false},
			} {
				scripts, err := renderHookScripts("127.0.0.1:18970", "closed", ".token-"+connectorName, []string{script}, c.managed, connectorName, true, "", "", c.secureClient, c.secureClient, "/home/u/.defenseclaw")
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range scripts {
					if s.name != script {
						continue
					}
					body := string(s.body)
					if got := strings.Contains(body, "trap '_dc_hook_on_exit' EXIT"); got != c.want {
						t.Errorf("%s %s %s: exit guard rendered = %v, want %v", goos, connectorName, c.name, got, c.want)
					}
					if strings.Contains(body, "_dc_boot_rc") {
						t.Errorf("%s %s %s: the retired boot trap is still rendered", goos, connectorName, c.name)
					}
				}
			}
		}
		managedShellGuardGOOS = previous
	}
}

// GAP-1755: the standalone managed Codex hook blocked with exit 2 (and
// stderr), before its helpers loaded and in every failure after, and its
// oversized-input block printed a block object and exited 2. Codex v0.130+
// reads a non-zero UserPromptSubmit status as a hook failure and submits the
// prompt, so a fail-closed managed hook let the prompt through on a gateway
// outage. codexBlockAnswer is Codex's exit-code contract: only exit 0 with
// one block object of the registered event is a block. Every block of the
// standalone managed hook is now that answer, as the per-user hook's is.
func TestCodexStandaloneManagedHookBlocksEveryEventItCanBlockInCodexsShape(t *testing.T) {
	failures := []struct {
		name string
		// answer is the gateway's answer; nil leaves the port refused.
		answer func(w http.ResponseWriter)
		// breaks changes the rendered state before the call.
		breaks func(t *testing.T, hooks string)
		// payload replaces the event's input.
		payload string
	}{
		{name: "the hardening helper is missing", breaks: func(t *testing.T, hooks string) {
			if err := os.Remove(filepath.Join(hooks, "_hardening.sh")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the gateway is unreachable"},
		{name: "the gateway answers HTTP 503", answer: func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{name: "the gateway answers HTTP 403", answer: func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }},
		{name: "the gateway answers no verdict", answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"action":"maybe"}`)) }},
		{name: "the gateway blocks without codex_output", answer: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"action":"block","reason":"policy says no"}`))
		}},
		{name: "the input is too large to inspect", payload: strings.Repeat(" ", 5000) + "{}"},
		{name: "the payload names another event", payload: codexEventPayload("Notification")},
	}
	for _, event := range codexControlledEvents {
		for _, failure := range failures {
			t.Run(event+"/"+failure.name, func(t *testing.T) {
				t.Parallel()
				addr := refusingAPIAddr(t)
				if failure.answer != nil {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { failure.answer(w) }))
					t.Cleanup(server.Close)
					addr = strings.TrimPrefix(server.URL, "http://")
				}
				hooks := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
				if err := writeHookScriptsCommonWithTransport(hooks, addr, managedHookTestToken, "closed", HookFailModeSourceConfig,
					[]string{"codex-hook.sh"}, true, "codex", true, "", "", false, false); err != nil {
					t.Fatal(err)
				}
				if failure.breaks != nil {
					failure.breaks(t, hooks)
				}
				payload := failure.payload
				if payload == "" {
					payload = codexEventPayload(event)
				}
				args := codexBoundShellHookArgsForTest(t, "codex-hook.sh", event)[1:]
				code, stdout, stderr := runShellHookWith(t, filepath.Join(hooks, "codex-hook.sh"), args,
					[]string{"HOME=" + t.TempDir()}, payload)
				if !codexBlockAnswer(event, code, stdout) {
					t.Fatalf("exit %d stdout %q stderr %q, want Codex's own %s block on stdout with exit 0", code, stdout, stderr, event)
				}
			})
		}
	}
}
