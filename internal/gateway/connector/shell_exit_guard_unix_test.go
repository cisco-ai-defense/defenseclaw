// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
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
					if !closed {
						// Fail mode open keeps the exit status (an unmarked 0
						// counts as 1): never a block, never an allow by
						// accident of bash's status.
						if run.exitCode != 1 && (failureName != "deliberate exit 3" || run.exitCode != 3) {
							t.Fatalf("open exit = %d, want the failure status (stdout %q, stderr %q)", run.exitCode, run.stdout, run.stderr)
						}
						if strings.Contains(run.stdout, `"deny"`) {
							t.Fatalf("open stdout = %q, want no deny", run.stdout)
						}
						return
					}
					switch {
					case connectorName == "cursor":
						if run.exitCode != 2 || !strings.Contains(run.stdout, `"permission":"deny"`) {
							t.Fatalf("closed cursor exit=%d stdout=%q, want 2 and the deny object (stderr %q)", run.exitCode, run.stdout, run.stderr)
						}
					case connectorName == "codex" && !p.managed:
						// Codex reads a non-zero UserPromptSubmit status as a
						// hook failure; the block is its deny object (GAP-0949).
						if run.exitCode != 0 || !strings.Contains(run.stdout, `"permissionDecision":"deny"`) {
							t.Fatalf("closed per-user codex exit=%d stdout=%q, want 0 and the deny object (stderr %q)", run.exitCode, run.stdout, run.stderr)
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
