// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// guardBeside makes the guard program report its path as
// <dir>\defenseclaw-hook-guard.exe, so the Codex guard starts
// <dir>\defenseclaw-hook.exe.
func guardBeside(t *testing.T, dir string) {
	t.Helper()
	previous := guardExecutable
	guardExecutable = func() (string, error) { return filepath.Join(dir, "defenseclaw-hook-guard.exe"), nil }
	t.Cleanup(func() { guardExecutable = previous })
}

func codexGuardArgs(event, contract string) []string {
	return []string{hookguard.SiblingSubcommand, "hook", "--connector", "codex", "--event", event, "--hook-contract", contract}
}

// The Codex guard starts the launcher beside it with the bound Codex hook
// argv and passes a started launcher's answer and exit code through
// (rel-1-0-6 GAP-0676).
func TestCodexGuardRunsTheLauncherBesideItAndPassesItsAnswer(t *testing.T) {
	launcher := fakeLauncher(t)
	guardBeside(t, filepath.Dir(launcher))
	for name, tc := range map[string]struct {
		stdin string
		code  int
	}{
		"allow": {`{"hook_event_name":"PreToolUse","allow":true}`, 0},
		"block": {`{"hook_event_name":"PreToolUse","deny":true}`, 2},
		"other": {`{"hook_event_name":"PreToolUse"}`, 7},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runGuard(codexGuardArgs("PreToolUse", "codex-hooks-v4"), tc.stdin)
			var report struct {
				Args  []string `json:"args"`
				Stdin string   `json:"stdin"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("launcher answer %q (exit %d, stderr %q): %v", out, code, errOut, err)
			}
			want := []string{"hook", "--connector", "codex", "--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}
			if code != tc.code || !reflect.DeepEqual(report.Args, want) || report.Stdin != tc.stdin || errOut != "fake launcher stderr" {
				t.Fatalf("exit %d, launcher saw %+v, stderr %q; want exit %d, argv %v and the launcher's stdin and stderr", code, report, errOut, tc.code, want)
			}
		})
	}
}

// A launcher that is missing or cannot start gets Codex's block for the
// event (JSON, exit 0: Codex reads a non-zero prompt status as a failed hook,
// GAP-0949). A stop, and an event Codex gives no control, get no blocking
// answer. The sentence says "missing" only when nothing is there.
func TestCodexGuardAnswersCodexBlockWhenTheLauncherCannotStart(t *testing.T) {
	missingDir := t.TempDir()
	folderDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(folderDir, "defenseclaw-hook.exe"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, place := range []struct {
		name, dir, sentence string
	}{
		{"missing", missingDir, hookguard.LauncherMessage("Codex", true)},
		{"a directory", folderDir, hookguard.LauncherMessage("Codex", false)},
	} {
		for _, tc := range []struct {
			event, contract, want string
		}{
			{"PreToolUse", "codex-hooks-v4", `"permissionDecision":"deny"`},
			{"PermissionRequest", "codex-hooks-v1", `"behavior":"deny"`},
			{"UserPromptSubmit", "codex-hooks-v4", `"decision":"block"`},
			{"PostToolUse", "codex-hooks-v2", `"decision":"block"`},
			{"SessionStart", "codex-hooks-v4", `"continue":false`},
			{"SessionStart", "codex-hooks-v2", ""},
			{"Stop", "codex-hooks-v4", ""},
			{"SubagentStop", "codex-hooks-v4", ""},
			{"SessionEnd", "codex-hooks-v4", ""},
		} {
			t.Run(place.name+"/"+tc.event+"/"+tc.contract, func(t *testing.T) {
				guardBeside(t, place.dir)
				code, stdout, stderr := runGuard(codexGuardArgs(tc.event, tc.contract), `{"hook_event_name":"`+tc.event+`"}`)
				if code != 0 || strings.TrimSpace(stderr) != place.sentence {
					t.Fatalf("exit %d, stderr %q; want exit 0 with %q", code, stderr, place.sentence)
				}
				if tc.want == "" {
					if stdout != "" {
						t.Fatalf("stdout %q; want no answer", stdout)
					}
					return
				}
				if !strings.Contains(stdout, tc.want) || !strings.Contains(stdout, place.sentence) || !json.Valid([]byte(stdout)) {
					t.Fatalf("stdout %q; want one JSON block with %s and the sentence", stdout, tc.want)
				}
			})
		}
	}
}

// Only the exact bound Codex argv is the Codex guard; anything else is
// refused with exit 2 and starts nothing.
func TestCodexGuardRefusesAnyOtherArgv(t *testing.T) {
	guardBeside(t, filepath.Dir(fakeLauncher(t)))
	for name, args := range map[string][]string{
		"other connector": {hookguard.SiblingSubcommand, "hook", "--connector", "kiro", "--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
		"other contract":  {hookguard.SiblingSubcommand, "hook", "--connector", "codex", "--event", "PreToolUse", "--hook-contract", "kiro-hooks-v1"},
		"no contract":     {hookguard.SiblingSubcommand, "hook", "--connector", "codex", "--event", "PreToolUse"},
		"spaced event":    {hookguard.SiblingSubcommand, "hook", "--connector", "codex", "--event", "Pre Tool", "--hook-contract", "codex-hooks-v4"},
		"extra argument":  append(codexGuardArgs("PreToolUse", "codex-hooks-v4"), "--enterprise-managed"),
		"a launcher path": {hookguard.SiblingSubcommand, `C:\x\defenseclaw-hook.exe`, "hook", "--connector", "codex"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runGuard(args, `{"allow":true}`)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "only \"launcher-guard\"") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want the exit-2 refusal", code, stdout, stderr)
			}
		})
	}
}
