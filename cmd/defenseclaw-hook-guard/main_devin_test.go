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

func devinGuardArgs(event string) []string {
	return []string{hookguard.DevinSubcommand, event, "hook", "--connector", "devin"}
}

// The Devin guard starts the launcher beside it with Devin's hook argv and
// passes a started launcher's answer and exit code through, on every event
// (rel-1-0-6 GAP-0676).
func TestDevinGuardRunsTheLauncherBesideItAndPassesItsAnswer(t *testing.T) {
	launcher := fakeLauncher(t)
	guardBeside(t, filepath.Dir(launcher))
	for name, tc := range map[string]struct {
		event, stdin string
		code         int
	}{
		"allow":      {"PreToolUse", `{"hook_event_name":"PreToolUse","allow":true}`, 0},
		"block":      {"UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","deny":true}`, 2},
		"other":      {"PermissionRequest", `{"hook_event_name":"PermissionRequest"}`, 7},
		"stop block": {"Stop", `{"hook_event_name":"Stop","deny":true}`, 2},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runGuard(devinGuardArgs(tc.event), tc.stdin)
			var report struct {
				Args  []string `json:"args"`
				Stdin string   `json:"stdin"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("launcher answer %q (exit %d, stderr %q): %v", out, code, errOut, err)
			}
			want := []string{"hook", "--connector", "devin"}
			if code != tc.code || !reflect.DeepEqual(report.Args, want) || report.Stdin != tc.stdin || errOut != "fake launcher stderr" {
				t.Fatalf("exit %d, launcher saw %+v, stderr %q; want exit %d, argv %v and the launcher's stdin and stderr", code, report, errOut, tc.code, want)
			}
		})
	}
}

// A launcher that is missing or cannot start blocks the events the Devin
// guard is registered on (exit 2, the only Devin block) and never blocks any
// other event. The sentence says "missing" only when nothing is there.
func TestDevinGuardBlocksWhenTheLauncherCannotStart(t *testing.T) {
	missingDir := t.TempDir()
	folderDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(folderDir, "defenseclaw-hook.exe"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, place := range []struct {
		name, dir, sentence string
	}{
		{"missing", missingDir, hookguard.LauncherMessage("Devin", true)},
		{"a directory", folderDir, hookguard.LauncherMessage("Devin", false)},
	} {
		for _, tc := range []struct {
			event string
			code  int
		}{
			{"PreToolUse", 2},
			{"PermissionRequest", 2},
			{"UserPromptSubmit", 2},
			{"Stop", 0},
			{"SessionEnd", 0},
			{"PostToolUse", 0},
		} {
			t.Run(place.name+"/"+tc.event, func(t *testing.T) {
				guardBeside(t, place.dir)
				code, stdout, stderr := runGuard(devinGuardArgs(tc.event), `{"hook_event_name":"`+tc.event+`"}`)
				wantStdout := ""
				if tc.code == 2 {
					wantStdout = place.sentence
				}
				if code != tc.code || strings.TrimSpace(stderr) != place.sentence || strings.TrimSpace(stdout) != wantStdout {
					t.Fatalf("exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr %q", code, stdout, stderr, tc.code, wantStdout, place.sentence)
				}
			})
		}
	}
}

// Only the exact Devin guard argv is the Devin guard; anything else is
// refused with exit 2 and starts nothing.
func TestDevinGuardRefusesAnyOtherArgv(t *testing.T) {
	guardBeside(t, filepath.Dir(fakeLauncher(t)))
	for name, args := range map[string][]string{
		"other connector": {hookguard.DevinSubcommand, "PreToolUse", "hook", "--connector", "kiro"},
		"no event":        {hookguard.DevinSubcommand, "hook", "--connector", "devin"},
		"managed":         append(devinGuardArgs("PreToolUse"), "--enterprise-managed"),
		"a launcher path": {hookguard.DevinSubcommand, `C:\x\defenseclaw-hook.exe`, "hook", "--connector", "devin"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runGuard(args, `{"allow":true}`)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "only \"launcher-guard\"") || !strings.Contains(stderr, hookguard.DevinSubcommand) {
				t.Fatalf("exit %d, stdout %q, stderr %q; want the exit-2 refusal that names every guard argv", code, stdout, stderr)
			}
		})
	}
}
