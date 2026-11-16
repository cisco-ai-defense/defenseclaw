// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDevinArgvAcceptsOnlyTheBoundDevinArgv(t *testing.T) {
	hookArgs, event, ok := DevinArgv([]string{DevinSubcommand, "UserPromptSubmit", "hook", "--connector", "devin"})
	if !ok || event != "UserPromptSubmit" || !reflect.DeepEqual(hookArgs, []string{"hook", "--connector", "devin"}) {
		t.Fatalf("DevinArgv = %v %q %v", hookArgs, event, ok)
	}
	for name, args := range map[string][]string{
		"codex":          {DevinSubcommand, "PreToolUse", "hook", "--connector", "codex"},
		"no event":       {DevinSubcommand, "hook", "--connector", "devin"},
		"quoted event":   {DevinSubcommand, `Pre"Tool`, "hook", "--connector", "devin"},
		"spaced event":   {DevinSubcommand, "Pre Tool", "hook", "--connector", "devin"},
		"managed":        {DevinSubcommand, "PreToolUse", "hook", "--connector", "devin", "--enterprise-managed"},
		"sibling":        {SiblingSubcommand, "PreToolUse", "hook", "--connector", "devin"},
		"launcher path":  {DevinSubcommand, `C:/x/defenseclaw-hook.exe`, "hook", "--connector", "devin"},
		"no args at all": nil,
	} {
		if _, _, ok := DevinArgv(args); ok {
			t.Errorf("%s: DevinArgv(%q) accepted", name, args)
		}
	}
}

// RunDevin answers a launcher that is not there, or is a folder: exit 2 and
// the sentence on stdout and stderr on the events it guards, exit 0 and the
// sentence on stderr only on any other event.
func TestRunDevinAnswersALauncherThatCannotStart(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "folder", hookBinaryName)
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		launcher string
		missing  bool
	}{
		"missing":  {filepath.Join(dir, "gone", hookBinaryName), true},
		"a folder": {folder, false},
	} {
		for _, event := range []string{"PreToolUse", "PermissionRequest", "UserPromptSubmit", "Stop", "SessionEnd", "PostToolUse"} {
			t.Run(name+"/"+event, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := RunDevin(tc.launcher, []string{"hook", "--connector", "devin"}, event, strings.NewReader(`{}`), &stdout, &stderr)
				message := LauncherMessage("Devin", tc.missing)
				wantCode, wantStdout := 0, ""
				if DevinBlockEvent(event) {
					wantCode, wantStdout = 2, message
				}
				if code != wantCode || strings.TrimSpace(stdout.String()) != wantStdout || strings.TrimSpace(stderr.String()) != message {
					t.Fatalf("exit %d, stdout %q, stderr %q; want exit %d, %q and %q", code, stdout.String(), stderr.String(), wantCode, wantStdout, message)
				}
			})
		}
	}
}
