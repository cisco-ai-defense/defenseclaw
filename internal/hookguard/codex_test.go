// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The Claude Code sentences are LauncherMessage's Claude Code forms; teardown
// matches them word for word, so they must not change (rel-1-0-6 GAP-0676).
func TestLauncherMessageKeepsTheClaudeCodeSentences(t *testing.T) {
	if got := LauncherMessage("Claude Code", true); got != MissingMessage {
		t.Fatalf("missing: %q, want %q", got, MissingMessage)
	}
	if got := LauncherMessage("Claude Code", false); got != CannotStartMessage {
		t.Fatalf("cannot start: %q, want %q", got, CannotStartMessage)
	}
	if strings.ContainsAny(LauncherMessage("Codex", false), `"%!^&|<>()'`) {
		t.Fatalf("the Codex sentence holds a shell or quote character: %q", LauncherMessage("Codex", false))
	}
}

func TestSiblingArgvAcceptsOnlyTheBoundCodexArgv(t *testing.T) {
	hookArgs, event, contract, ok := SiblingArgv([]string{SiblingSubcommand, "hook", "--connector", "codex", "--event", "PermissionRequest", "--hook-contract", "codex-hooks-v3-generic"})
	if !ok || event != "PermissionRequest" || contract != "codex-hooks-v3-generic" ||
		!reflect.DeepEqual(hookArgs, []string{"hook", "--connector", "codex", "--event", "PermissionRequest", "--hook-contract", "codex-hooks-v3-generic"}) {
		t.Fatalf("SiblingArgv = %v %q %q %v", hookArgs, event, contract, ok)
	}
	for name, args := range map[string][]string{
		"claude code":     {SiblingSubcommand, "hook", "--connector", "claudecode", "--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
		"launcher-guard":  {Subcommand, "hook", "--connector", "codex", "--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
		"foreign id":      {SiblingSubcommand, "hook", "--connector", "codex", "--event", "PreToolUse", "--hook-contract", "other-v1"},
		"quoted event":    {SiblingSubcommand, "hook", "--connector", "codex", "--event", `Pre"Tool`, "--hook-contract", "codex-hooks-v4"},
		"empty event":     {SiblingSubcommand, "hook", "--connector", "codex", "--event", "", "--hook-contract", "codex-hooks-v4"},
		"swapped flags":   {SiblingSubcommand, "hook", "--connector", "codex", "--hook-contract", "codex-hooks-v4", "--event", "PreToolUse"},
		"managed":         {SiblingSubcommand, "hook", "--connector", "codex", "--enterprise-managed", "--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
		"too few":         {SiblingSubcommand, "hook", "--connector", "codex"},
		"no program args": nil,
	} {
		if _, _, _, ok := SiblingArgv(args); ok {
			t.Errorf("%s: SiblingArgv(%q) accepted", name, args)
		}
	}
}

// CodexBlock is the stable launcher's unavailable answer for each event,
// except that a stop never gets a blocking answer.
func TestCodexBlockAnswersEveryEventCodexCanBlock(t *testing.T) {
	for _, tc := range []struct {
		event, contract, want string
	}{
		{"PreToolUse", "codex-hooks-v1", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"m"}}`},
		{"PermissionRequest", "codex-hooks-v4", `{"hookSpecificOutput":{"decision":{"behavior":"deny","message":"m"},"hookEventName":"PermissionRequest"}}`},
		{"UserPromptSubmit", "codex-hooks-v4", `{"decision":"block","reason":"m"}`},
		{"PostToolUse", "codex-hooks-v1", `{"decision":"block","reason":"m"}`},
		{"SessionStart", "codex-hooks-v3", `{"continue":false,"stopReason":"m"}`},
		{"PreCompact", "codex-hooks-v3-generic", `{"continue":false,"stopReason":"m"}`},
		{"PostCompact", "codex-hooks-v4", `{"continue":false,"stopReason":"m"}`},
		{"SessionStart", "codex-hooks-v2", "null"},
		{"PreCompact", "codex-hooks-v2", "null"},
		{"Stop", "codex-hooks-v4", "null"},
		{"SubagentStop", "codex-hooks-v4", "null"},
		{"SessionEnd", "codex-hooks-v4", "null"},
		{"SubagentStart", "codex-hooks-v4", "null"},
	} {
		got, err := json.Marshal(CodexBlock(tc.event, tc.contract, "m"))
		if err != nil || string(got) != tc.want {
			t.Errorf("CodexBlock(%s, %s) = %s (%v), want %s", tc.event, tc.contract, got, err, tc.want)
		}
	}
}

func TestSiblingExceptionStatusIsTheHighBitOfTheExitCode(t *testing.T) {
	for code, want := range map[int]bool{0: false, 1: false, 2: false, 7: false, 9009: false, 0x7fffffff: false,
		0x80000003: true, 0xc0000005: true, 0xc000007b: true, 0xc0000135: true, 0xc000013a: true, 0xffffffff: true} {
		if got := siblingExceptionStatus(code); got != want {
			t.Errorf("siblingExceptionStatus(%#x) = %v, want %v", code, got, want)
		}
	}
}

// RunCodex answers a launcher that is not there, or is a folder, with the
// Codex block on stdout and the sentence on stderr, exit 0.
func TestRunCodexAnswersALauncherThatCannotStart(t *testing.T) {
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
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"hook", "--connector", "codex", "--event", "UserPromptSubmit", "--hook-contract", "codex-hooks-v4"}
			code := RunCodex(tc.launcher, args, "UserPromptSubmit", "codex-hooks-v4", strings.NewReader(`{}`), &stdout, &stderr)
			message := LauncherMessage("Codex", tc.missing)
			want, _ := json.Marshal(map[string]any{"decision": "block", "reason": message})
			if code != 0 || strings.TrimSpace(stdout.String()) != string(want) || strings.TrimSpace(stderr.String()) != message {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit 0, %s and %q", code, stdout.String(), stderr.String(), want, message)
			}
		})
	}
}
