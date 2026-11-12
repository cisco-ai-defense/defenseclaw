// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-0607: on a case-sensitive file system (Linux) ~/.DefenseClaw is another
// directory than the state directory ~/.defenseclaw, so appending to a file
// in it is ordinary work. macOS and Windows fold the case: there it is the
// state directory. The real spelling stays blocked on every host.
func TestStateWriteCaseDifferentLookalikeFollowsFileSystemCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command matrix")
	}
	_, cwd := r104ReviewHome(t)
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	lookalikeBlocks := runtime.GOOS != "linux"
	rows := []struct {
		name, command string
		block         bool
	}{
		{"case-different folder", "printf changed >> /home/alice/.DefenseClaw/config.yaml", lookalikeBlocks},
		{"state folder", "printf changed >> /home/alice/.defenseclaw/config.yaml", true},
		{"case-different folder, other file", "printf changed >> /home/alice/.DefenseClaw/notes.txt", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": row.command},
			})
			if got := resp.Action == guardrailActionBlock; got != row.block {
				t.Fatalf("block=%t, want %t; findings=%v", got, row.block, resp.Findings)
			}
			if row.block && !findingStringHasRuleID(resp.Findings, "tamper.detector_state_write") {
				t.Fatalf("no tamper.detector_state_write finding; findings=%v", resp.Findings)
			}
		})
	}
}

// The rule match itself: a Windows-flavored path is read in any case on every
// host, a POSIX one in the case of the host's file system.
func TestStateWriteRuleMatchReadsCaseByHostFileSystem(t *testing.T) {
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	generation := snapshotRulePackGenerationFor(t.Context(), "claudecode")
	if generation == nil {
		t.Fatal("no rule pack generation")
	}
	var rule *PatternRule
	for _, category := range generation.categories {
		for i := range category.Rules {
			if category.Rules[i].ID == stateWriteRuleID {
				rule = &category.Rules[i]
			}
		}
	}
	if rule == nil {
		t.Fatal("state write rule missing from the default pack")
	}
	posixFolds := runtime.GOOS != "linux"
	for _, tc := range []struct {
		path   string
		flavor actionfacts.PathFlavor
		want   bool
	}{
		{"/home/alice/.defenseclaw/config.yaml", actionfacts.PathFlavorPOSIX, true},
		{"/Users/alice/.defenseclaw/hooks/claude-code-hook.sh", actionfacts.PathFlavorPOSIX, true},
		{"/home/alice/.DefenseClaw/config.yaml", actionfacts.PathFlavorPOSIX, posixFolds},
		{"/Users/alice/.DefenseClaw/hooks/claude-code-hook.sh", actionfacts.PathFlavorPOSIX, posixFolds},
		{"C:/Users/alice/.defenseclaw/config.yaml", actionfacts.PathFlavorWindows, true},
		{"C:/Users/alice/.DefenseClaw/config.yaml", actionfacts.PathFlavorWindows, true},
		{"/home/alice/.DefenseClaw/notes.txt", actionfacts.PathFlavorPOSIX, false},
	} {
		if got := highWriteRuleMatchesTarget(*rule, tc.path, tc.flavor, false); got != tc.want {
			t.Errorf("%s (%v): match=%t, want %t", tc.path, tc.flavor, got, tc.want)
		}
	}
}
