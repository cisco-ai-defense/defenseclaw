// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0568HookAction answers one PreToolUse shell call through the
// connector's hook evaluation, with the hook client's header when client is
// set and as a managed hook peer (the home hidden from the gateway) when
// managed is set.
func gap0568HookAction(t *testing.T, api *APIServer, connector, home, cwd, command string, client, managed bool) string {
	t.Helper()
	ctx := context.Background()
	if client {
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0568", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
			ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
		}
	}
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		homes := filepath.Dir(home)
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(homes, 0o700) }()
	}
	if connector == "claudecode" {
		return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", CWD: cwd, ToolName: "Bash",
			ToolInput: map[string]any{"command": command},
		}).Action
	}
	return api.evaluateCodexHook(ctx, codexHookRequest{
		HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command",
		ToolInput: map[string]any{"cmd": command},
	}).Action
}

// TestGAP0568ObserveOverBudgetStateWriteBlocks is the review F1 of
// rel-1-0-2:GAP-0568: observe mode, the OSS default, allows every finding
// but a proven write to the active DefenseClaw state. The statement-budget
// refusal must not hide that proof: a state write after 200 or 3000
// statements, or through a link the same call makes, blocks in observe mode
// as it does alone, for both connectors, with and without the hook
// client's header, per-user and as a managed peer behind ProtectHome (where
// only the client's map proves it). A benign over-budget call and an
// over-budget keys write (not state) still only alert in observe mode.
func TestGAP0568ObserveOverBudgetStateWriteBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := gap0568StateFile(t, home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	rows := []struct {
		name, command string
		observeBlock  bool
	}{
		{"state write alone", "printf changed >> " + state, true},
		{"state write after 200", gap0568Assignments(200) + "; printf changed >> " + state, true},
		{"state write after 3000", gap0568Assignments(3000) + "; printf changed >> " + state, true},
		{"state write through a new link after 200", gap0568Assignments(200) + "; ln -s " + state + " s9; printf c >> s9", true},
		// Review round 2: the state named by a pattern (R2-1, the glob
		// twin) and with a quote inside the name (R2-2, the client's
		// state-name check), under and over the budget.
		{"glob-spelled state write alone", "printf c >> ~/.defense?law/config.yaml", true},
		{"glob-spelled state write after 200", gap0568Assignments(200) + "; printf c >> ~/.defense?law/config.yaml", true},
		{"quote-split state write alone", "printf c >> ~/.defense''claw/config.yaml", true},
		{"quote-split state write after 200", gap0568Assignments(200) + "; printf c >> ~/.defense''claw/config.yaml", true},
		{"benign 200", gap0568Assignments(200), false},
		{"keys write after 200", gap0568Assignments(200) + "; echo k >> " + keys, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"observe", "action"} {
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					// Action mode blocks every row: each is over the budget
					// or a state write.
					want := mode == "action" || row.observeBlock
					action := gap0568HookAction(t, api, connector, home, cwd, row.command, cell.client, cell.managed)
					if got := action == "block"; got != want {
						t.Errorf("%s/%s client=%t managed=%t %s: action %q, want block=%t", connector, mode, cell.client, cell.managed, row.name, action, want)
					}
				}
			}
		}
	}
}

// TestGAP0568MemoIsFreshForEveryCall is the review F4 of rel-1-0-2:GAP-0568:
// the file system memo lives for one evaluation only. A file the first call
// writes is replaced by a link to the active state before the second call;
// the second call must see the link (the state-mention reader goes through
// the memo). A memo shared across calls answers from the first call and
// fails this.
func TestGAP0568MemoIsFreshForEveryCall(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	state := gap0568StateFile(t, home)
	target := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dispatch := func() []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", Command: "printf c >> notes.txt", CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX},
			Connector: "claudecode", EnforcementCapable: true,
		})
	}
	if findingWithID(dispatch(), "tamper.detector_state_write") != nil {
		t.Fatal("an ordinary write named the active state")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, target); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if findings := dispatch(); findingWithID(findings, "tamper.detector_state_write") == nil {
		t.Fatalf("a state write through a link made between two calls was not found: %v", findingIDs(findings))
	}
}
