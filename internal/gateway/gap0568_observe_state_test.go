// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	return gap0568ToolHookAction(t, api, connector, "Bash", home, cwd, command, client, managed)
}

// gap0568ToolHookAction is gap0568HookAction for a Claude Code tool other
// than Bash (the PowerShell tool); Codex always runs exec_command.
func gap0568ToolHookAction(t *testing.T, api *APIServer, connector, tool, home, cwd, command string, client, managed bool) string {
	t.Helper()
	ctx := context.Background()
	if client {
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0568", "cwd": cwd,
			"tool_name": tool, "tool_input": map[string]any{"command": command}})
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
			HookEventName: "PreToolUse", CWD: cwd, ToolName: tool,
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
	decoys := make([]string, 130)
	for i := range decoys {
		decoys[i] = fmt.Sprintf("echo claw%d", i)
	}
	// perUserOnly rows: behind ProtectHome the hook client cannot tell the
	// pattern names the state (no defense or claw in it), a known limit of
	// the managed reading (review r3 item 5).
	perUserOnly := map[string]bool{"short glob state write after 200": true, "qmark glob state write after 200": true}
	// managedHolds rows: past the reduced reading's bound with statements
	// that may write, the managed gateway holds the call; per-user reads
	// the call itself and only alerts (review r4 mutation MN5).
	managedHolds := map[string]bool{"130 naming writes to a project file": true,
		// rel-1-0-6:GAP-0414: the write is in a function definition the
		// reduced reading does not keep; per-user the gateway reads the
		// call itself and, as under the budget, cannot prove it.
		"function writer after 130 reads": true}
	ovf := gap0568Assignments(200) + "; " + strings.Join(decoys, "; ") + "; "
	reads := make([]string, 130)
	writes := make([]string, 130)
	greps := make([]string, 130)
	statuses := make([]string, 130)
	for i := range reads {
		reads[i] = "cat " + state + " 2>/dev/null"
		writes[i] = fmt.Sprintf("echo claw%d >> notes.txt", i)
		greps[i] = fmt.Sprintf("grep -c claw%d README.md 2>/dev/null", i)
		statuses[i] = "defenseclaw status 2>&1"
	}
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
		// Review r3: patterns with neither defense nor claw, proved by the
		// glob twin (mutation MD), and a state write after 130 statements
		// that name the state, past the reduced reading's bound (finding 3).
		{"short glob state write after 200", gap0568Assignments(200) + "; printf c >> ~/.def*/config.yaml", true},
		{"qmark glob state write after 200", gap0568Assignments(200) + "; printf c >> ~/.d?f?n?e?l?w/config.yaml", true},
		{"state write after 130 naming statements", gap0568Assignments(200) + "; " + strings.Join(decoys, "; ") + "; printf c >> " + state, true},
		{"tilde state write after 130 naming statements", gap0568Assignments(200) + "; " + strings.Join(decoys, "; ") + "; printf c >> ~/.defenseclaw/config.yaml", true},
		// Review r4 finding 2: other spellings of a state write or delete
		// after 130 naming statements are kept in the reduced reading.
		{"/bin/rm after 130 naming statements", ovf + "/bin/rm -f " + state, true},
		{"escaped rm after 130 naming statements", ovf + "\\rm -f " + state, true},
		{"quoted rm after 130 naming statements", ovf + "\"rm\" -f " + state, true},
		{"sh -c rm after 130 naming statements", ovf + "sh -c 'rm -f " + state + "'", true},
		{"unlink after 130 naming statements", ovf + "unlink " + state, true},
		{"find -delete after 130 naming statements", ovf + "find ~/.defenseclaw -name config.yaml -delete", true},
		{"tee -a after 130 naming statements", ovf + "printf c | /usr/bin/tee -a " + state, true},
		{"shred -u after 130 naming statements", ovf + "shred -u " + state, true},
		// Review r4 finding 3: overflowing reads with discarded output
		// stay alerts in observe mode.
		{"130 state reads with 2>/dev/null", gap0568Assignments(200) + "; " + strings.Join(reads, "; "), false},
		{"130 defenseclaw status with 2>&1", gap0568Assignments(200) + "; " + strings.Join(statuses, "; "), false},
		{"130 greps with 2>/dev/null", gap0568Assignments(200) + "; " + strings.Join(greps, "; "), false},
		{"130 naming writes to a project file", gap0568Assignments(200) + "; " + strings.Join(writes, "; "), false},
		{"cd then relative write after 130 reads", gap0568Assignments(200) + "; " + strings.Join(reads, "; ") + "; cd ~/.defenseclaw; printf c >> config.yaml", true},
		{"cd then relative rm after 130 reads", gap0568Assignments(200) + "; cd ~/.defenseclaw; " + strings.Join(reads, "; ") + "; rm -f config.yaml", true},
		{"function writer after 130 reads", gap0568Assignments(200) + "; " + strings.Join(reads, "; ") + `; f() { printf c >> "$1"; }; f ` + state, false},
		{"benign 200", gap0568Assignments(200), false},
		{"keys write after 200", gap0568Assignments(200) + "; echo k >> " + keys, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"observe", "action"} {
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					if perUserOnly[row.name] && cell.managed {
						continue
					}
					// Action mode blocks every row: each is over the budget
					// or a state write.
					want := mode == "action" || row.observeBlock || managedHolds[row.name] && cell.managed
					action := gap0568HookAction(t, api, connector, home, cwd, row.command, cell.client, cell.managed)
					if got := action == "block"; got != want {
						t.Errorf("%s/%s client=%t managed=%t %s: action %q, want block=%t", connector, mode, cell.client, cell.managed, row.name, action, want)
					}
				}
			}
		}
	}
}

// TestGAP0413PowerShellOverBudgetStateWriteHolds is rel-1-0-6:GAP-0413
// (review r5 finding 2): the reduced state reading's "no writer" answer
// came from a POSIX split and read-only proof of a PowerShell-tool call, so
// 200 assignments, 130 echo "clawN" and a Set-Content of the state were
// allowed behind ProtectHome in observe mode. A PowerShell call is now kept
// whole and held there. Per-user, the gateway reads the call itself; on a
// POSIX host it does not resolve the PowerShell home spellings, so those
// cells only alert (a Windows host blocks them, checked on dc-win2).
func TestGAP0413PowerShellOverBudgetStateWriteHolds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	state := gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	assignments := make([]string, 200)
	for i := range assignments {
		assignments[i] = fmt.Sprintf("$a%d=1", i)
	}
	echoes := make([]string, 130)
	for i := range echoes {
		echoes[i] = fmt.Sprintf(`echo "claw%d"`, i)
	}
	pad := strings.Join(assignments, "; ") + "; " + strings.Join(echoes, "; ") + "; "
	api := instructionProtectionTestAPI(t, "claudecode", "observe", "HIGH")
	for _, row := range []struct {
		name, command string
		managedBlock  bool
	}{
		{"Set-Content of the state after 130 echoes", pad + "Set-Content -Path ~/.defenseclaw/config.yaml -Value x", true},
		{"absolute Set-Content of the state after 130 echoes", pad + "Set-Content -Path " + state + " -Value x", true},
		{"quote-split Set-Content after 200", strings.Join(assignments, "; ") + `; echo "claw\"; Set-Content -Path ~/.defenseclaw/config.yaml -Value x; \""`, true},
		{"benign 200", strings.Join(assignments, "; "), false},
	} {
		for _, managed := range []bool{false, true} {
			want := managed && row.managedBlock
			if got := gap0568ToolHookAction(t, api, "claudecode", "PowerShell", home, cwd, row.command, true, managed) == "block"; got != want {
				t.Errorf("%s managed=%t: block %t, want %t", row.name, managed, got, want)
			}
		}
	}
	if reduced, overflow, ok := hookpaths.StateNamingReading(pad+"Set-Content -Path "+state+" -Value x", home, true); !ok || !overflow || !strings.HasSuffix(reduced, " -Value x") {
		t.Errorf("PowerShell reading: ok %t overflow %t, want the whole call as an overflow", ok, overflow)
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
