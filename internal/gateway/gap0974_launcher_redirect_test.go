// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0974: an authorized_keys append through cmd /c and pwsh -Command
// launchers on the Codex shell route was a detection-only CRITICAL in every
// tier. `echo K 2>&1 >> T` left the Windows parse partial (the 2>&1), and a
// launcher statement with its own `>> T` stayed partial for its unread body
// (and the bare pwsh line read as POSIX lost the finding). Both writes are
// proven and block in all five tiers; the same launchers writing a project
// file stay allowed.
func TestGAP0974LauncherRedirectAuthorizedKeysBlocks(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows hook dialect readings and path resolution")
	}
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	const target = `C:\Users\alice\.ssh\authorized_keys`
	const key = `echo ssh-ed25519 AAAAgap0974 gap0974`
	type row struct {
		name    string
		command any
		block   bool
	}
	var rows []row
	for k := 1; k <= 4; k++ {
		outer, inner := strings.Repeat("cmd /c ", k), strings.Repeat("cmd /c ", k-1)
		for _, redirect := range []string{" 2>&1 >> " + target, " >> " + target, ` >> "` + target + `"`} {
			rows = append(rows,
				row{"cmd-string k" + string(rune(0x30+k)) + redirect, outer + key + redirect, true},
				row{"cmd-argv k" + string(rune(0x30+k)) + redirect, []any{"cmd", "/c", inner + key + redirect}, true},
				row{"pwsh k" + string(rune(0x30+k)) + redirect, inner + "pwsh -Command \x27" + key + "\x27" + redirect, true})
		}
		rows = append(rows,
			row{"benign dir k" + string(rune(0x30+k)), outer + "dir 2>&1", false},
			row{"benign echo k" + string(rune(0x30+k)), outer + "echo hi > out.txt", false},
			row{"benign errapp k" + string(rune(0x30+k)), outer + key + " 2>&1 >> notes.txt", false},
			row{"benign pwsh k" + string(rune(0x30+k)), inner + "pwsh -Command \x27echo hi\x27 >> notes.txt", false})
	}
	for _, tier := range boundedTestTiers {
		api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		for _, r := range rows {
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": r.command},
			})
			if blocked := resp.Action == "block"; blocked != r.block {
				t.Errorf("%s %s: action %s (%s %v), want block=%v", tier.name, r.name, resp.Action, resp.Severity, resp.RuleIDs, r.block)
			}
		}
	}
}
