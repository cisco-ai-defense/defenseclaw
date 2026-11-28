// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP2127NewChildInStateFolderIsAllowedMemberCopyIsTiered
// (rel-1-0-10:GAP-2127, a documented limit): a new child folder made in the
// detector state folder by a recursive copy, an archive copy, a folder move
// or an rsync is allowed, as in shipped 1.0.10 at its default settings. A
// copy onto an existing member of the state folder is a proven state write:
// an alert in the default pack, a block in strict. A recursive copy of a new
// child is not raised to the unknown tier because agent traces keep folders
// in the state folder and the raise would block them. This pin holds today's
// verdicts so a later change cannot lower or raise them silently; it is green
// at rel and at the head.
func TestGAP2127NewChildInStateFolderIsAllowedMemberCopyIsTiered(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := r104ReviewHomeNoAlias(t)
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "src", "config.yaml"), []byte("y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newChild := []string{
		"cp -r src ~/.defenseclaw/newchild",
		"cp -a src ~/.defenseclaw/newchild",
		"mv src ~/.defenseclaw/newchild",
		"rsync -a src/ ~/.defenseclaw/newchild/",
	}
	member := []string{
		"cp -r src/config.yaml ~/.defenseclaw/config.yaml",
		"cp src/config.yaml ~/.defenseclaw/config.yaml",
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		ask := func(id, command string) agentHookResponse {
			event := claudeToolEvent("PreToolUse", "gap2127-"+pack, id, command)
			event["cwd"] = cwd
			return callAgentHookForTest(t, handler, event)
		}
		for i, command := range newChild {
			got := ask("n"+string(rune('a'+i)), command)
			if got.Action != "allow" || containsString(got.RuleIDs, stateWriteRuleID) {
				t.Errorf("%s %q: action %q rules %v, want allow without %s (new child, documented limit)", pack, command, got.Action, got.RuleIDs, stateWriteRuleID)
			}
		}
		want := gap0747WantAction(pack == "strict")
		for i, command := range member {
			got := ask("m"+string(rune('a'+i)), command)
			if got.Action != want || !containsString(got.RuleIDs, stateWriteRuleID) {
				t.Errorf("%s %q: action %q rules %v, want %q with %s (existing member)", pack, command, got.Action, got.RuleIDs, want, stateWriteRuleID)
			}
		}
	}
}
