// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP0718HookSettingsWriteThroughACallLink: a write to a project hook
// settings file is the write rule (alert in default, permissive and managed,
// block in strict and managed-strict) whether it is spelled directly, in a
// folder other than the working directory, after a cd the walk cannot place,
// or through a link the call itself makes; a git rewrite of a folder that is
// such a link counts as GAP-0572 counts an unreadable folder. Links, moves
// and writes that reach no hook file stay allowed (rel-1-0-10:GAP-0718,
// GAP-0571, GAP-0572).
func TestGAP0718HookSettingsWriteThroughACallLink(t *testing.T) {
	home, cwd := shellProtectedFileHome(t)
	work := filepath.Join(home, "td", "work", "default")
	hooked := filepath.Join(work, "hooked")
	for _, dir := range []string{filepath.Join(work, "uuid", ".git"), filepath.Join(hooked, ".git"), filepath.Join(hooked, ".claude")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(hooked, ".claude", "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "notes.txt"), []byte("n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("W", work)
	settings := ".claude/settings.json"
	written := []struct{ id, dir, command string }{
		{"D23", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && echo {} > hk2/" + settings},
		{"D40", cwd, "cd $W && ln -s hooked hk && echo {} > hk/" + settings},
		{"D45", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && cd hk2 && echo {} > " + settings},
		{"D46", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && git -C hk2 checkout -- ."},
		{"D47", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && cp notes.txt hk2/" + settings},
		{"D48", cwd, "cd $W && ln -s hooked hk && mv hk hk2 && tee hk2/" + settings + " < notes.txt"},
		{"D51", cwd, "cd $W && ln -s hooked hk && echo {} > hooked/" + settings},
		{"D52", cwd, "cd $W && echo {} > hooked/" + settings},
		{"X1", work, "echo {} > hooked/" + settings},
		{"X2", work, "ln -s hooked hk && echo {} > hk/" + settings},
		{"X5", work, "git -C hooked checkout -- ."},
		{"X6", work, "ln -s hooked/.claude cl && echo {} > cl/settings.json"},
	}
	allowed := []struct{ id, dir, command string }{
		{"D18", cwd, "cd $W && ln -s uuid uuid-link && mv uuid-link uuid-link2 && rm uuid-link2 && echo ok"},
		{"N1", work, "ln -s hooked hk && echo x > hk/notes.txt"},
		{"N2", work, "ln -s hooked hk && cat hk/" + settings},
		{"N3", cwd, "cd $W && ln -s hooked hk && git -C hk checkout -- main.go"},
		{"N4", work, "echo {} > hooked/.claude/notes.json"},
	}
	want := map[string]string{"default": "alert", "permissive": "alert", "managed": "alert", "strict": "block", "managed-strict": "block"}
	for _, cell := range []string{"default", "permissive", "strict", "managed", "managed-strict"} {
		posture, managed := cell, false
		switch cell {
		case "managed":
			posture, managed = "default", true
		case "managed-strict":
			posture, managed = "strict", true
		}
		for _, row := range written {
			action, rules := shellProtectedFileRoute(t, home, row.dir, "claudecode", posture, managed, row.command)
			if action != want[cell] || !strings.Contains(strings.Join(rules, ","), agentHookConfigWriteRuleID) {
				t.Errorf("%s %s: %s %v, want %s with %s", row.id, cell, action, rules, want[cell], agentHookConfigWriteRuleID)
			}
		}
		for _, row := range allowed {
			if action, rules := shellProtectedFileRoute(t, home, row.dir, "claudecode", posture, managed, row.command); action != "allow" {
				t.Errorf("%s %s: %s %v, want allow", row.id, cell, action, rules)
			}
		}
	}
}
