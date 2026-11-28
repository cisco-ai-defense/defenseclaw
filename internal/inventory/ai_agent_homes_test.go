// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

func TestSavedAgentHomesAreScanned(t *testing.T) {
	restore := savedUserVariable
	t.Cleanup(func() { savedUserVariable = restore })
	savedUserVariable = func(home, _, name string) (string, bool) { return shellSavedVariable(home, name), true }

	home := t.TempDir()
	cache := filepath.Join(home, "cfg", "claude", "plugins", "cache", "market", "tools", "1.0")
	registry, _ := json.Marshal(map[string]any{"plugins": map[string]any{"tools@market": []map[string]string{{"installPath": cache}}}})
	writeSkillFiles(t, home, map[string]string{
		".zshrc":                        "export CODEX_HOME=\"$HOME/work/codex\"\nexport CLAUDE_CONFIG_DIR=$(pwd)\n",
		".bashrc":                       "CLAUDE_CONFIG_DIR=~/cfg/claude # moved\n",
		".profile":                      "export COPILOT_HOME=/etc\n",
		"work/codex/skills/cx/SKILL.md": "codex",
		"cfg/claude/skills/cl/SKILL.md": "claude",
		"cfg/claude/plugins/installed_plugins.json":                    string(registry),
		"cfg/claude/plugins/cache/market/tools/1.0/skills/pl/SKILL.md": "plugin",
		".claude/skills/default/SKILL.md":                              "the default folder is still read",
	})
	catalog := []AISignature{
		{ID: "codex", Category: SignalSupportedConnector, SupportedConnector: "codex", SkillPaths: []string{"$CODEX_HOME/skills"}},
		{ID: "claudecode", Category: SignalSupportedConnector, SupportedConnector: "claudecode", SkillPaths: []string{"~/.claude/skills", "$CLAUDE_CONFIG_DIR/skills"}},
		{ID: "copilot", Category: SignalSupportedConnector, SupportedConnector: "copilot", SkillPaths: []string{"$COPILOT_HOME/skills"}},
	}
	scan := func(opts AIDiscoveryOptions) []string {
		opts.Enabled, opts.Mode, opts.DataDir = true, "enhanced", filepath.Join(home, "data")
		svc := NewContinuousDiscoveryServiceWithOptions(opts, catalog)
		cleanupPreparedDiscoveryService(t, svc)
		var got []string
		for _, signal := range svc.detectSkills() {
			for _, ev := range signal.Evidence {
				if ev.Skill != nil {
					got = append(got, signal.SignatureID+"/"+ev.Skill.Location)
				}
			}
		}
		slices.Sort(got)
		return got
	}

	// A Secure Client scan reads where each user saved the variables; a
	// command substitution and a folder outside the home are refused.
	want := []string{
		"claudecode/~/.claude/skills/default", "claudecode/~/cfg/claude/plugins/cache/market/tools/1.0/skills/pl",
		"claudecode/~/cfg/claude/skills/cl", "codex/~/work/codex/skills/cx",
	}
	if got := scan(AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}, ManagedEnterprise: true, SecureClient: true}); !slices.Equal(got, want) {
		t.Fatalf("service scan = %q, want %q", got, want)
	}
	// A per-user scan is unchanged: it uses its own environment.
	if got := scan(AIDiscoveryOptions{HomeDir: home}); !slices.Equal(got, []string{"claudecode/~/.claude/skills/default"}) {
		t.Fatalf("per-user scan = %q", got)
	}
}

func TestShellWord(t *testing.T) {
	for in, want := range map[string]string{
		`"~/a b"`: "~/a b", `'x'`: "x", `~/c;ls`: "~/c", `~/d # note`: "~/d", `"open`: "",
	} {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %q, want %q", in, got, want)
		}
	}
}

// A signed-out Windows user's saved folder cannot be read; the scan keeps
// using the last one it read, across a restart too, so the user's skills are
// not reported removed at sign-out and new at sign-in.
func TestSavedAgentHomeIsRememberedWhileTheUserIsSignedOut(t *testing.T) {
	restore := savedUserVariable
	t.Cleanup(func() { savedUserVariable = restore })
	home, data := t.TempDir(), t.TempDir()
	moved := filepath.Join(home, "work", "codex")
	writeSkillFiles(t, home, map[string]string{"work/codex/skills/cx/SKILL.md": "codex"})
	value, known := moved, true
	savedUserVariable = func(string, string, string) (string, bool) { return value, known }
	newService := func() *ContinuousDiscoveryService {
		svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
			Enabled: true, Mode: "enhanced", DataDir: data, HomeDir: home, ManagedEnterprise: true,
		}, nil)
		cleanupPreparedDiscoveryService(t, svc)
		return svc
	}
	svc := newService()
	if got := svc.agentHome(home, "CODEX_HOME"); got != moved {
		t.Fatalf("signed in: %q, want %q", got, moved)
	}
	value, known = "", false // signed out
	if got := svc.agentHome(home, "CODEX_HOME"); got != moved {
		t.Fatalf("signed out: %q, want the remembered %q", got, moved)
	}
	if got := newService().agentHome(home, "CODEX_HOME"); got != moved {
		t.Fatalf("signed out after a restart: %q, want %q", got, moved)
	}
	value, known = "", true // signed in, variable removed
	if got := svc.agentHome(home, "CODEX_HOME"); got != filepath.Join(home, ".codex") {
		t.Fatalf("variable removed: %q", got)
	}
	value, known = "", false
	if got := svc.agentHome(home, "CODEX_HOME"); got != filepath.Join(home, ".codex") {
		t.Fatalf("signed out after removing the variable: %q", got)
	}
}
