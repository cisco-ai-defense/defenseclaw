// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2569: the client header names where each link-walk spelling of a
// command lies, so a managed gateway that cannot walk the home places it.
func TestR105GAP2569ClientLinkWalkFacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{filepath.Join(state, "hooks"), filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(state, filepath.Join(cwd, "dclink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	home, _ = filepath.EvalSymlinks(home)
	state = filepath.Join(home, ".defenseclaw")
	cwd = filepath.Join(home, "project")
	header := func(t *testing.T, command string) map[string]string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		targets, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload))
		if !ok {
			t.Fatalf("%s: header does not decode", command)
		}
		return targets
	}
	for command, want := range map[string]map[string]string{
		"rm -rf dclink/../.defenseclaw/hooks": {
			cwd + "/dclink":                       state,
			cwd + "/dclink/..":                    home,
			cwd + "/dclink/../.defenseclaw":       state,
			cwd + "/dclink/../.defenseclaw/hooks": filepath.Join(state, "hooks"),
		},
		"git -C dclink clean -fdx":         {cwd + "/dclink": state},
		"rm -rf dclink/../.defenseclaw/*":  {cwd + "/dclink/../.defenseclaw": state},
		"git --work-tree=dclink clean -fd": {cwd + "/dclink": state},
		"cd ./dclink && ls":                {cwd + "/dclink": state},
	} {
		targets := header(t, command)
		for spelling, physical := range want {
			if got := targets[WalkFactPrefix+spelling]; got != physical {
				t.Errorf("%s: fact %s = %q, want %q (all %q)", command, spelling, got, physical, targets)
			}
		}
	}
	// A word that crosses no link adds no fact.
	for key := range header(t, "rm -rf build/../out ./build") {
		if len(key) > len(WalkFactPrefix) && key[:len(WalkFactPrefix)] == WalkFactPrefix {
			t.Errorf("plain project word listed a walk fact %q", key)
		}
	}
	// The gateway side: a deeper spelling below a walked prefix.
	targets := map[string]string{WalkFactPrefix + cwd + "/dclink": state}
	if got, ok := WalkFactTarget(targets, cwd+"/dclink/hooks"); !ok || got != filepath.Join(state, "hooks") {
		t.Errorf("deeper spelling = %q, %v", got, ok)
	}
	if _, ok := WalkFactTarget(targets, cwd+"/dclink/hooks/../.."); ok {
		t.Error("a .. below a walked prefix was placed lexically")
	}
	if _, ok := WalkFactTarget(targets, cwd+"/build"); ok {
		t.Error("an unwalked spelling was placed")
	}
}
