// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The Skill hook of a project whose .claude folder is a junction to a network
// share that does not answer reports the project skill root as unreadable
// within the answer wait, as the gateway refuses it in action modes, and
// reads the ordinary project as before (rel-1-0-9:GAP-0621).
func TestWindowsSkillHookBoundsAProjectRootJunctionToASilentShare(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	share, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(share, "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"junction", "plain"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "plain", ".claude", "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(home, "junction", ".claude"), share).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, out)
	}
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, share, 20*time.Millisecond, time.Second, func(string) { <-release })
	facts := func(project string) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "cwd": project,
			"tool_name": "Skill", "tool_input": map[string]string{"skill": "sample"},
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded := ResolveConnector("claudecode", "", "PreToolUse", body)
		if encoded == "" {
			return nil
		}
		decoded, ok := Decode(encoded)
		if !ok {
			t.Fatal("Skill hook facts were not decoded")
		}
		return decoded
	}
	junction := filepath.Join(home, "junction")
	start := time.Now()
	got := facts(junction)[ProjectSkillRootUnverifiedPrefix+filepath.Join(junction, ".claude", "skills")]
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the Skill hook held the call %v", took)
	}
	if got != ProjectSkillRootUnreadable || probes.Load() != 1 {
		t.Fatalf("junction finding = %q with %d probes, want %q after one probe", got, probes.Load(), ProjectSkillRootUnreadable)
	}
	plain := filepath.Join(home, "plain")
	for key, value := range facts(plain) {
		if len(key) > len(ProjectSkillRootUnverifiedPrefix) && key[:len(ProjectSkillRootUnverifiedPrefix)] == ProjectSkillRootUnverifiedPrefix {
			t.Fatalf("ordinary project reported %s = %s", key, value)
		}
	}
}
