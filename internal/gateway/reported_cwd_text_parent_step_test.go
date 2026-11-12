// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Windows reads a parent step in a working directory as text before it asks
// the file system, so a reported cwd of proj\lnk\.. is proj whatever lnk is.
// The hook client and the gateway place such a call there for every
// connector, as the Codex workdir is: a hard link to the keys inside the
// project is the protected file, and an ordinary file of any other name stays
// allowed. (The test stands in for Windows with the placement switch.)
func TestReportedCwdWithAParentStepAfterALinkIsPlacedAsTextWhereTheSystemDoes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	defer hookpaths.SetParentStepIsText(true)()
	root := t.TempDir()
	home := filepath.Join(root, "home", "eng1")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	ordinary := filepath.Join(home, "ordinary.txt")
	for _, file := range []string{keys, ordinary} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"hlk-home": keys, "hlk-ord": ordinary} {
		if err := os.Link(target, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(keys, filepath.Join(project, "hlk-proj")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ordinary, filepath.Join(project, "plain-proj")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "lnk")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	operands := func(count int, last string) string {
		words := make([]string, 0, count+1)
		for i := 0; i < count; i++ {
			words = append(words, fmt.Sprintf("f%d", i))
		}
		return "touch " + strings.Join(append(words, last), " ")
	}
	homes := filepath.Dir(home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, connector := range []string{"claudecode", "codex"} {
		for _, cwd := range []string{project + "/lnk/..", project + "/lnk/../."} {
			for _, count := range []int{0, 5000} {
				for _, probe := range []struct {
					target string
					want   bool
				}{{"hlk-proj", true}, {"plain-proj", false}, {"hlk-home", false}, {"hlk-ord", false}} {
					for _, protectHome := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/%d operands/%s/protect home=%t", connector, strings.TrimPrefix(cwd, project), count, probe.target, protectHome), func(t *testing.T) {
							body, err := json.Marshal(map[string]any{"session_id": "c944", "hook_event_name": "PreToolUse",
								"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": operands(count, probe.target)}})
							if err != nil {
								t.Fatal(err)
							}
							evidence := hookpaths.ResolveConnector(connector, "", "preToolUse", body)
							if protectHome {
								if err := os.Chmod(homes, 0); err != nil {
									t.Fatal(err)
								}
								defer func() { _ = os.Chmod(homes, 0o700) }()
							}
							got := overLimitHostHookWithEvidence(t, connector, home, string(body), evidence)
							if blocked := nativeWriteBlockedOverBound(t, got, count > actionfacts.MaxOperandsPerCall); blocked != probe.want {
								t.Fatalf("blocked = %t, want %t: %.600s", blocked, probe.want, got)
							}
						})
					}
				}
			}
		}
	}
}
