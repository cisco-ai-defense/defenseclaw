// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// g622bStateNames are the names under ~/.defenseclaw the gateway protects
// (gateway activeDefenseClawStateNames); a protected tree is represented by
// a file below it.
var g622bStateNames = []string{
	".env", "audit.db", "audit.db-shm", "audit.db-wal", "cache", "confidence_policy.yaml",
	"config.yaml", "custom-providers.json", "device.key", "guardrail_runtime.json", "hooks",
	"installer", "judge.db", "judge.db-shm", "judge.db-wal", "judge_bodies.db",
	"judge_bodies.db-shm", "judge_bodies.db-wal", "picked_connector", "policies", "previous",
	"quarantine", "receipts", "registries",
}

func g622bStateFile(t *testing.T, home, name string) string {
	t.Helper()
	relative := name
	switch name {
	case "cache", "hooks", "installer", "policies", "quarantine", "receipts", "registries":
		relative = filepath.Join(name, "state.dat")
	case "previous":
		relative = filepath.Join(name, "installer", "state.dat")
	}
	path := filepath.Join(home, ".defenseclaw", relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, "# base\n")
	return path
}

func g622bPatchEvidence(t *testing.T, connector, project, target string) string {
	t.Helper()
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n # base\n+changed\n*** End Patch\n"
	var args map[string]any
	event := "tool.execute.before"
	if connector == "hermes" {
		event, args = "pre_tool_call", map[string]any{"mode": "patch", "patch": patch}
	} else {
		args = map[string]any{"patchText": patch}
	}
	body, err := json.Marshal(map[string]any{"hook_event_name": event, "tool_name": "patch", "tool_input": args, "cwd": project})
	if err != nil {
		t.Fatal(err)
	}
	return ResolveConnector(connector, "", event, body)
}

// GAP-0488, GAP-0073: a native patch target is judged by file identity
// against every file of the active DefenseClaw state. For each state file, a
// project hard link names the state file in the hook's evidence, and a
// target an ordinary file at the hook's first reading and a hard link, a
// symlink or a rename-swapped link to it afterwards reads as changed, for the
// Hermes V4A patch and the OpenCode patch. The ordinary twins (a hard link
// between two project files, a save of the same file) read as unchanged.
func TestG622bPatchTargetsAreJudgedByIdentityAgainstEveryStateFile(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		for i, name := range g622bStateNames {
			t.Run(fmt.Sprintf("%s %s", connector, name), func(t *testing.T) {
				home, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				project := filepath.Join(home, "proj")
				if err := os.MkdirAll(project, 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
				state := g622bStateFile(t, home, name)

				// A hard link at the first reading is the state file.
				hard := filepath.Join(project, fmt.Sprintf("hard-%d.txt", i))
				if err := os.Link(state, hard); err != nil {
					t.Fatal(err)
				}
				known, ok := Decode(g622bPatchEvidence(t, connector, project, hard))
				if !ok || known[hard] != state {
					t.Errorf("hard link evidence = %q (decoded %v), want the state file %q", known[hard], ok, state)
				}
				if err := os.Remove(hard); err != nil {
					t.Fatal(err)
				}

				// An ordinary target changed after the first reading.
				for j, swap := range []struct {
					name string
					make func(string) error
				}{
					{"hard link", func(p string) error { return os.Link(state, p) }},
					{"symlink", func(p string) error { return os.Symlink(state, p) }},
					{"hard link saved by rename", func(p string) error {
						staged := p + ".new"
						if err := os.Link(state, staged); err != nil {
							return err
						}
						return os.Rename(staged, p)
					}},
				} {
					target := filepath.Join(project, fmt.Sprintf("swap-%d-%d.txt", i, j))
					mustWrite(t, target, "# base\n")
					watch := watchOfEvidence(g622bPatchEvidence(t, connector, project, target))
					if watch == nil || watch.Changed() {
						t.Fatalf("%s: ordinary target read as changed before the swap (watch present: %t)", swap.name, watch != nil)
					}
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
					if err := swap.make(target); err != nil {
						t.Fatal(err)
					}
					if !watch.Changed() {
						t.Errorf("%s to state file %s was not read as a change", swap.name, name)
					}
				}
			})
		}
	}
}

// The ordinary twins of the state-identity test: a hard link between two
// project files is no state file, and a target saved again at the same path
// (also as a hard link to another project file) is no change.
func TestG622bOrdinaryHardLinkedPatchTargetsStayAllowed(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			project := filepath.Join(home, "proj")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			g622bStateFile(t, home, "config.yaml")
			one, two := filepath.Join(project, "one.txt"), filepath.Join(project, "two.txt")
			mustWrite(t, one, "x\n")
			if err := os.Link(one, two); err != nil {
				t.Fatal(err)
			}
			evidence := g622bPatchEvidence(t, connector, project, two)
			targets, ok := Decode(evidence)
			if !ok || targets[two] != two || targets[PatchCompleteKey] != "1" {
				t.Fatalf("hard link between project files: evidence %v (ok %v), want itself and complete", targets, ok)
			}
			watch := watchOfEvidence(evidence)
			if watch.Changed() {
				t.Error("hard link between project files read as changed")
			}
			saved := two + ".tmp"
			mustWrite(t, saved, "x\n")
			if err := os.Rename(saved, two); err != nil {
				t.Fatal(err)
			}
			if watch.Changed() {
				t.Error("an atomic save of the target read as changed")
			}
		})
	}
}
