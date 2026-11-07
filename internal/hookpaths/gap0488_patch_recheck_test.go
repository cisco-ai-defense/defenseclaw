// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0488, GAP-0073: PatchTargetWatch.Changed is true only for a patch the hook
// attested complete whose targets lead somewhere else, or to a protected key
// file, a second time. The identity of the file at an unchanged path is not
// compared: an editor save of the same ordinary file is not a change.
func TestGAP0488PatchTargetsChangedFollowsWhereTargetsLead(t *testing.T) {
	type call struct {
		connector, event string
		patch            bool
	}
	calls := map[string]call{
		"hermes v4a":     {"hermes", "pre_tool_call", true},
		"opencode patch": {"opencode", "tool.execute.before", true},
		"opencode write": {"opencode", "tool.execute.before", false},
	}
	patch := "*** Begin Patch\n*** Update File: swap.txt\n@@\n x\n+y\n*** Update File: other.txt\n@@\n x\n+y\n*** End Patch\n"
	for name, c := range calls {
		for _, change := range []struct {
			name string
			// mutate changes the project; the result reports a protected or moved target.
			mutate func(t *testing.T, project, keys string)
			want   bool
		}{
			{"nothing", func(*testing.T, string, string) {}, false},
			{"atomic save of the same ordinary file", func(t *testing.T, project, _ string) {
				saved := filepath.Join(project, "swap.txt.tmp")
				mustWrite(t, saved, "x\n")
				if err := os.Rename(saved, filepath.Join(project, "swap.txt")); err != nil {
					t.Fatal(err)
				}
			}, false},
			{"rewritten in place", func(t *testing.T, project, _ string) {
				mustWrite(t, filepath.Join(project, "swap.txt"), "changed\n")
			}, false},
			{"symlink to the keys file", func(t *testing.T, project, keys string) {
				replaceWith(t, filepath.Join(project, "swap.txt"), func(p string) error { return os.Symlink(keys, p) })
			}, true},
			{"hard link to the keys file", func(t *testing.T, project, keys string) {
				replaceWith(t, filepath.Join(project, "swap.txt"), func(p string) error { return os.Link(keys, p) })
			}, true},
			{"second target linked to the keys file", func(t *testing.T, project, keys string) {
				replaceWith(t, filepath.Join(project, "other.txt"), func(p string) error { return os.Symlink(keys, p) })
			}, true},
			{"symlink to another ordinary file", func(t *testing.T, project, _ string) {
				replaceWith(t, filepath.Join(project, "swap.txt"), func(p string) error {
					return os.Symlink(filepath.Join(project, "other.txt"), p)
				})
			}, true},
		} {
			t.Run(name+" "+change.name, func(t *testing.T) {
				home, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				project := filepath.Join(home, "proj")
				for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				keys := filepath.Join(home, ".ssh", "authorized_keys")
				mustWrite(t, keys, "k\n")
				mustWrite(t, filepath.Join(project, "swap.txt"), "x\n")
				mustWrite(t, filepath.Join(project, "other.txt"), "x\n")
				t.Setenv("HOME", home)
				var body []byte
				switch name {
				case "hermes v4a":
					body, _ = json.Marshal(map[string]any{"hook_event_name": c.event, "tool_name": "patch",
						"tool_input": map[string]any{"mode": "patch", "patch": patch}, "cwd": project})
				case "opencode patch":
					body, _ = json.Marshal(map[string]any{"hook_event_name": c.event, "tool_name": "patch",
						"tool_input": map[string]any{"patchText": patch}, "cwd": project})
				default:
					body, _ = json.Marshal(map[string]any{"hook_event_name": c.event, "tool_name": "write",
						"tool_input": map[string]any{"filePath": filepath.Join(project, "swap.txt"), "content": "y"}, "cwd": project})
				}
				evidence := ResolveConnector(c.connector, "", c.event, body)
				if watchOfEvidence(evidence).Changed() {
					t.Fatal("unchanged targets read as changed")
				}
				change.mutate(t, project, keys)
				want := change.want && c.patch
				if got := watchOfEvidence(evidence).Changed(); got != want {
					t.Errorf("changed = %v, want %v", got, want)
				}
			})
		}
	}
	if watchOfEvidence("").Changed() {
		t.Error("no evidence read as changed")
	}
}

// watchOfEvidence is the watch of an evidence header a hook sent, as the hook
// builds it from the map it encoded; nil when the header attests no complete
// patch.
func watchOfEvidence(evidence string) *PatchTargetWatch {
	targets, ok := Decode(evidence)
	if !ok {
		return nil
	}
	home, _ := os.UserHomeDir()
	return patchTargetWatchOf(targets, home)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// replaceWith removes path and makes it again with create.
func replaceWith(t *testing.T, path string, create func(string) error) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := create(path); err != nil {
		t.Fatal(err)
	}
}
