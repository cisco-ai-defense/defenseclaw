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

// A Delete File of a link removes the link, so the hook attests the entry (its
// directory followed, the link name kept) and reads it again as that entry:
// the file the link reaches, a credential file included, is not the target of
// the delete, and a link to it is removed like any other. A target that is
// not a delete is still read through the link, and a delete whose directory
// leads elsewhere since the reading, or whose entry is itself a protected key
// file, still reads as changed (the credential files are the gateway's call).
func TestPatchTargetWatchDeleteOfLinkIsReadAsTheEntry(t *testing.T) {
	deleteWatch := func(t *testing.T, project, verb, target string) *PatchTargetWatch {
		t.Helper()
		patch := "*** Begin Patch\n*** " + verb + " File: " + target + "\n"
		if verb == "Update" {
			patch += "@@\n k\n+x\n"
		}
		patch += "*** End Patch\n"
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
			"tool_input": map[string]any{"command": patch}, "cwd": project})
		if err != nil {
			t.Fatal(err)
		}
		watch := watchOfEvidence(ResolveConnector("codex", "", "PreToolUse", body))
		if watch == nil {
			t.Fatalf("%s File %s: the patch is not attested complete", verb, target)
		}
		return watch
	}
	fixture := func(t *testing.T) (home, project string) {
		t.Helper()
		home, project = stepUpFixture(t)
		mustWrite(t, filepath.Join(home, ".netrc"), "machine x\n")
		for name, target := range map[string]string{
			"lnk-netrc": filepath.Join(home, ".netrc"),
			"lnk-notes": filepath.Join(project, "notes.txt"),
			"lnk-ssh":   filepath.Join(home, ".ssh", "authorized_keys"),
		} {
			if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(home, filepath.Join(project, "lnk-home")); err != nil {
			t.Fatal(err)
		}
		return home, project
	}

	for _, name := range []string{"lnk-netrc", "lnk-notes", "lnk-ssh", "notes.txt"} {
		t.Run("delete of "+name+" is not a change", func(t *testing.T) {
			_, project := fixture(t)
			for _, spelling := range []string{name, filepath.Join(project, name)} {
				if deleteWatch(t, project, "Delete", spelling).Changed() {
					t.Errorf("Delete File %s read as changed", spelling)
				}
			}
		})
	}
	t.Run("a link retargeted since the reading is still the same entry", func(t *testing.T) {
		home, project := fixture(t)
		watch := deleteWatch(t, project, "Delete", "lnk-notes")
		replaceWith(t, filepath.Join(project, "lnk-notes"), func(p string) error {
			return os.Symlink(filepath.Join(home, ".netrc"), p)
		})
		if watch.Changed() {
			t.Error("a link retargeted since the reading read as changed")
		}
	})
	t.Run("update through the same link is read through it", func(t *testing.T) {
		_, project := fixture(t)
		watch := deleteWatch(t, project, "Update", "lnk-notes")
		replaceWith(t, filepath.Join(project, "lnk-notes"), func(p string) error {
			return os.Symlink(filepath.Join(project, "..", ".netrc"), p)
		})
		if !watch.Changed() {
			t.Error("an update retargeted to the credential file read as unchanged")
		}
	})
	t.Run("a name below a link into the home is a change", func(t *testing.T) {
		_, project := fixture(t)
		if !deleteWatch(t, project, "Delete", "lnk-home/.ssh/authorized_keys").Changed() {
			t.Error("Delete File below a link to the home read as unchanged")
		}
	})
	t.Run("the protected key file itself is a change", func(t *testing.T) {
		home, project := fixture(t)
		if !deleteWatch(t, project, "Delete", filepath.Join(home, ".ssh", "authorized_keys")).Changed() {
			t.Error("Delete File of the keys file read as unchanged")
		}
	})
	t.Run("a directory that becomes a link since the reading is a change", func(t *testing.T) {
		home, project := fixture(t)
		if err := os.Mkdir(filepath.Join(project, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(project, "sub", ".netrc"), "n\n")
		watch := deleteWatch(t, project, "Delete", "sub/.netrc")
		if watch.Changed() {
			t.Fatal("an ordinary file in a project directory read as changed")
		}
		if err := os.RemoveAll(filepath.Join(project, "sub")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(home, filepath.Join(project, "sub")); err != nil {
			t.Fatal(err)
		}
		if !watch.Changed() {
			t.Error("the directory led to the home since the reading, and the delete read as unchanged")
		}
	})
}
