// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A delete removes the final name and follows only the links of its
// directory. A Delete File of a name below a directory link that leads into
// the home of the user removes the credential file there, so it is blocked
// as the direct name is; a Delete File of a link that is itself the final
// name removes the link, not the file it names, so it stays allowed. The
// gateway that follows links itself and the one that relies on the entries
// the hook client lists judge the same.
func TestTypedPatchDeleteFollowsTheDirectoryLinkAndNotTheFinalLink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{home, project, filepath.Join(home, ".aws"), filepath.Join(root, "plain")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".netrc"), filepath.Join(home, ".aws", "credentials"), filepath.Join(root, "plain", "notes.txt")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"homelink":  home,
		"awslink":   filepath.Join(home, ".aws"),
		"plainlink": filepath.Join(root, "plain"),
		"finalnet":  filepath.Join(home, ".netrc"),
		"finalaws":  filepath.Join(home, ".aws", "credentials"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	type deletion struct {
		name, entry string
		blocked     bool
	}
	cases := []deletion{
		{"homelink/.netrc", filepath.Join(home, ".netrc"), true},
		{"awslink/credentials", filepath.Join(home, ".aws", "credentials"), true},
		{"finalnet", filepath.Join(project, "finalnet"), false},
		{"finalaws", filepath.Join(project, "finalaws"), false},
		{"plainlink/notes.txt", filepath.Join(root, "plain", "notes.txt"), false},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "typed-patch-delete-link-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, tc := range cases {
			want := "allow"
			if tc.blocked {
				want = "block"
			}
			path := filepath.Join(project, tc.name)
			// The entry the hook client lists for a delete: the directory
			// followed, the final name kept.
			for label, evidence := range map[string]map[string]string{"gateway resolves": nil, "client lists": {path: tc.entry}} {
				if action, rules := patchDeleteVerdict(t, connector, "Delete File", home, project, path, evidence); action != want {
					t.Errorf("%s (%s) Delete File %q: %s %v, want %s", profile, label, tc.name, action, rules, want)
				}
			}
		}
		// A write follows the final link too: the same names are protected.
		for _, name := range []string{"finalnet", "finalaws"} {
			if action, rules := patchDeleteVerdict(t, connector, "Add File", home, project, filepath.Join(project, name), nil); action != "block" {
				t.Errorf("%s Add File through the final link %q: %s %v, want block", profile, name, action, rules)
			}
		}
	}
}
