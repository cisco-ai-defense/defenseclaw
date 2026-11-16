// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction, a directory symlink and a chain of them, spelled with the
// extended-length prefix, lead into the same skill folder as the plain
// spelling does; so does the folder spelled with the prefix directly.
func TestExtendedLengthSpellingOfALinkLeadsIntoTheSkillFolder(t *testing.T) {
	home, _, held := skillTree(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(proj, "junction-held")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, held).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v: %s", err, out)
	}
	links := map[string]string{"junction": junction, "held folder": held}
	// A directory symlink needs a privilege a runner may not give.
	dirLink := filepath.Join(proj, "symlink-held")
	chain := filepath.Join(proj, "chain-held")
	if os.Symlink(held, dirLink) == nil && os.Symlink(junction, chain) == nil {
		links["directory symlink"], links["chain"] = dirLink, chain
	}
	for name, link := range links {
		for _, prefix := range []string{`\\?\`, `\\.\`, ""} {
			t.Run(name+" "+prefix, func(t *testing.T) {
				for field, input := range map[string]map[string]any{
					"command": {"command": "type " + prefix + filepath.Join(link, "SKILL.md")},
					"Read":    {"file_path": prefix + filepath.Join(link, "SKILL.md")},
				} {
					refs := SkillFolderRefs("", input, home, proj)
					if !reaches(refs, held) {
						t.Errorf("%s %v: refs = %+v, want one to %s", field, input, refs, held)
					}
				}
			})
		}
	}
	// The ordinary twin: a link to a folder that is no skill folder.
	other := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	otherLink := filepath.Join(proj, "junction-other")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", otherLink, other).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v: %s", err, out)
	}
	if refs := SkillFolderRefs("", map[string]any{"command": "type " + `\\?\` + filepath.Join(otherLink, "notes.txt")}, home, proj); len(refs) != 0 {
		t.Errorf("ordinary link with the extended prefix: refs = %+v, want none", refs)
	}
}
