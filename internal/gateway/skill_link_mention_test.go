// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A shell call that only mentions the name of a link to a denied skill reads
// nothing through it: a lookup, quoted or printed text, a comment, the pattern
// of a search and a function body nothing calls. The default tier allows
// each; the strict tier keeps refusing every word that names the link. A call
// that reads through the link stays refused in both, whatever it spells: a
// search that lists its operands (rg --files), a function a variable calls,
// text a pipe hands to a command. The assetfacts tests hold the spellings.
func TestShellCallThatOnlyMentionsALinkToADeniedSkillIsAllowedInTheDefaultTier(t *testing.T) {
	mentions := []string{
		"command -v lnk-held",
		`echo "cd lnk-held && ls"`,
		"f() { cat lnk-held/SKILL.md; }",
		"grep lnk-held notes.txt",
		"rg -n lnk-held notes.txt",
		"echo lnk-held",
		`echo "lnk-held/SKILL.md"`,
		"echo ok # cat lnk-held/SKILL.md",
		"grep lnk-held/SKILL.md notes.txt",
		"echo cat lnk-held",
	}
	if runtime.GOOS != "windows" {
		mentions = append(mentions, "type lnk-held")
	}
	reads := []string{
		"cat lnk-held",
		"cd lnk-held && ls",
		"f() { cat lnk-held/SKILL.md; }; f",
		"command -v lnk-held; cat lnk-held",
		`echo "cd lnk-held && ls" | sh`,
		"echo lnk-held | xargs cat",
		"echo lnk-held/SKILL.md | xargs cat",
		"grep token lnk-held",
		"grep -R lnk-held .",
		"grep lnk-held notes.txt; cat lnk-held",
		"rg --files lnk-held",
		`f() { cat lnk-held/SKILL.md; }; reader=f; "$reader"`,
	}
	vectors := [][]interface{}{{"command", "-v", "lnk-held"}, {"grep", "lnk-held/SKILL.md", "notes.txt"}}
	// One fixture serves both tiers: the store behind it costs more than the
	// calls do.
	f := newOperandContextFixture(t, "held")
	if err := os.Symlink(f.held, filepath.Join(f.proj, "lnk-held")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	for _, strict := range []bool{false, true} {
		if strict {
			f.inStrictTier(t)
		}
		for _, command := range mentions {
			if got := f.blocks("Bash", f.proj, map[string]interface{}{"command": command}); got != strict {
				t.Errorf("strict=%t %q: blocked = %t, want %t", strict, command, got, strict)
			}
		}
		for _, vector := range vectors {
			if got := f.blocks("Bash", f.proj, map[string]interface{}{"command": vector}); got != strict {
				t.Errorf("strict=%t %v: blocked = %t, want %t", strict, vector, got, strict)
			}
		}
		for i, command := range reads {
			if strict && i > 2 {
				break
			}
			if !f.blocks("Bash", f.proj, map[string]interface{}{"command": command}) {
				t.Errorf("strict=%t %q: read of a denied skill through a link allowed", strict, command)
			}
		}
		if !f.blocks("Bash", f.proj, map[string]interface{}{"command": []interface{}{"grep", "-r", "token", "lnk-held"}}) {
			t.Errorf("strict=%t: grep of the link as a file operand in a vector allowed", strict)
		}
	}
}
