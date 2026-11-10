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
// nothing through it: a lookup, quoted text, the pattern of a search and a
// function body nothing calls. The default tier allows each; the strict tier
// keeps refusing every word that names the link. A call that reads through
// the link stays refused in both.
func TestShellCallThatOnlyMentionsALinkToADeniedSkillIsAllowedInTheDefaultTier(t *testing.T) {
	mentions := []string{
		"command -v lnk-held",
		"command -V lnk-held && echo ok",
		`echo "cd lnk-held && ls"`,
		`echo 'cat lnk-held'`,
		"f() { cat lnk-held/SKILL.md; }",
		"f() { cat lnk-held; }; echo ok",
		"grep lnk-held notes.txt",
		"grep -rn lnk-held notes.txt",
		"grep -e lnk-held notes.txt",
		"rg -n lnk-held notes.txt",
		"cat notes.txt | grep lnk-held",
		"echo lnk-held",
		"printf %s lnk-held",
	}
	if runtime.GOOS != "windows" {
		mentions = append(mentions, "type cat lnk-held", "type lnk-held")
	}
	reads := []string{
		"cat lnk-held",
		"cat lnk-held/SKILL.md",
		"cd lnk-held && ls",
		"f() { cat lnk-held/SKILL.md; }; f",
		"command -v lnk-held; cat lnk-held",
		`echo "cd lnk-held && ls" | sh`,
		"echo lnk-held | xargs cat",
		"grep token lnk-held",
		"grep -r token lnk-held",
		"grep -e token lnk-held",
		"grep -f lnk-held notes.txt",
		"grep -R token . lnk-held",
		"grep -R lnk-held .",
		"grep lnk-held notes.txt; cat lnk-held",
	}
	for _, strict := range []bool{false, true} {
		f := newOperandContextFixture(t, "held")
		if err := os.Symlink(f.held, filepath.Join(f.proj, "lnk-held")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		if strict {
			f.inStrictTier(t)
		}
		for _, command := range mentions {
			if got := f.blocks("Bash", f.proj, map[string]interface{}{"command": command}); got != strict {
				t.Errorf("strict=%t %q: blocked = %t, want %t", strict, command, got, strict)
			}
		}
		for _, command := range reads {
			if !f.blocks("Bash", f.proj, map[string]interface{}{"command": command}) {
				t.Errorf("strict=%t %q: read of a denied skill through a link allowed", strict, command)
			}
		}
		for _, vector := range [][]interface{}{
			{"command", "-v", "lnk-held"}, {"echo", "cd lnk-held && ls"}, {"grep", "lnk-held", "notes.txt"},
		} {
			if got := f.blocks("Bash", f.proj, map[string]interface{}{"command": vector}); got != strict {
				t.Errorf("strict=%t %v: blocked = %t, want %t", strict, vector, got, strict)
			}
		}
		if !f.blocks("Bash", f.proj, map[string]interface{}{"command": []interface{}{"grep", "-r", "token", "lnk-held"}}) {
			t.Errorf("strict=%t: grep of the link as a file operand in a vector allowed", strict)
		}
	}
}
