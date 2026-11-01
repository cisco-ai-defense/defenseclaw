// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestR107KnownCopyWordAfterCdGetsTheVerdictWithoutTheCd: the unquoted
// rel-1-0-2:GAP-0004 copy forms (a source named by an assigned plain value
// or a one-name for loop) after a leading cd get the verdict they get
// without it, in every cell (rel-1-0-6:GAP-0320). The cd twins of the
// keys-bound forms, and a copy of the keys link after cd, still block.
func TestR107KnownCopyWordAfterCdGetsTheVerdictWithoutTheCd(t *testing.T) {
	checkDynamicWordParity(t,
		[]string{
			`f=a.txt; cp $f out.txt && echo ok`,
			`cd ~/proj && f=a.txt; cp "$f" out.txt && echo ok`,
			`cd ~/proj && f=a.txt; cp $f out.txt && echo ok`,
			`cd ~/proj; f=a.txt; cp $f out.txt`,
			`cd ~/proj && f=a.txt; cp $f out.txt`,
			`cd ~/proj && for x in a.txt; do cp $x build/; done; echo hi > report.txt`,
			`cd ~/proj && cp a.txt out.txt; echo hi > report.txt`,
		},
		[]string{
			`cd ~/proj && cp $f build/ && echo hi > report.txt`,
			`cd ~/proj && f=a.txt; cp $f disklink`,
			`cd ~/proj && for f in a.txt; do cp $f disklink; done`,
			`cd ~/proj && f=a.txt; cp $f build/; echo hi > disklink`,
			`cd ~/proj && f=a.txt; read f; cp $f build/ && echo hi > report.txt`,
			`cd ~/proj && T=--target-directory=$HOME/.ssh; cp $T a.txt`,
			`cd ~/proj && f=disklink; cp -a $f kbak && echo k >> kbak`,
			`cd ~/proj && cp -a disklink kbak && echo k >> kbak`,
			`cd ~/.ssh && f=a.txt; cp ~/proj/$f authorized_keys`,
			`cd ~ && f=a.txt; cp proj/$f .ssh/authorized_keys`,
			`cd /nonexistent-r107 && f=a.txt; cp $f build/ && echo hi > report.txt`,
			`cd ~/proj/../proj && f=a.txt; cp $f build/ && echo hi > report.txt`,
			`echo x; cd ~/proj && f=a.txt; cp $f build/ && echo hi > report.txt`,
		})
}

// TestR107Review5CdConditionsOfTheKnownCopyWord: review 5 of a458e99554
// (rel-1-0-6:GAP-0320). One must-deny row per condition of the leading-cd
// reading, beside must-allow neighbours, in all 4 cells: a cd target that
// is missing, not enterable (mode 0), a dash word with a directory named
// "-" present, a cd that is not the first statement, a dynamic cd word that
// binds f, and a known word copied after a mid-command cd from a folder
// holding a keys link.
func TestR107Review5CdConditionsOfTheKnownCopyWord(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, dir := range []string{"-", "locked"} {
		if err := os.MkdirAll(filepath.Join(project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "build", "kl.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(project, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(project, "locked"), 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root enters a mode 0 directory")
	}
	allowed := []string{
		`cd build && f=a.txt; cp $f out.txt`,
		`f=a.txt; cd build; cp $f out.txt`,
		`cd build && f=a.txt; cp $f build2/ && echo hi > report.txt`,
	}
	blocked := []string{
		`cd nosuch && f=a.txt; cp $f build/ && echo hi > report.txt`,
		`cd locked && f=a.txt; cp $f build/ && echo hi > report.txt`,
		`cd - && f=a.txt; cp $f build/ && echo hi > report.txt`,
		`cd ~; cd build && f=a.txt; cp $f build/ && echo hi > report.txt`,
		`f=; cd ${f:=disklink} 2>/dev/null; cp -a $f kbak && echo k >> kbak`,
		`f=kl.txt; cd build; cp -a $f kbak && echo k >> kbak`,
		`cd build; cp -a kl.txt kbak && echo k >> kbak`,
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, command := range allowed {
				if got := postDynamicWordParity(t, home, project, connector, managed, command, nil); !strings.HasPrefix(got, `{"action":"allow"`) {
					t.Errorf("%s managed=%v %s = %.200s, want allow", connector, managed, command, got)
				}
			}
			for _, command := range blocked {
				if got := postDynamicWordParity(t, home, project, connector, managed, command, nil); !strings.HasPrefix(got, `{"action":"block"`) {
					t.Errorf("%s managed=%v %s = %.200s, want block", connector, managed, command, got)
				}
			}
		}
	}
}

// TestR107Review6ForgedCdEnterableFact: review 6 of 74119a1a2b
// (rel-1-0-6:GAP-0320). The managed client evidence is edited to claim
// that a missing or mode-0 directory is enterable (a forged
// CdEnterableFactPrefix "1"). The forged fact may change how a copy source
// word is read, but no write onto the keys decoy may pass: every row
// below must still block on managed Claude Code and Codex. A value other
// than "1" must make the evidence invalid, which keeps the block.
func TestR107Review6ForgedCdEnterableFact(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	if os.Geteuid() == 0 {
		t.Skip("root enters a mode 0 directory")
	}
	locked := filepath.Join(project, "locked")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	forge := func(value string, dirs ...string) func(map[string]string) {
		return func(targets map[string]string) {
			for _, dir := range dirs {
				targets[hookpaths.CdEnterableFactPrefix+dir] = value
			}
		}
	}
	nosuch := filepath.Join(project, "nosuch")
	sshDir := filepath.Join(home, ".ssh")
	rows := []struct {
		name, command string
		edit          func(map[string]string)
	}{
		{"missing dir, copy onto the keys link", `cd nosuch && f=a.txt; cp $f disklink`, forge("1", nosuch)},
		{"missing dir, copy onto the keys file", `cd nosuch && f=a.txt; cp $f ~/.ssh/authorized_keys`, forge("1", nosuch)},
		{"missing dir, write the keys link after the copy", `cd nosuch && f=a.txt; cp $f build/; echo hi > disklink`, forge("1", nosuch)},
		{"locked dir, known word names the keys link, copy then write", `cd locked && f=disklink; cp -a $f kbak && echo k >> kbak`, forge("1", locked)},
		{"locked dir, copy onto the keys link", `cd locked && f=a.txt; cp $f disklink`, forge("1", locked)},
		{"ssh dir, copy onto the keys file", `cd ~/.ssh && f=a.txt; cp ~/proj/$f authorized_keys`, forge("1", sshDir)},
		{"missing dir, a fact value other than 1", `cd nosuch && f=a.txt; cp $f build/ && echo hi > report.txt`, forge("0", nosuch)},
		{"missing dir, a relative fact key", `cd nosuch && f=a.txt; cp $f build/ && echo hi > report.txt`, forge("1", "nosuch")},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			if got := postDynamicWordParity(t, home, project, connector, true, row.command, row.edit); !strings.HasPrefix(got, `{"action":"block"`) {
				t.Errorf("%s managed %s: %.200s, want block", connector, row.name, got)
			}
		}
		// Informational: a forged "1" for a missing dir with no decoy write.
		got := postDynamicWordParity(t, home, project, connector, true, `cd nosuch && f=a.txt; cp $f build/ && echo hi > report.txt`, forge("1", nosuch))
		t.Logf("INFO %s managed forged missing dir, plain copy: %.40s", connector, got)
	}
}
