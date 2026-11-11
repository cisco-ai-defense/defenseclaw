// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stateWriterRow struct{ name, command string }

// stateCell is one connector, rule pack and per-user or managed setup.
type stateCell struct {
	connector, pack string
	managed         bool
}

// The balanced cells run every row; the spread cells (the other connector and
// the strict pack, per-user and managed) run a few rows that stand for each
// behaviour, so the whole test stays inside the test time budget.
var (
	balancedStateCells = []stateCell{{"claudecode", "", false}, {"claudecode", "", true}}
	managedStateCells  = []stateCell{{"claudecode", "", true}}
	spreadStateCells   = []stateCell{{"codex", "", false}, {"claudecode", "strict", false}, {"claudecode", "strict", true}}
)

// runStateWriterRows posts every row in every cell. A protected row must
// block on the DefenseClaw state rule in every cell; an ordinary row must not
// block in any. One error names each failing row with the first cell it
// failed in. With blind, the managed cells run behind a home the gateway
// cannot read (the strict pack of that fixture blocks every call as an
// install window, so it is skipped there).
func runStateWriterRows(t *testing.T, home, project string, cells []stateCell, protected, ordinary []stateWriterRow, blind bool) {
	t.Helper()
	failed := map[string][]string{}
	var order []string
	note := func(row stateWriterRow, cell, got string) {
		key := row.name + ": " + row.command
		if _, seen := failed[key]; !seen {
			order = append(order, key)
		}
		failed[key] = append(failed[key], cell+" "+got[:min(len(got), 60)])
	}
	for _, c := range cells {
		if blind && c.managed && c.pack != "" {
			continue
		}
		cell := fmt.Sprintf("%s/managed=%t/pack=%q", c.connector, c.managed, c.pack)
		for _, row := range protected {
			got := postSelfProtectionPackCell(t, home, project, c.connector, c.pack, c.managed, blind && c.managed, row.command)
			if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
				note(row, cell, got)
			}
		}
		for _, row := range ordinary {
			got := postSelfProtectionPackCell(t, home, project, c.connector, c.pack, c.managed, blind && c.managed, row.command)
			if strings.HasPrefix(got, `{"action":"block"`) {
				note(row, cell, got)
			}
		}
	}
	for _, key := range order {
		t.Errorf("%s -> wrong in %d cells, first %s", key, len(failed[key]), failed[key][0])
	}
}

// rel-1-0-6:GAP-1053: the destination operand of cp, mv, install and ln names
// what is written whatever the source words are. A glob in a source word does
// not hide the destination, in or out of a loop, spelled by absolute path,
// HOME, tilde, USER or a link. A target directory (every option spelling
// reads the same operand roles), a directory link and a directory with a link
// child named by the pattern keep the state rule. A pattern in an option
// value or after the end of the options is not a source. A login bound to the
// active account is that account; bound to another it names another file.
func TestCopyWithGlobSourceKeepsItsStateDestination(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	state := parent + active + "/.defenseclaw/config.yaml"
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.cfg"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A project directory that holds a link to the state file: cp writes
	// through it, a move or a link replaces it.
	if err := os.MkdirAll(filepath.Join(project, "linked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(project, "linked", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	protected := []stateWriterRow{
		{"plain-absolute", "cp " + src + "/*.cfg " + state},
		{"plain-home-star", "cp * $HOME/.defenseclaw/config.yaml"},
		{"plain-user-move", "mv " + src + "/[ab].cfg " + parent + "$USER/.defenseclaw/config.yaml"},
		{"plain-install", "install -m 600 " + src + "/*.cfg $HOME/.defenseclaw/config.yaml"},
		{"plain-file-link", "cp " + src + "/*.cfg $HOME/statealias"},
		{"loop-plain", "for u in $USER; do cp " + src + "/*.cfg " + parent + "$u/.defenseclaw/config.yaml; done"},
		{"target-directory-short", "cp -t $HOME/.defenseclaw ./conf*.yaml"},
		{"target-directory-long-equals", "cp --target-directory=~/.defenseclaw " + src + "/config*.yaml"},
		{"target-directory-after-sources", "mv ./conf*.yaml -t " + parent + active + "/.defenseclaw"},
		{"target-directory-ln", "ln -sf -t $HOME/.defenseclaw ./conf*.yaml"},
		{"plain-directory-link", "cp " + src + "/config*.yaml $HOME/aliasdir/"},
		{"directory-with-linked-child", "cp " + src + "/config*.yaml linked/"},
		{"directory-with-linked-child-loop", "for u in $USER; do cp " + src + "/{other,config}.yaml linked/; done"},
		{"option-value-pattern", "cp -S suffix*.bak " + src + "/a*.cfg " + state},
		{"after-end-of-options", "cp -- -S* $HOME/.defenseclaw/config.yaml"},
		{"bound-login", "USER=" + active + "; cp " + src + "/*.cfg " + parent + "$USER/.defenseclaw/config.yaml"},
	}
	ordinary := []stateWriterRow{
		{"directory-with-linked-child-other-names", "cp " + src + "/a*.cfg linked/"},
		{"move-into-directory-with-linked-child", "mv " + src + "/config*.yaml linked/"},
		{"glob-to-state-dir-no-protected-name", "cp -t $HOME/.defenseclaw " + src + "/*.cfg"},
		{"glob-option-value-to-project-file", "cp -S suffix*.bak " + src + "/a*.cfg ./ok"},
		{"glob-target-directory-project", "cp --target-directory=ordinary " + src + "/config*.yaml"},
		{"bound-other-login", "USER=ordinary; cp " + src + "/*.cfg " + parent + "$USER/.defenseclaw/config.yaml"},
		{"glob-to-project-file", "cp " + src + "/*.cfg ./ok"},
		{"glob-loop-to-project-file", "for u in $USER; do cp " + src + "/*.cfg ./ok-$u; done"},
	}
	runStateWriterRows(t, home, project, balancedStateCells, protected, ordinary, false)
	spreadProtected := []stateWriterRow{protected[0], protected[6], protected[10], protected[11]}
	spreadOrdinary := []stateWriterRow{ordinary[2], ordinary[6]}
	runStateWriterRows(t, home, project, spreadStateCells, spreadProtected, spreadOrdinary, false)
}

// rel-1-0-6:GAP-1052: a for loop over a variable with a known value reads the
// words of that value the way the shell splits an unquoted expansion, so a
// list that holds the login blocks a state write through the loop variable.
// A gateway behind a home it cannot read has no cwd of its own and reads the
// loop from the directory the hook client ran it in. A list of other names, a
// quoted expansion (one word) and an unknown value keep the verdict they have.
func TestLoopOverKnownMultiWordVariableReachesState(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	target := parent + "$u/.defenseclaw/config.yaml"
	protected := []stateWriterRow{
		{"prefix", `L="zed $USER"; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
		{"suffix-with-extra-word-cp", `L="$USER zed"; for u in $L extra; do cp a.txt ` + target + `; done`},
		{"export-redirect", `export L="a b $USER c"; for u in $L; do printf x > ` + target + `; done`},
		{"array", `L=(zed $USER); for u in "${L[@]}"; do sed -i s/a/b/ ` + target + `; done`},
		{"nested-var", `M=$USER; L="zed $M"; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
		{"control-single-var", `L=$USER; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
	}
	ordinary := []stateWriterRow{
		{"other-names-sibling-state", `L="zed ordinary"; for u in $L; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`},
		{"login-ordinary-file", `L="zed $USER"; for u in $L; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`},
		{"quoted-expansion-one-word", `L="zed ordinary"; for u in "$L"; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`},
		{"known-ordinary-copy", `L="a.txt b.txt"; for f in $L; do cp $f ordinary/; done`},
	}
	runStateWriterRows(t, home, project, balancedStateCells, protected, ordinary, false)
	// Behind a home the gateway cannot read: one row per list form that takes
	// a different path (a split string, an array) and the ordinary twin.
	runStateWriterRows(t, home, project, managedStateCells, []stateWriterRow{protected[0], protected[3]}, ordinary[1:2], true)
	runStateWriterRows(t, home, project, spreadStateCells[1:2], protected[:1], ordinary[1:2], false)
}
