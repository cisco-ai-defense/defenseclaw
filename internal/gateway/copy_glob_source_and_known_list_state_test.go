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

// runStateWriterRows posts every row for both connectors, per-user and
// managed, in the default and strict packs. A protected row must block on the
// DefenseClaw state rule in every cell; an ordinary row must not block in
// any. One error names each failing row with the first cell it failed in.
func runStateWriterRows(t *testing.T, home, project string, protected, ordinary []stateWriterRow) {
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
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict"} {
				cell := fmt.Sprintf("%s/managed=%t/pack=%q", connector, managed, pack)
				for _, row := range protected {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
						note(row, cell, got)
					}
				}
				for _, row := range ordinary {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					if strings.HasPrefix(got, `{"action":"block"`) {
						note(row, cell, got)
					}
				}
			}
		}
	}
	for _, key := range order {
		t.Errorf("%s -> wrong in %d cells, first %s", key, len(failed[key]), failed[key][0])
	}
}

// rel-1-0-6:GAP-1053: the destination operand of cp, mv and install names
// what is written whatever the source words are. A glob in a source word
// (one that matches, matches nothing, or is not readable by the gateway) does
// not hide the destination, in or out of a loop, spelled by absolute path,
// HOME, USER or a loop variable. A pattern in the destination position or a
// target-directory value is not a source and keeps its own reading.
func TestCopyWithGlobSourceKeepsItsStateDestination(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	state := parent + active + "/.defenseclaw/config.yaml"
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.cfg"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var protected []stateWriterRow
	for _, dest := range []struct{ name, word string }{
		{"absolute", state}, {"home", "$HOME/.defenseclaw/config.yaml"}, {"tilde", "~/.defenseclaw/config.yaml"},
		{"user", parent + "$USER/.defenseclaw/config.yaml"}, {"link", "$HOME/statealias"},
	} {
		for _, src := range []string{src + "/*.cfg", "*", "./*.yaml", src + "/[ab].cfg", src + "/*.cfg " + src + "/other"} {
			for _, verb := range []string{"cp", "mv", "install -m 600", "cp -f"} {
				if verb == "mv" && dest.name == "link" {
					// A move onto a link replaces the link, not the file it names.
					continue
				}
				protected = append(protected,
					stateWriterRow{"plain-" + dest.name, verb + " " + src + " " + dest.word},
					stateWriterRow{"loop-" + dest.name, "for u in $USER; do " + verb + " " + src + " " + dest.word + "; done"},
				)
			}
		}
	}
	ordinary := []stateWriterRow{
		{"glob-to-project-file", "cp " + src + "/*.cfg ./ok"},
		{"glob-to-project-dir", "cp *.txt ordinary/"},
		{"glob-to-sibling-state-name", "cp " + src + "/*.cfg " + parent + "ordinary/aliasdir/config.yaml"},
		{"glob-loop-to-project-file", "for u in $USER; do cp " + src + "/*.cfg ./ok-$u; done"},
		{"glob-target-dir-project", "cp -t ordinary *.txt"},
		{"mv-glob-to-project-file", "mv a* ./ok"},
	}
	runStateWriterRows(t, home, project, protected, ordinary)
}

// rel-1-0-6:GAP-1052 (not reproduced on rel d0e6d95094; kept as the class
// guard): a for loop over a variable with a known value reads the
// words of that value the way the shell splits an unquoted expansion, so a
// list that holds the login blocks a state write through the loop variable.
// A list of other names, a quoted expansion (one word) and an unknown value
// keep the verdict they have.
func TestLoopOverKnownMultiWordVariableReachesState(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	var protected []stateWriterRow
	target := parent + "$u/.defenseclaw/config.yaml"
	for _, decl := range []string{
		`L="zed $USER"`, `L="$USER zed"`, `L="zed ` + active + `"`, `L="zed ${USER}"`, `L="a b $USER c"`, `L=zed\ $USER`,
	} {
		for _, list := range []string{"$L", "$L extra"} {
			protected = append(protected,
				stateWriterRow{"sed", decl + `; for u in ` + list + `; do sed -i s/a/b/ ` + target + `; done`},
				stateWriterRow{"export-sed", `export ` + decl + `; for u in ` + list + `; do sed -i s/a/b/ ` + target + `; done`},
				stateWriterRow{"redirect", decl + `; for u in ` + list + `; do printf x > ` + target + `; done`},
				stateWriterRow{"cp", decl + `; for u in ` + list + `; do cp a.txt ` + target + `; done`},
			)
		}
	}
	protected = append(protected,
		stateWriterRow{"array", `L=(zed $USER); for u in "${L[@]}"; do sed -i s/a/b/ ` + target + `; done`},
		stateWriterRow{"array-star", `L=(zed $USER); for u in ${L[@]}; do sed -i s/a/b/ ` + target + `; done`},
		stateWriterRow{"nested-var", `M=$USER; L="zed $M"; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
		stateWriterRow{"split-var", `A=zed; B=$USER; L="$A $B"; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
		stateWriterRow{"control-unquoted-list", `for u in zed $USER; do sed -i s/a/b/ ` + target + `; done`},
		stateWriterRow{"control-single-var", `L=$USER; for u in $L; do sed -i s/a/b/ ` + target + `; done`},
	)
	ordinary := []stateWriterRow{
		{"other-names", `L="zed ordinary"; for u in $L; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`},
		{"other-names-sibling-state", `L="zed ordinary"; for u in $L; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`},
		{"login-ordinary-file", `L="zed $USER"; for u in $L; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`},
		{"quoted-expansion-one-word", `L="zed ordinary"; for u in "$L"; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`},
		{"known-ordinary-copy", `L="a.txt b.txt"; for f in $L; do cp $f ordinary/; done`},
	}
	runStateWriterRows(t, home, project, protected, ordinary)
}
