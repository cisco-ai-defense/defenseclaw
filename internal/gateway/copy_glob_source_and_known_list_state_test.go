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
// With blind, the managed cells run behind a home the gateway cannot read, and
// only the default pack (the strict pack of that fixture blocks every call as
// an install window).
func runStateWriterRows(t *testing.T, home, project string, protected, ordinary []stateWriterRow, blind bool) {
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
				if blind && managed && pack != "" {
					continue
				}
				cell := fmt.Sprintf("%s/managed=%t/pack=%q", connector, managed, pack)
				for _, row := range protected {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, blind && managed, row.command)
					if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
						note(row, cell, got)
					}
				}
				for _, row := range ordinary {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, blind && managed, row.command)
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
	// A project directory that holds a link to the state file: cp writes
	// through it, a move or a link replaces it.
	if err := os.MkdirAll(filepath.Join(project, "linked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(project, "linked", "config.yaml")); err != nil {
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
	// The destination is a directory (the target-directory option in every
	// spelling, or a plain last operand that is a link to a state directory),
	// and a source pattern can name a protected file in it.
	for _, dir := range []string{"$HOME/.defenseclaw", "~/.defenseclaw", parent + active + "/.defenseclaw", "$HOME/aliasdir", "$HOME/aliasdir/"} {
		for _, verb := range []string{"cp", "mv", "ln -sf"} {
			for _, source := range []string{src + "/config*.yaml", "./conf*.yaml", "c*"} {
				for _, form := range []string{"-t " + dir + " " + source, "-t" + dir + " " + source, "--target-directory " + dir + " " + source,
					"--target-directory=" + dir + " " + source, "--target " + dir + " " + source, source + " -t " + dir, "-at " + dir + " " + source} {
					if strings.HasPrefix(form, "-at") && verb != "cp" {
						continue
					}
					// A home word joined to a short option (-t$HOME/d) is not read as a home path.
					if strings.HasPrefix(form, "-t"+dir) && strings.ContainsAny(dir, "$~") {
						continue
					}
					protected = append(protected,
						stateWriterRow{"target-directory", verb + " " + form},
						stateWriterRow{"loop-target-directory", "for u in $USER; do " + verb + " " + form + "; done"},
					)
				}
			}
		}
	}
	for _, dir := range []string{"$HOME/aliasdir", "$HOME/aliasdir/"} {
		protected = append(protected, stateWriterRow{"plain-directory-link", "cp " + src + "/config*.yaml " + dir})
	}
	for _, source := range []string{src + "/config*.yaml", src + "/conf*", "./conf*.yaml", src + "/{other,config}.yaml", "c*"} {
		for _, form := range []string{"cp " + source + " linked/", "cp -t linked " + source, "cp --target-directory=linked " + source, "cp " + source + " ./linked/"} {
			protected = append(protected,
				stateWriterRow{"directory-with-linked-child", form},
				stateWriterRow{"loop-directory-with-linked-child", "for u in $USER; do " + form + "; done"},
			)
		}
	}
	// A pattern is not the destination wherever else it stands: the value of
	// another option, or a word after the end of the options.
	for _, dest := range []string{state, "$HOME/.defenseclaw/config.yaml", "~/.defenseclaw/config.yaml", parent + "$USER/.defenseclaw/config.yaml", "$HOME/statealias"} {
		protected = append(protected,
			stateWriterRow{"option-value-pattern", "cp -S suffix*.bak " + src + "/a*.cfg " + dest},
			stateWriterRow{"after-end-of-options", "cp -- -S* " + dest},
			stateWriterRow{"loop-option-value-pattern", "for u in $USER; do cp -S suffix*.bak " + src + "/a*.cfg " + dest + "; done"},
		)
	}
	// A login the command binds to the active account is that account; the
	// same word bound to another account names the file of that account.
	for _, name := range []string{"USER", "LOGNAME"} {
		for _, bind := range []string{name + "=" + active + ";", "export " + name + "=" + active + ";"} {
			protected = append(protected, stateWriterRow{"bound-login", bind + " cp " + src + "/*.cfg " + parent + "$" + name + "/.defenseclaw/config.yaml"})
		}
	}
	ordinary := []stateWriterRow{
		{"directory-with-linked-child-other-names", "cp " + src + "/a*.cfg linked/"},
		{"directory-with-linked-child-other-names-target", "cp -t linked " + src + "/*.cfg"},
		{"move-into-directory-with-linked-child", "mv " + src + "/config*.yaml linked/"},
		{"glob-to-state-dir-no-protected-name", "cp -t $HOME/.defenseclaw " + src + "/*.cfg"},
		{"glob-to-state-dir-link-no-protected-name", "cp -t $HOME/aliasdir " + src + "/*.cfg"},
		{"glob-to-state-dir-plain-no-protected-name", "cp " + src + "/*.cfg $HOME/.defenseclaw/"},
		{"glob-option-value-to-project-file", "cp -S suffix*.bak " + src + "/a*.cfg ./ok"},
		{"glob-after-end-of-options-to-project-file", "cp -- -S* ./ok"},
		{"glob-target-directory-after-end-of-options", "cp -t ordinary -- " + src + "/config*.yaml"},
		{"glob-target-directory-long-project", "cp --target-directory=ordinary " + src + "/config*.yaml"},
		{"glob-sources-before-target-directory-project", "cp " + src + "/config*.yaml -t ordinary"},
		{"bound-other-login", "USER=ordinary; cp " + src + "/*.cfg " + parent + "$USER/.defenseclaw/config.yaml"},
		{"bound-other-logname", "LOGNAME=ordinary; cp " + src + "/*.cfg " + parent + "$LOGNAME/.defenseclaw/config.yaml"},
		{"exported-other-login", "export USER=ordinary; cp " + src + "/*.cfg " + parent + "$USER/.defenseclaw/config.yaml"},
		{"glob-to-project-file", "cp " + src + "/*.cfg ./ok"},
		{"glob-to-project-dir", "cp *.txt ordinary/"},
		{"glob-to-sibling-state-name", "cp " + src + "/*.cfg " + parent + "ordinary/aliasdir/config.yaml"},
		{"glob-loop-to-project-file", "for u in $USER; do cp " + src + "/*.cfg ./ok-$u; done"},
		{"glob-target-dir-project", "cp -t ordinary *.txt"},
		{"mv-glob-to-project-file", "mv a* ./ok"},
	}
	runStateWriterRows(t, home, project, protected, ordinary, false)
}

// rel-1-0-6:GAP-1052: a for loop over a variable with a known value reads the
// words of that value the way the shell splits an unquoted expansion, so a
// list that holds the login blocks a state write through the loop variable.
// A gateway behind a home it cannot read has no cwd of its own and reads the
// loop from the directory the hook client ran it in. A list of other names, a
// quoted expansion (one word) and an unknown value keep the verdict they have.
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
	runStateWriterRows(t, home, project, protected, ordinary, false)
	runStateWriterRows(t, home, project, protected, ordinary, true)
}
