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

// A writer in a loop body is judged by the program name Bash reads from the
// parsed word, and its destination is read before anything else: no spelling
// of the name (plain, backslash, quoted, command or builtin prefix) and no
// source shape (literal, empty, dynamic, from the loop variable) lets a
// protected link through, in any profile. A destination that is an ordinary
// file, and a loop whose word list is empty, stay allowed
// (rel-1-0-6:GAP-0880, GAP-0885). One test per writer program; each spelling
// and each source shape is judged once onto the link and once onto the
// ordinary file, and the rows rotate over the connector, per-user or managed
// gateway and rule pack cells.
func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestinationCp(t *testing.T) {
	loopWriterNameSpellings(t, "cp")
}

func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestinationMv(t *testing.T) {
	loopWriterNameSpellings(t, "mv")
}

func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestinationInstall(t *testing.T) {
	loopWriterNameSpellings(t, "install")
}

func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestinationLn(t *testing.T) {
	loopWriterNameSpellings(t, "ln")
}

func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestinationTee(t *testing.T) {
	loopWriterNameSpellings(t, "tee")
}

// loopWriterNameSpellings judges every spelling and every source shape of one
// writer program in a loop body, each onto the protected link and onto an
// ordinary file, and the empty word list.
func loopWriterNameSpellings(t *testing.T, program string) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	for _, name := range []string{"a.txt", "out2.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spell := func(kind, program string) string {
		switch kind {
		case "backslash":
			return program[:1] + `\` + program[1:]
		case "quoted":
			return program[:1] + `"` + program[1:2] + `"` + program[2:]
		case "command":
			return "command " + program
		case "builtin":
			return "builtin " + program
		}
		return program
	}
	type source struct{ name, prefix, word string }
	literal := source{"literal", "", "a.txt"}
	options := map[string]string{"install": " -m 600", "ln": " -sf"}
	type shape struct {
		spelling string
		source   source
	}
	// Every spelling with the literal source, then every other source with
	// the plain spelling.
	shapes := []shape{{"plain", literal}, {"backslash", literal}, {"quoted", literal}, {"command", literal}, {"builtin", literal},
		{"plain", source{"empty", "", `""`}},
		{"plain", source{"dynamic", "src=$RANDOM; ", `"$src"`}},
		{"plain", source{"loop-variable", "", `"$f.bak"`}}}
	type row struct{ name, command, want string }
	var rows []row
	add := func(s shape, target, loop, want string) {
		var body string
		if program == "tee" {
			body = fmt.Sprintf(`printf %%s %s | %s "$f"`, s.source.word, spell(s.spelling, program))
		} else {
			body = spell(s.spelling, program) + options[program] + " " + s.source.word + ` "$f"`
		}
		rows = append(rows, row{program + "/" + s.spelling + "/" + s.source.name + "/" + target,
			fmt.Sprintf("%sfor f in %s; do %s; done", s.source.prefix, loop, body), want})
	}
	for _, s := range shapes {
		add(s, "link", "keylink", "block")
		add(s, "ordinary", "out2.txt", "allow")
	}
	add(shapes[0], "empty-list", "", "allow")
	type cell struct {
		connector, pack string
		managed         bool
	}
	// An ordinary destination is not judged in strict. The programs start the
	// rotation at different cells, so the five tests together judge every
	// cell.
	var blockCells, allowCells []cell
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				blockCells = append(blockCells, cell{connector, pack, managed})
				if pack != "strict" {
					allowCells = append(allowCells, cell{connector, pack, managed})
				}
			}
		}
	}
	offset := len(shapes) * map[string]int{"cp": 0, "mv": 1, "install": 2, "ln": 3, "tee": 4}[program]
	for index, r := range rows {
		cells := allowCells
		if r.want == "block" {
			cells = blockCells
		}
		c := cells[(offset+index/2)%len(cells)]
		if r.name == "cp/command/literal/ordinary" && c.connector == "codex" && c.managed {
			// The authorized-keys write-target reader (not the loop reader)
			// fails closed on this one prefixed form, as it does without the
			// loop reader; the loop reader allows it (hookpaths
			// TestGAP0431LoopCopyProofGuards). Judge it per-user.
			c.managed = false
		}
		t.Run(fmt.Sprintf("%s/%s/managed=%t/%q", r.name, c.connector, c.managed, c.pack), func(t *testing.T) {
			got := postSelfProtectionPackCell(t, f.home, f.project, c.connector, c.pack, c.managed, c.managed, r.command)
			if want := fmt.Sprintf(`{"action":"%s"`, r.want); !strings.HasPrefix(got, want) {
				t.Errorf("%s: got %.160s, want %s", r.command, got, r.want)
			}
		})
	}
}
