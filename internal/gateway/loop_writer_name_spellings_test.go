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
// (rel-1-0-6:GAP-0880, GAP-0885).
func TestLoopWriterNameSpellingsAndSourceShapesAreJudgedByDestination(t *testing.T) {
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
	sources := []struct{ name, prefix, word string }{
		{"literal", "", "a.txt"},
		{"empty", "", `""`},
		{"dynamic", "src=$RANDOM; ", `"$src"`},
		{"loop-variable", "", `"$f.bak"`},
	}
	options := map[string]string{"install": " -m 600", "ln": " -sf"}
	type row struct{ name, command, want string }
	var rows []row
	for _, program := range []string{"cp", "mv", "install", "ln", "tee"} {
		for _, spelling := range []string{"plain", "backslash", "quoted", "command", "builtin"} {
			for _, source := range sources {
				name := program + "/" + spelling + "/" + source.name
				for _, target := range []struct{ name, loop, want string }{
					{"link", "keylink", "block"},
					{"ordinary", "out2.txt", "allow"},
					{"empty-list", "", "allow"},
				} {
					var body string
					if program == "tee" {
						body = fmt.Sprintf(`printf %%s %s | %s "$f"`, source.word, spell(spelling, program))
					} else {
						body = spell(spelling, program) + options[program] + " " + source.word + ` "$f"`
					}
					command := fmt.Sprintf("%sfor f in %s; do %s; done", source.prefix, target.loop, body)
					rows = append(rows, row{name + "/" + target.name, command, target.want})
				}
			}
		}
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					if r.name == "cp/command/literal/ordinary" && connector == "codex" && managed {
						// The authorized-keys write-target reader (not the loop
						// reader) fails closed on this one prefixed form, as it
						// does without the loop reader; the loop reader allows it
						// (hookpaths TestGAP0431LoopCopyProofGuards).
						continue
					}
					for _, pack := range []string{"", "permissive", "strict"} {
						if r.want == "allow" && pack == "strict" {
							continue
						}
						got := postSelfProtectionPackCell(t, f.home, f.project, connector, pack, managed, managed, r.command)
						if want := fmt.Sprintf(`{"action":"%s"`, r.want); !strings.HasPrefix(got, want) {
							t.Errorf("connector=%s managed=%t pack=%q: %s: got %.160s, want %s", connector, managed, pack, r.command, got, r.want)
						}
					}
				}
			}
		})
	}
}
