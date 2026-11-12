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

// A for loop whose word list names a protected file (directly or through a
// link) and whose body holds a writer by name is blocked in every profile,
// whatever runs before it or inside it: eval, a directory change, a prefixed
// environment, an unreached branch, a declared function. Nothing is proved
// about whether the body runs or the variable still holds the word. The same
// shapes over an ordinary file stay allowed in the default and permissive
// profiles (rel-1-0-6:GAP-0880, GAP-0885).
func TestLoopWithProtectedWordIsJudgedWhateverRunsAroundIt(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "out2.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shapes := []struct{ name, template string }{
		{"plain", `for f in %s; do cp a.txt "$f"; done`},
		{"eval-in-body", `src=$(printf a.txt); for f in %s; do eval :; cp "$src" "$f"; done`},
		{"eval-before-loop", `eval :; for f in %s; do cp a.txt "$f"; done`},
		{"source-before-loop", `. /dev/null; for f in %s; do cp a.txt "$f"; done`},
		{"cd-in-body", `for f in %s; do cd .; cp a.txt "$f"; done`},
		{"cd-unread-before", `cd "$X"; for f in %s; do cp a.txt "$f"; done`},
		{"home-prefix-in-body", `for f in %s; do HOME="$HOME" cp a.txt "$f"; done`},
		{"unreached-eval-in-body", `src=$(printf a.txt); for f in %s; do if false; then eval :; fi; cp "$src" "$f"; done`},
		{"uncalled-function-before", `g(){ cd /tmp; }; for f in %s; do cp a.txt "$f"; done`},
		{"redirect-write", `for f in %s; do printf x > "$f"; done`},
		{"redirect-append", `for f in %s; do printf x >> "$f"; done`},
	}
	for _, shape := range shapes {
		for _, target := range []struct{ name, word, want string }{
			{"link", "keylink", "block"},
			{"ordinary", "out2.txt", "allow"},
		} {
			command := fmt.Sprintf(shape.template, target.word)
			t.Run(shape.name+"/"+target.name, func(t *testing.T) {
				for _, connector := range []string{"claudecode", "codex"} {
					for _, managed := range []bool{false, true} {
						for _, pack := range []string{"", "permissive", "strict"} {
							if target.want == "allow" && pack == "strict" {
								continue
							}
							got := postSelfProtectionPackCell(t, f.home, f.project, connector, pack, managed, managed, command)
							if want := fmt.Sprintf(`{"action":"%s"`, target.want); !strings.HasPrefix(got, want) {
								t.Errorf("connector=%s managed=%t pack=%q: %s: got %.160s, want %s", connector, managed, pack, command, got, target.want)
							}
						}
					}
				}
			})
		}
	}
}
