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

// The verdict on a copy in a loop does not depend on what the source operand
// holds or on which program the name cp reaches: a loop that runs its body
// (any non-empty or unknown word list) judges cp by its name as a writer, and
// a destination that reaches a protected file through a link blocks in every
// profile; a loop whose word list is empty never runs its body, so nothing
// it names is written (rel-1-0-6:GAP-0880, GAP-0885).
func TestCopyInLoopIsJudgedByNameNotBySourceOrProgramFile(t *testing.T) {
	system, err := os.ReadFile("/bin/cp")
	if err != nil {
		t.Skip("the rows need a system cp to copy")
	}
	f := newB36ManagedHookFixture(t)
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	for _, name := range []string{"a.txt", "out2.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fakeDir, copyDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeDir, "cp"), []byte("#!/bin/sh\nprintf altered > \"$2\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, "cp"), system, 0o700); err != nil {
		t.Fatal(err)
	}
	ambient := os.Getenv("PATH")
	paths := map[string]string{
		"system-cp":          ambient,
		"program-writable":   fakeDir + string(os.PathListSeparator) + ambient,
		"copy-of-system-cp":  copyDir + string(os.PathListSeparator) + ambient,
		"project-first-path": f.project + string(os.PathListSeparator) + ambient,
	}
	rows := []struct{ name, command, want string }{
		{"ifs-source", `IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{"assigned-source", `src=; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{"reply-source", `REPLY=; for f in keylink; do cp "$REPLY" "$f"; done`, "block"},
		{"option-source", `src=-n; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{"named-source", `for f in keylink; do cp a.txt "$f"; done`, "block"},
		{"literal-empty-source", `for f in keylink; do cp '' "$f"; done`, "block"},
		{"literal-empty-double-quoted-source", `for f in keylink; do cp "" "$f"; done`, "block"},
		{"command-substituted-source", `for f in keylink; do cp "$(true)" "$f"; done`, "block"},
		{"literal-option-source", `for f in keylink; do cp -n "$f"; done`, "block"},
		{"missing-source", `for f in keylink; do cp "$f"; done`, "block"},
		{"option-source-after-separator", `for f in keylink; do cp -- -n "$f"; done`, "block"},
		{"glob-source", `for f in keylink; do cp *.nomatch "$f"; done`, "block"},
		{"unquoted-dynamic-source", `for f in keylink; do cp $SRC "$f"; done`, "block"},
		{"literal-empty-source-ordinary-destination", `for f in out2.txt; do cp '' "$f"; done`, "allow"},
		{"literal-empty-source-empty-list", `for f in; do cp '' "$f"; done`, "allow"},
		{"unknown-list", `for f in $UNKNOWN_LIST keylink; do cp "$IFS" "$f"; done`, "block"},
		{"empty-list", `IFS=; for f in; do cp "$IFS" "$f"; done`, "allow"},
		{"empty-variable-list", `E=; for f in $E; do cp a.txt "$f"; done`, "allow"},
		{"ordinary-destination", `IFS=; for f in out2.txt; do cp "$IFS" "$f"; done`, "allow"},
		{"ordinary-copy", `for f in out2.txt; do cp a.txt "$f"; done`, "allow"},
	}
	for pathName, path := range paths {
		for _, row := range rows {
			payload := f.payload(t, row.command)
			header := f.clientHeader(t, payload)
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/managed=%t/%s", pathName, connector, managed, row.name), func(t *testing.T) {
						t.Setenv("PATH", path)
						var got string
						if managed {
							got = f.post(t, connector, payload, header)
						} else {
							if err := os.Chmod(f.homes, 0o700); err != nil {
								t.Fatal(err)
							}
							body := postDynamicWordParity(t, f.home, f.project, connector, false, row.command, nil)
							switch {
							case strings.HasPrefix(body, `{"action":"block"`):
								got = "block"
							case strings.HasPrefix(body, `{"action":"allow"`):
								got = "allow"
							default:
								got = body
							}
						}
						if got != row.want {
							t.Errorf("%s = %s, want %s", row.command, got, row.want)
						}
					})
				}
			}
		}
	}
}
