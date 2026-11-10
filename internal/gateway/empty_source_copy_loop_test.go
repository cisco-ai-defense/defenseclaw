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
// profile, as it does for mv, install, ln and tee and whatever the options
// (a target-directory option names the destination); a loop whose word list is empty never runs its body, so nothing
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
		// No option and no source shape of a writer skips the destination.
		{"cp-recursive", `for f in keylink; do cp -r a.txt "$f"; done`, "block"},
		{"cp-recursive-capital", `for f in keylink; do cp -R a.txt "$f"; done`, "block"},
		{"cp-archive", `for f in keylink; do cp -a a.txt "$f"; done`, "block"},
		{"cp-force", `for f in keylink; do cp -f a.txt "$f"; done`, "block"},
		{"cp-no-clobber", `for f in keylink; do cp -n a.txt "$f"; done`, "block"},
		{"cp-grouped-options", `for f in keylink; do cp -rfp a.txt "$f"; done`, "block"},
		{"cp-no-target-directory", `for f in keylink; do cp -T a.txt "$f"; done`, "block"},
		{"cp-target-directory-short", `for f in keylink; do cp -t "$f" a.txt; done`, "block"},
		{"cp-target-directory-joined", `for f in keylink; do cp -t"$f" a.txt; done`, "block"},
		{"cp-target-directory-grouped", `for f in keylink; do cp -rt "$f" a.txt; done`, "block"},
		{"cp-target-directory-long", `for f in keylink; do cp --target-directory "$f" a.txt; done`, "block"},
		{"cp-target-directory-long-attached", `for f in keylink; do cp --target-directory="$f" a.txt; done`, "block"},
		{"cp-target-directory-abbreviated", `for f in keylink; do cp --target="$f" a.txt; done`, "block"},
		{"cp-target-directory-quoted-option", `for f in keylink; do cp "--target-directory=$f" a.txt; done`, "block"},
		{"cp-recursive-dynamic-source", `for f in keylink; do cp -r "$SRC" "$f"; done`, "block"},
		{"mv-literal-empty-source", `for f in keylink; do mv '' "$f"; done`, "block"},
		{"mv-dynamic-source", `for f in keylink; do mv "$SRC" "$f"; done`, "block"},
		{"mv-unquoted-dynamic-source", `for f in keylink; do mv $SRC "$f"; done`, "block"},
		{"mv-named-source", `for f in keylink; do mv a.txt "$f"; done`, "block"},
		{"mv-force", `for f in keylink; do mv -f a.txt "$f"; done`, "block"},
		{"mv-target-directory", `for f in keylink; do mv -t "$f" a.txt; done`, "block"},
		{"install-dynamic-source", `for f in keylink; do install -m 600 "$SRC" "$f"; done`, "block"},
		{"install-target-directory", `for f in keylink; do install -m 600 -t "$f" a.txt; done`, "block"},
		{"ln-empty-source", `for f in keylink; do ln -sf '' "$f"; done`, "block"},
		{"ln-named-source", `for f in keylink; do ln -sf a.txt "$f"; done`, "block"},
		{"tee-operand", `for f in keylink; do tee "$f"; done`, "block"},
		{"tee-append", `for f in keylink; do tee -a "$f"; done`, "block"},
		{"cp-recursive-ordinary-destination", `for f in out2.txt; do cp -r a.txt "$f"; done`, "allow"},
		{"cp-target-directory-ordinary", `for f in out2.txt; do cp -t "$f" a.txt; done`, "allow"},
		{"cp-target-directory-protected-source", `for f in keylink; do cp -t out2.txt "$f"; done`, "allow"},
		{"mv-ordinary-destination", `for f in out2.txt; do mv '' "$f"; done`, "allow"},
		{"mv-dynamic-source-ordinary-destination", `for f in out2.txt; do mv "$SRC" "$f"; done`, "allow"},
		{"install-ordinary-destination", `for f in out2.txt; do install -m 600 "$SRC" "$f"; done`, "allow"},
		{"ln-ordinary-destination", `for f in out2.txt; do ln -sf a.txt "$f"; done`, "allow"},
		{"tee-ordinary-destination", `for f in out2.txt; do tee "$f"; done`, "allow"},
		{"mv-empty-list", `for f in; do mv '' "$f"; done`, "allow"},
		{"cp-recursive-empty-list", `for f in; do cp -r a.txt "$f"; done`, "allow"},
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
