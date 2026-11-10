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

// GAP-0431: loop destination proofs judge a move and a copy through the same
// link alike in each hook configuration.
func TestGAP0431LoopDestinationGuardsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("src", "a.txt")
	for _, name := range []string{"a.txt", "out2.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, command, want string
	}{
		{"L5-entry-move", `for f in ordinary; do mv a.txt keylink; done`, "allow"},
		{"L5-copy", `for f in ordinary; do cp a.txt keylink; done`, "block"},
		{"L6-entry-move", `for f in ordinary; do mv "$src" "$f/../keylink"; done`, "block"},
		{"L6-copy", `for f in ordinary; do cp a.txt "$f/../keylink"; done`, "block"},
		{"L6-copy-ordinary", `for f in ordinary; do cp a.txt "$f/../out2.txt"; done`, "allow"},
		{"L6-quoted-copy", `src=a.txt; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{"L6-environment-source", `for f in keylink; do cp "$src" "$f"; done`, "block"},
		{"L6-special-source-index", `OPTIND=; for f in keylink; do cp "$OPTIND" "$f"; done`, "block"},
		{"L6-special-source-seconds", `SECONDS=; for f in keylink; do cp "$SECONDS" "$f"; done`, "block"},
		{"L6-option-after-separator", `src=-n; for f in keylink; do cp -- "$src" "$f"; done`, "block"},
		{"L6-joined-option-separator", `src=-n; for f in keylink; do cp "-"'-' "$src" "$f"; done`, "block"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
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
						t.Errorf("%s = %s, want %s", row.name, got, row.want)
					}
				})
			}
		}
	}
}

// A loop that runs its body judges cp and mv by their names as writers whatever
// their source operands hold, so a destination that reaches a protected file
// through a link blocks in every profile (rel-1-0-6:GAP-0880, GAP-0885).
func TestGAP0431ManagedLoopSourcesAreJudgedAsWriters(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, row := range []struct{ command, want string }{
		{`for f in keylink; do cp "$(printf '')" "$f"; done`, "block"},
		{`src=; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{`src=-n; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{`src=-f; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{`src=--help; for f in keylink; do cp "$src" "$f"; done`, "block"},
		{`REPLY=; for f in keylink; do cp "$REPLY" "$f"; done`, "block"},
		{`OPTARG=; for f in keylink; do cp "$OPTARG" "$f"; done`, "block"},
		{`BASH_ENV=; for f in keylink; do cp "$BASH_ENV" "$f"; done`, "block"},
		{`IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{`src=a.txt; for f in keylink; do mv a.txt "$f"; done`, "block"},
		{`for f in keylink; do mv "$src" "$f"; done`, "block"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != row.want {
				t.Errorf("%s: %s = %s, want %s", connector, row.command, got, row.want)
			}
		}
	}
}

func TestGAP0431StartupSourceKeepsLinkedDestination(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "0"), []byte("zero\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(f.project, "startup.sh")
	if err := os.WriteFile(startup, []byte("printf() { builtin printf a.txt; }\ndeclare -i src=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", startup)
	for _, command := range []string{
		`for f in keylink; do cp "$(printf '')" "$f"; done`,
		`src=; for f in keylink; do cp "$src" "$f"; done`,
		`src=; for f in keylink; do cp "${src-a.txt}" "$f"; done`,
	} {
		payload := f.payload(t, command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != "block" {
				t.Errorf("%s: %s: %s, want block", connector, command, got)
			}
		}
	}
}
