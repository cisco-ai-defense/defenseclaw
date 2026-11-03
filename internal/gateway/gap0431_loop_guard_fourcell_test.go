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

// GAP-0431: loop destination proofs keep entry-replacing moves ordinary and
// retain copy writes through the same link in each hook configuration.
func TestGAP0431LoopDestinationGuardsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
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
		{"L6-entry-move", `for f in ordinary; do mv "$src" "$f/../keylink"; done`, "allow"},
		{"L6-copy", `for f in ordinary; do cp a.txt "$f/../keylink"; done`, "block"},
		{"L6-copy-ordinary", `for f in ordinary; do cp a.txt "$f/../out2.txt"; done`, "allow"},
		{"L6-quoted-copy", `for f in keylink; do cp "$src" "$f"; done`, "block"},
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
