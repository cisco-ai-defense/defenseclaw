// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deepFolderFixture is the managed fixture in a project folder about 200
// bytes deep, where the client map holds about half of the 255 operands of a
// command: every entry carries two absolute paths.
func deepFolderFixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	base, err := os.MkdirTemp("", "deepfolder")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	deep := filepath.Join(base, strings.Repeat("a", 60), strings.Repeat("b", 60))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", deep)
	f := newB36ManagedHookFixture(t)
	if len(f.project) < 180 {
		t.Fatalf("project folder is %d bytes, want a deep one", len(f.project))
	}
	return f
}

// TestLongOperandListInADeepFolderIsAllowedAndKeepsProtectedTargets is
// GAP-1058: a managed hook call of 255 to 1,000 ordinary operands in a deep
// working folder was blocked, because the client map ran out of bytes and the
// gateway failed closed on every operand the map left out. The client now
// names the plain operands it left out (hookpaths.OmittedPlainKey), so the
// ordinary call is allowed on both connectors, managed and per-user; an
// operand that is a link, a link the command makes, a second name of a keys
// file or a protected name stays refused where it is in the list, in the
// default and in the strict profile, and an ordinary hard link twin is
// allowed.
func TestLongOperandListInADeepFolderIsAllowedAndKeepsProtectedTargets(t *testing.T) {
	sizes := []int{120, 255, 256, 300, 500, 1000}
	if hookAnswerRaceBuild {
		sizes = []int{255, 300}
	}
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			f := deepFolderFixture(t)
			if strict {
				f = f.strict(t)
			}
			ordinary := filepath.Join(f.project, "ordinary")
			if err := os.WriteFile(filepath.Join(ordinary, "plainfile"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			links := []struct {
				name string
				make func(path string) error
			}{
				{"linkdown", func(path string) error { return os.Symlink(f.keys, path) }},
				{"hardkeys", func(path string) error { return os.Link(f.keys, path) }},
				{"hardplain", func(path string) error { return os.Link(filepath.Join(ordinary, "plainfile"), path) }},
			}
			for _, link := range links {
				if err := link.make(filepath.Join(ordinary, link.name)); err != nil {
					t.Fatal(err)
				}
			}
			type row struct{ name, command, want string }
			var rows []row
			for _, n := range sizes {
				plain := gap0151Operands(n, "none", "")
				rows = append(rows,
					row{fmt.Sprintf("n=%d ordinary", n), "cd ordinary && touch " + plain, "allow"},
					row{fmt.Sprintf("n=%d ordinary hard link twin last", n), "cd ordinary && touch " + plain + " hardplain", "allow"},
					row{fmt.Sprintf("n=%d symlink to keys last", n), "cd ordinary && touch " + plain + " linkdown", "block"},
					row{fmt.Sprintf("n=%d hard link to keys last", n), "cd ordinary && touch " + plain + " hardkeys", "block"},
					row{fmt.Sprintf("n=%d link made by the command last", n), "cd ordinary && ln -s " + f.keys + " madelink && touch " + plain + " madelink", "block"},
					row{fmt.Sprintf("n=%d protected name last", n), "cd ordinary && touch " + gap0151Operands(n, "last", f.keys), "block"},
					row{fmt.Sprintf("n=%d protected name first", n), "cd ordinary && touch " + gap0151Operands(n, "first", "~/.ssh/authorized_keys"), "block"},
				)
			}
			payloads := make([][]byte, len(rows))
			for i, r := range rows {
				payloads[i] = f.payload(t, r.command)
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			for i, r := range rows {
				calls = append(calls, everyMode(r.name, payloads[i], headers[i])...)
			}
			f.answerAll(t, calls)
			for i, call := range calls {
				row := rows[i/4]
				if strict && call.managed && row.want == "allow" {
					// The strict profile keeps refusing the operands the map
					// leaves out of a managed hook call (the documented known limit,
					// TestR103B36BoundedHeaderOmittedOperandsStayUnknown).
					row.want = "block"
				}
				if call.verdict != row.want {
					t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, row.want)
				}
			}
		})
	}
}
