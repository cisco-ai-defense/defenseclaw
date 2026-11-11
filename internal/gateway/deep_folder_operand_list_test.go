// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// deepFolderFixture is the managed fixture in a project folder about 200
// bytes deep, where the client map holds about half of the 255 operands of a
// command: every entry carries two absolute paths.
func deepFolderFixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	f := deepFolderFixtureOf(t, 2, 60)
	if len(f.project) < 180 {
		t.Fatalf("project folder is %d bytes, want a deep one", len(f.project))
	}
	return f
}

// deepFolderFixtureOf is the managed fixture below parts folders of width
// bytes each.
func deepFolderFixtureOf(t *testing.T, parts, width int) b36ManagedHookFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && parts*width > 800 {
		t.Skip("macOS limits a path to 1024 bytes")
	}
	base, err := os.MkdirTemp("", "deepfolder")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	deep := base
	for i := 0; i < parts; i++ {
		deep = filepath.Join(deep, strings.Repeat("a", width))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", deep)
	return newB36ManagedHookFixture(t)
}

// TestLongOperandListInADeepFolderIsAllowedAndKeepsProtectedTargets is
// GAP-1058: a managed hook call of 300 ordinary operands in a deep working
// folder was blocked, because the client map ran out of bytes and the gateway
// failed closed on every operand the map left out. The client now names the
// plain operands it left out (hookpaths.OmittedPlainKey), so the ordinary call
// is allowed on both connectors, managed and per-user; a link to the keys
// file and a protected name stay refused where they are in the list, and an
// ordinary hard link twin is allowed. The strict profile keeps refusing the
// managed call, and a protected name there. A race build (the CI gateway
// shards) runs the rows above; the others add a hard link to the keys file,
// a link the command makes and a protected name first.
func TestLongOperandListInADeepFolderIsAllowedAndKeepsProtectedTargets(t *testing.T) {
	const n = 300
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
			plain := gap0151Operands(n, "none", "")
			rows := []row{
				{"ordinary", "cd ordinary && touch " + plain, "allow"},
				{"protected name last", "cd ordinary && touch " + gap0151Operands(n, "last", f.keys), "block"},
			}
			if !strict {
				rows = append(rows,
					row{"ordinary hard link twin last", "cd ordinary && touch " + plain + " hardplain", "allow"},
					row{"symlink to keys last", "cd ordinary && touch " + plain + " linkdown", "block"},
				)
				if !hookAnswerRaceBuild {
					rows = append(rows,
						row{"hard link to keys last", "cd ordinary && touch " + plain + " hardkeys", "block"},
						row{"link made by the command last", "cd ordinary && ln -s " + f.keys + " madelink && touch " + plain + " madelink", "block"},
						row{"protected name first", "cd ordinary && touch " + gap0151Operands(n, "first", "~/.ssh/authorized_keys"), "block"},
					)
				}
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
