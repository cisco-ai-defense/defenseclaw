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

// deepFolderMinProject is the depth the GAP-1058 regression needs: a project
// folder at least this many bytes deep, so the client map holds about half of
// the 255 operands of a command.
const deepFolderMinProject = 180

// deepFolderFixture is the managed fixture in a project folder at least
// deepFolderMinProject bytes deep on any temp root. The padding is computed
// from the length of the temp folder it was made in, not fixed: a fixed pad
// left the project at 161 plus the digits of the two random folder suffixes,
// so a short root such as /tmp passed only when both had 10 digits
// (rel-1-0-10:GAP-0439).
func deepFolderFixture(t *testing.T) b36ManagedHookFixture {
	t.Helper()
	if runtime.GOOS == "darwin" {
		// macOS limits a path to 1024 bytes and its temp root is long already.
		return deepFolderFixtureOf(t, 2, 60)
	}
	base := deepFolderBase(t)
	// project = base/<pad>/b36<digits>/homes/alice/project, digits >= 1.
	rest := len(filepath.Join("b36", "homes", "alice", "project")) + 1
	pad := deepFolderMinProject - len(base) - 1 - 1 - rest
	if pad < 1 {
		pad = 1
	}
	const nameMax = 200
	deep := base
	for pad > 0 {
		w := pad
		if w > nameMax {
			w = nameMax
		}
		deep = filepath.Join(deep, strings.Repeat("a", w))
		pad -= w
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newB36ManagedHookFixtureIn(t, deep)
	if len(f.project) < deepFolderMinProject {
		t.Fatalf("project folder is %d bytes, want at least %d", len(f.project), deepFolderMinProject)
	}
	return f
}

// deepFolderBase is a fresh folder in the temp root, removed with the test.
func deepFolderBase(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "deepfolder")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// The fixture reaches its depth on a short temp root whatever digits the two
// random folder names get: it is made 150 times under /tmp. Before the pad was
// computed from the root, some of these had a project folder of 179
// bytes or fewer.
func TestDeepFolderFixtureReachesItsDepthOnAShortTempRoot(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("short POSIX temp root")
	}
	if fi, err := os.Stat("/tmp"); err != nil || !fi.IsDir() {
		t.Skip("no /tmp")
	}
	t.Setenv("TMPDIR", "/tmp")
	for i := 0; i < 150; i++ {
		t.Run(fmt.Sprintf("make=%d", i), func(t *testing.T) {
			f := deepFolderFixture(t)
			if len(f.project) < deepFolderMinProject {
				t.Fatalf("project folder is %d bytes, want at least %d", len(f.project), deepFolderMinProject)
			}
		})
	}
}

// deepFolderFixtureOf is the managed fixture below parts folders of width
// bytes each. It names that folder as the fixture's parent: setting TMPDIR
// moved t.TempDir() there only while GOTMPDIR was unset, so on a gate box
// that sets GOTMPDIR the project stayed about 125 bytes deep and both deep
// folder tests failed their own guards (rel-1-0-10:GAP-0439, GAP-0423).
func deepFolderFixtureOf(t *testing.T, parts, width int) b36ManagedHookFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && parts*width > 800 {
		t.Skip("macOS limits a path to 1024 bytes")
	}
	base := deepFolderBase(t)
	deep := base
	for i := 0; i < parts; i++ {
		deep = filepath.Join(deep, strings.Repeat("a", width))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	return newB36ManagedHookFixtureIn(t, deep)
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
