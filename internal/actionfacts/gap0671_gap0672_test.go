// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// g0671Folder is a work folder with the given files.
func g0671Folder(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// g0671Named is the credentials files the private record names.
func g0671Named(facts Facts) []string {
	var named []string
	for _, read := range facts.CredentialPathReads() {
		if read.Value != "" {
			named = append(named, read.Value)
		}
	}
	return named
}

func g0671Unknown(facts Facts) bool {
	return slices.ContainsFunc(facts.CredentialPathReads(), func(p PathFact) bool { return p.Value == "" })
}

// TestGAP0671RgTypeAddReadsHidden is substrate-1:GAP-0671: an rg file type
// selected with -t or --type whitelists its --type-add globs past ripgrep's
// hidden-file rule, as a -g include does (real rg 14.1 prints .env for
// rg -l --type-add 'e:*.env' -te KEY). The value of --type-add is not the
// pattern, so the form with no folder searches the working folder. -T
// (--type-not) and a type that is defined but not selected read nothing
// hidden. Rel and the parent count every row marked read.
func TestGAP0671RgTypeAddReadsHidden(t *testing.T) {
	files := []string{".env", ".npmrc", ".aws/credentials", "src/a.go"}
	for _, row := range []struct {
		cmd  string
		read bool
	}{
		{"rg --type-add 'e:*.env' -te KEY .", true},
		{"rg --type-add 'e:*.env' -te KEY", true},
		{"rg --type-add=e:.env --type e KEY .", true},
		{"rg --type-add 'e:.npmrc' -t e KEY", true},
		{"rg --type-add 'e:*.{go,env}' --type=e KEY", true},
		// One glob per --type-add: "*.go,*.env" is one glob that names
		// no file (real rg 14.1.0 reads nothing, g0683Rows).
		{"rg --type-add 'e:*.go,*.env' --type=e KEY", false},
		{"rg --type-add 'f:*.env' --type-add 'e:include:f' -te KEY", true},
		{"rg -l --type-add 'e:*.env' -tgo -te KEY src .", true},
		{"rg --type-add 'g:*.go' -tg KEY", false},
		{"rg --type-add 'e:*.env' -Te KEY", false},
		{"rg --type-add 'e:*.env' --type-not e KEY .", false},
		{"rg --type-add 'e:*.env' KEY", false},
		{"rg --type-add 'e:*.env' --type-clear e -te KEY", false},
	} {
		t.Run(row.cmd, func(t *testing.T) {
			dir := g0671Folder(t, files...)
			facts := Analyze(Input{Tool: "exec", Command: row.cmd, CWD: dir, ActiveHome: t.TempDir()})
			named := g0671Named(facts)
			if got := len(named) != 0; got != row.read {
				t.Fatalf("%q: credentials read = %v, want %v (status %s, named %v)", row.cmd, got, row.read, facts.Parse.Status, named)
			}
			if row.read && !slices.ContainsFunc(named, func(v string) bool { return filepath.Base(v) == ".env" || filepath.Base(v) == ".npmrc" }) {
				t.Fatalf("%q: the hidden file is not named (named %v)", row.cmd, named)
			}
			if caps := facts.CredentialPathReadCaps(); caps.Any() {
				t.Fatalf("%q: TRUNCATED %v in a small folder", row.cmd, caps)
			}
		})
	}
	// The value of --type-add is no folder operand: --type-add's value is
	// skipped, so KEY is the pattern and . the folder.
	argv := []string{"rg", "--type-add", "e:*.env", "-te", "KEY", "."}
	if got := searchOperandIndexes(argv, "rg"); !slices.Equal(got, []int{4, 5}) {
		t.Fatalf("operands of %v: %v, want [4 5]", argv, got)
	}
}

// g0672Tree is a work folder holding one tree, t, and n symbolic links to
// it (h1 ... hn): every name is a distinct folder to the walk, as in the
// RV2 repro. The tree has .env at its top, and either subs folders of 9
// files or one flat folder of files.
func g0672Tree(t *testing.T, n, subs, flat int) (string, []string) {
	t.Helper()
	files := []string{"t/.env"}
	for i := range subs {
		for j := range 9 {
			files = append(files, "t/d"+strconv.Itoa(i)+"/f"+strconv.Itoa(j)+".go")
		}
	}
	for i := range flat {
		files = append(files, "t/f"+strconv.Itoa(i)+".go")
	}
	dir := g0671Folder(t, files...)
	names := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		name := "h" + strconv.Itoa(i)
		if err := os.Symlink(filepath.Join(dir, "t"), filepath.Join(dir, name)); err != nil {
			// A standard Windows user may not hold the symbolic-link
			// privilege; TestGAP0674NoWalkKeptPastItsCall skips the same way.
			t.Skipf("no symbolic links here: %v", err)
		}
		names = append(names, name)
	}
	return dir, names
}

// TestGAP0672OneWalkBudgetPerCall is substrate-1:GAP-0672: the walks of
// one call share one walk budget (4,096 folders, 65,536 entries), however
// many folders the call names. 200 names of one tree read at most one
// budget's worth of the tree: the walks past it are cut, and a cut marks
// only the chain's unknown tier (no TRUNCATED, so no verdict change, the
// round-1 P2-1 ruling). At a6f8f54ead each name had its own budget (200
// whole walks). Each named folder's own probe is not a walk: every name's
// .env is read, as on both rels (substrate-1:GAP-0911). A later check of the call walks the tree as it
// is then (rel-1-0-10:GAP-1045): with the tree's .env removed it names
// none, within the same one budget.
func TestGAP0672OneWalkBudgetPerCall(t *testing.T) {
	for _, shape := range []struct {
		name        string
		subs, flat  int
		description string
	}{
		{"folders", 40, 0, "41 folders of 401 entries"},
		{"entries", 0, 1000, "1 folder of 1,001 entries"},
	} {
		t.Run(shape.name, func(t *testing.T) {
			const n = 200
			dir, names := g0672Tree(t, n, shape.subs, shape.flat)
			in := Input{Tool: "exec", Command: "grep -r KEY " + strings.Join(names, " "), CWD: dir, ActiveHome: t.TempDir()}
			first := Analyze(in)
			if caps := first.CredentialPathReadCaps(); caps.Any() {
				t.Fatalf("a spent walk budget is a cap of the resolve: %v", caps)
			}
			named := g0671Named(first)
			// Each name's own .env is read exactly: the one-level probe of
			// a named folder is outside the shared walk budget, as rel
			// probes it (substrate-1:GAP-0911); only the walks below it
			// share the one budget, and the walks it cuts add the unknown
			// read.
			if len(named) != n {
				t.Fatalf("%d names of a tree of %s: %d files named, want %d (each named folder's own probe)",
					n, shape.description, len(named), n)
			}
			if !g0671Unknown(first) {
				t.Fatalf("%d names past the shared budget: no file-unknown read (the chain's unknown tier)", n)
			}
			if err := os.Remove(filepath.Join(dir, "t", ".env")); err != nil {
				t.Fatal(err)
			}
			again := Analyze(in)
			if named := g0671Named(again); len(named) != 0 {
				t.Fatalf("the .env is gone, a later check still names %v", named)
			}
			if !g0671Unknown(again) {
				t.Fatalf("a later check of %d names: no file-unknown read past the shared budget", n)
			}
		})
	}
}
