// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// evalSymlinksAllowed are the files Go builds for Windows that may still use
// filepath.EvalSymlinks, with the number of uses each may have and the
// reason it cannot leave a guard open on Windows.
var evalSymlinksAllowed = map[string]struct {
	uses   int
	reason string
}{
	"internal/winpath/eval_links_windows.go": {1, "EvalLinks itself: the empty path keeps the answer of filepath.EvalSymlinks"},
	"internal/testenv/private_windows.go":    {1, "test helper: the spelling of a private temp folder it just made"},

	// OpenShell sandboxes and the kernel policy run only on Linux:
	// openshell.CheckHost refuses Windows, so this code is built there but
	// never run.
	"internal/config/openshell_tighten.go":      {2, linuxOnly},
	"internal/openshell/discover.go":            {1, linuxOnly},
	"internal/openshell/driver_select.go":       {1, linuxOnly},
	"internal/openshell/gatewaycfg.go":          {2, linuxOnly},
	"internal/openshell/homebrew.go":            {2, linuxOnly},
	"internal/openshell/image/docker.go":        {1, linuxOnly},
	"internal/openshell/manager/create.go":      {1, linuxOnly},
	"internal/openshell/manager/kernelfeed.go":  {1, linuxOnly},
	"internal/openshell/manager/policy.go":      {1, linuxOnly},
	"internal/openshell/microvm.go":             {4, linuxOnly},
	"internal/openshell/packs/allow.go":         {1, linuxOnly},
	"internal/openshell/packs/match.go":         {1, linuxOnly},
	"internal/openshell/procs.go":               {1, linuxOnly},
	"internal/openshell/sandboxcli/app.go":      {2, linuxOnly},
	"internal/openshell/sandboxcli/suggest.go":  {2, linuxOnly},
	"internal/openshell/sandboxcli/wrappers.go": {1, linuxOnly},
	"internal/openshell/sshshim.go":             {1, linuxOnly},
	"internal/openshell/workspace/resume.go":    {1, linuxOnly},
	"internal/openshell/workspace/undo.go":      {1, linuxOnly},
	"internal/openshell/workspace/validate.go":  {3, linuxOnly},
	"internal/openshell/wrapper/wrapper.go":     {1, linuxOnly},
	"internal/sensor/kernelpolicy/fs.go":        {1, linuxOnly},
}

const linuxOnly = "OpenShell and the kernel policy run only on Linux"

// No file Go builds for Windows uses filepath.EvalSymlinks, outside the
// short list above: there it leaves a junction unfollowed, so a path that
// leaves a root through a junction would look as if it were under the root
// (rel-1-0-10:GAP-2182, rel-1-0-10:GAP-2185). Such files use winpath.EvalLinks.
// The sweep covers the whole module, so a wrapper or a seam (a variable set to
// filepath.EvalSymlinks) in any package is seen, and it sees the function
// under every import name a file gives path/filepath, a dot import included.
// It reads the files of the plain Windows build and those built only with
// the cmid tag, the Windows enterprise build. It reads the sources, so it
// runs on every CI runner.
func TestNoEvalSymlinksInWindowsBuiltFiles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	seen := map[string]int{}
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path == root {
				return nil
			}
			if name == "testdata" || name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if ok, err := builtForWindows(filepath.Dir(path), name); err != nil || !ok {
			return err
		}
		files++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(src, []byte("EvalSymlinks")) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		uses := evalSymlinksUses(t, path, src)
		if _, ok := evalSymlinksAllowed[rel]; ok {
			seen[rel] = len(uses)
			return nil
		}
		for _, pos := range uses {
			t.Errorf("%s: filepath.EvalSymlinks in a file built for Windows; use winpath.EvalLinks", pos)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	if files < 1000 {
		t.Fatalf("the sweep read only %d files built for Windows; it is not reading the module", files)
	}
	var allowed []string
	for rel := range evalSymlinksAllowed {
		allowed = append(allowed, rel)
	}
	sort.Strings(allowed)
	for _, rel := range allowed {
		if want := evalSymlinksAllowed[rel].uses; seen[rel] != want {
			t.Errorf("%s uses filepath.EvalSymlinks %d times, and %d are allowed: use winpath.EvalLinks for a new use, and lower the count (or drop the file) when a use goes",
				rel, seen[rel], want)
		}
	}
}

// windowsBuildTags are the build tag sets of the builds that run on Windows:
// the plain one and the enterprise one (-tags cmid).
var windowsBuildTags = [][]string{nil, {"cmid"}}

// builtForWindows reports whether Go builds the file for Windows in any of
// windowsBuildTags.
func builtForWindows(dir, name string) (bool, error) {
	for _, tags := range windowsBuildTags {
		ctx := build.Default
		ctx.GOOS = "windows"
		ctx.GOARCH = "amd64"
		ctx.CgoEnabled = false
		ctx.BuildTags = tags
		ok, err := ctx.MatchFile(dir, name)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// evalSymlinksUses are the places in one file that name
// filepath.EvalSymlinks, under the import name the file gives path/filepath
// or through a dot import.
func evalSymlinksUses(t *testing.T, path string, src []byte) []token.Position {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	locals, dot := map[string]bool{}, false
	for _, spec := range file.Imports {
		if p, _ := strconv.Unquote(spec.Path.Value); p == "path/filepath" {
			switch {
			case spec.Name == nil:
				locals["filepath"] = true
			case spec.Name.Name == ".":
				dot = true
			default:
				locals[spec.Name.Name] = true
			}
		}
	}
	if len(locals) == 0 && !dot {
		return nil
	}
	// Names that only look like a use: the selected name of x.EvalSymlinks,
	// a declared function or method, a field or an interface method.
	notUse := map[*ast.Ident]bool{}
	var uses []token.Position
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			notUse[n.Sel] = true
			if id, ok := n.X.(*ast.Ident); ok && locals[id.Name] && n.Sel.Name == "EvalSymlinks" {
				uses = append(uses, fset.Position(n.Pos()))
			}
		case *ast.FuncDecl:
			notUse[n.Name] = true
		case *ast.Field:
			for _, name := range n.Names {
				notUse[name] = true
			}
		}
		return true
	})
	if dot {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "EvalSymlinks" && !notUse[id] {
				uses = append(uses, fset.Position(id.Pos()))
			}
			return true
		})
	}
	return uses
}

// The sweep sees every spelling of filepath.EvalSymlinks and nothing else.
func TestEvalSymlinksUsesFindsEverySpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"plain call", "package p\nimport \"path/filepath\"\nfunc f() { filepath.EvalSymlinks(\"a\") }\n", 1},
		{"seam", "package p\nimport \"path/filepath\"\nvar eval = filepath.EvalSymlinks\n", 1},
		{"renamed import", "package p\nimport fp \"path/filepath\"\nvar eval = fp.EvalSymlinks\nfunc f() { fp.EvalSymlinks(\"a\") }\n", 2},
		{"two import names", "package p\nimport (\n\t\"path/filepath\"\n\tfp \"path/filepath\"\n)\nvar eval = filepath.EvalSymlinks\nfunc f() { fp.EvalSymlinks(\"a\") }\n", 2},
		{"two import names, last one unused", "package p\nimport (\n\tfp \"path/filepath\"\n\t_ \"path/filepath\"\n)\nfunc f() { fp.EvalSymlinks(\"a\") }\n", 1},
		{"dot import", "package p\nimport . \"path/filepath\"\nvar eval = EvalSymlinks\nfunc f() { EvalSymlinks(\"a\") }\n", 2},
		{"method of that name", "package p\nimport \"path/filepath\"\ntype fsys struct{}\nfunc (fsys) EvalSymlinks(p string) (string, error) { return filepath.Clean(p), nil }\nfunc g(f fsys) { f.EvalSymlinks(\"a\") }\n", 0},
		{"interface method, dot import", "package p\nimport . \"path/filepath\"\ntype FS interface{ EvalSymlinks(string) (string, error) }\nvar _ = Clean\n", 0},
		{"another package", "package p\nimport \"example.com/filepath\"\nvar eval = filepath.EvalSymlinks\n", 0},
		{"no import", "package p\nfunc EvalSymlinks() {}\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(evalSymlinksUses(t, tc.name+".go", []byte(tc.src))); got != tc.want {
				t.Fatalf("uses = %d, want %d", got, tc.want)
			}
		})
	}
}

// The sweep reads a file built only with the cmid tag, and no file that no
// Windows build reads.
func TestBuiltForWindowsReadsTheEnterpriseBuild(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		file, src string
		want      bool
	}{
		{"plain.go", "package p\n", true},
		{"windows_only.go", "//go:build windows\n\npackage p\n", true},
		{"cmid_only.go", "//go:build cmid\n\npackage p\n", true},
		{"windows_cmid.go", "//go:build windows && cmid\n\npackage p\n", true},
		{"no_cmid.go", "//go:build !cmid\n\npackage p\n", true},
		{"linux_cmid.go", "//go:build linux && cmid\n\npackage p\n", false},
		{"linux_only.go", "//go:build linux\n\npackage p\n", false},
		{"never.go", "//go:build ignore\n\npackage p\n", false},
		{"file_linux.go", "package p\n", false},
	}
	for _, tc := range cases {
		if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := builtForWindows(dir, tc.file)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if got != tc.want {
			t.Errorf("builtForWindows(%s) = %v, want %v", tc.file, got, tc.want)
		}
	}
}
