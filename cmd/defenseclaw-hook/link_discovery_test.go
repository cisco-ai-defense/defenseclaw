// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The link tests below discover what they check rather than list it
// (GAP-1862): the main packages come from go list, plus the mains that only
// build with a custom tag (benchmarks/cmd/s7bench builds with -tags s7bench),
// and the packages that run connector Setup come from the source.

const linkTestModule = "github.com/defenseclaw/defenseclaw"

// moduleGoFile is one non-test Go file of the module, outside testdata,
// node_modules and vendor folders.
type moduleGoFile struct {
	importPath string
	path       string
	src        []byte
}

func moduleGoFiles(t *testing.T) []moduleGoFile {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var files []moduleGoFile
	err = filepath.WalkDir(root, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if file != root && (name == "testdata" || name == "node_modules" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if file != root {
				if _, err := os.Stat(filepath.Join(file, "go.mod")); err == nil {
					return filepath.SkipDir // another module
				}
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(file))
		if err != nil {
			return err
		}
		files = append(files, moduleGoFile{importPath: path.Join(linkTestModule, filepath.ToSlash(rel)), path: file, src: src})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// standardBuildTags are the build tags go sets itself; any other tag on a
// main package's files is a custom tag the default go list does not see.
func standardBuildTags(t *testing.T, gotool string) map[string]bool {
	t.Helper()
	out, err := exec.Command(gotool, "tool", "dist", "list").Output()
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	tags := map[string]bool{"cgo": true, "race": true, "msan": true, "asan": true, "gc": true, "gccgo": true,
		"unix": true, "purego": true, "boringcrypto": true, "ignore": true}
	for _, platform := range strings.Fields(string(out)) {
		goos, goarch, _ := strings.Cut(platform, "/")
		tags[goos], tags[goarch] = true, true
	}
	return tags
}

// taggedMainPackages returns the main packages that build only with a
// custom tag, and the tags. A file tagged ignore is a go run script, not a
// program.
func taggedMainPackages(t *testing.T, gotool string, files []moduleGoFile) (dirs []string, tags []string) {
	t.Helper()
	standard := standardBuildTags(t, gotool)
	byDir, tagSet := map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, file := range files {
		if !bytes.Contains(file.src, []byte("package main")) || !bytes.Contains(file.src, []byte("//go:build")) {
			continue
		}
		parsed, err := parser.ParseFile(fset, file.path, file.src, parser.PackageClauseOnly|parser.ParseComments)
		if err != nil || parsed.Name.Name != "main" {
			continue
		}
		var expr constraint.Expr
		for _, group := range parsed.Comments {
			if group.Pos() >= parsed.Package {
				break
			}
			for _, comment := range group.List {
				if constraint.IsGoBuild(comment.Text) {
					expr, _ = constraint.Parse(comment.Text)
				}
			}
		}
		if expr == nil {
			continue
		}
		var custom []string
		ignored := false
		constraintTags(expr, func(tag string) {
			ignored = ignored || tag == "ignore"
			if !standard[tag] && !strings.HasPrefix(tag, "go1.") && !strings.HasPrefix(tag, "goexperiment.") {
				custom = append(custom, tag)
			}
		})
		if ignored || len(custom) == 0 {
			continue
		}
		byDir[file.importPath] = true
		for _, tag := range custom {
			tagSet[tag] = true
		}
	}
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(dirs)
	sort.Strings(tags)
	return dirs, tags
}

// constraintTags visits every tag of a build constraint (Eval stops early
// on && and ||).
func constraintTags(expr constraint.Expr, visit func(string)) {
	switch x := expr.(type) {
	case *constraint.TagExpr:
		visit(x.Tag)
	case *constraint.NotExpr:
		constraintTags(x.X, visit)
	case *constraint.AndExpr:
		constraintTags(x.X, visit)
		constraintTags(x.Y, visit)
	case *constraint.OrExpr:
		constraintTags(x.X, visit)
		constraintTags(x.Y, visit)
	}
}

// mainPackage is one program and its dependencies (on one OS).
type mainPackage struct {
	importPath string
	deps       map[string]bool
}

// mainPackages lists every main package of the module on goos: what go list
// ./... sees, plus the custom-tagged mains with their tags.
func mainPackages(t *testing.T, gotool, goos string, files []moduleGoFile) []mainPackage {
	t.Helper()
	tagged, tags := taggedMainPackages(t, gotool, files)
	runs := [][]string{{"./..."}}
	if len(tagged) > 0 {
		runs = append(runs, append([]string{"-tags", strings.Join(tags, ",")}, tagged...))
	}
	seen := map[string]bool{}
	var mains []mainPackage
	for _, args := range runs {
		list := append([]string{"list", "-f", `{{if eq .Name "main"}}{{.ImportPath}} {{join .Deps " "}}{{end}}`}, args...)
		cmd := exec.Command(gotool, list...)
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s go %s: %v", goos, strings.Join(list, " "), err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || seen[fields[0]] {
				continue
			}
			seen[fields[0]] = true
			deps := map[string]bool{}
			for _, dep := range fields[1:] {
				deps[dep] = true
			}
			mains = append(mains, mainPackage{importPath: fields[0], deps: deps})
		}
	}
	for _, dir := range tagged {
		if !seen[dir] {
			t.Errorf("%s: go list did not list the tagged main %s (tags %v)", goos, dir, tags)
		}
	}
	return mains
}

// connectorSetupCallers returns the packages outside internal/gateway/connector
// that call connector Setup: a file that imports the connector package and
// calls a method named Setup with two arguments (Setup(ctx, opts)). A
// package that only builds a SetupOpts for Capabilities (internal/substrate/kit,
// internal/openshell/workspace) does not run Setup. The match may name an
// unrelated Setup too, which only makes the check stricter.
func connectorSetupCallers(t *testing.T, files []moduleGoFile) map[string]bool {
	t.Helper()
	const connectorPkg = linkTestModule + "/internal/gateway/connector"
	callers := map[string]bool{}
	fset := token.NewFileSet()
	for _, file := range files {
		if file.importPath == connectorPkg || !bytes.Contains(file.src, []byte(".Setup(")) ||
			!bytes.Contains(file.src, []byte(strconv.Quote(connectorPkg))) {
			continue
		}
		parsed, err := parser.ParseFile(fset, file.path, file.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file.path, err)
		}
		imports := false
		for _, spec := range parsed.Imports {
			if p, _ := strconv.Unquote(spec.Path.Value); p == connectorPkg {
				imports = true
			}
		}
		if !imports {
			continue
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && len(call.Args) == 2 {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Setup" {
					callers[file.importPath] = true
				}
			}
			return true
		})
	}
	return callers
}
