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

package lazyregexp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestLazyRegexpMatchesLikeRegexp(t *testing.T) {
	const expr = `^(?P<name>[a-z]+)-(?P<n>[0-9]{1,3})$`
	lazy, eager := New(expr), regexp.MustCompile(expr)
	for _, in := range []string{"perf-106", "Perf-106", "perf-1066", "a-1", ""} {
		if lazy.MatchString(in) != eager.MatchString(in) {
			t.Fatalf("MatchString(%q) differs", in)
		}
		if got, want := lazy.FindStringSubmatch(in), eager.FindStringSubmatch(in); len(got) != len(want) {
			t.Fatalf("FindStringSubmatch(%q) = %q, want %q", in, got, want)
		}
		if lazy.ReplaceAllString(in, "${n}") != eager.ReplaceAllString(in, "${n}") {
			t.Fatalf("ReplaceAllString(%q) differs", in)
		}
	}
	if lazy.String() != expr || lazy.SubexpIndex("n") != 2 || lazy.NumSubexp() != 2 {
		t.Fatal("pattern metadata differs from regexp")
	}
}

func TestLazyRegexpCompilesOnceUnderConcurrency(t *testing.T) {
	lazy := New(`x+`)
	var wg sync.WaitGroup
	seen := make([]*regexp.Regexp, 32)
	for i := range seen {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen[i] = lazy.Regexp()
		}()
	}
	wg.Wait()
	for _, re := range seen {
		if re != seen[0] {
			t.Fatal("concurrent first uses compiled more than one Regexp")
		}
	}
}

// New does not compile: the first use does, once, and a bad pattern panics
// there as regexp.MustCompile did at start.
func TestNewCompilesOnFirstUse(t *testing.T) {
	lazy := New(`z+`)
	if lazy.rx != nil {
		t.Fatal("New compiled the pattern before its first use")
	}
	if !lazy.MatchString("zz") || lazy.rx == nil {
		t.Fatal("the first use did not compile the pattern")
	}
	bad := New(`([`)
	defer func() {
		if recover() == nil {
			t.Fatal("the first use of an invalid pattern did not panic")
		}
	}()
	bad.MatchString("x")
}

// Every lazyregexp.New pattern in the module's non-test sources compiles.
// Tests no longer compile patterns at New, so this check stands in for the
// start-time panic of regexp.MustCompile. It evaluates each call's argument
// from the source: string literals joined with +, package-level string
// constants and variables (also of another package of the module), and
// regexp.QuoteMeta of those. A pattern built at run time cannot be read
// here; there are only a few, each used by its package's own tests, and the
// count is pinned so a new one is a decision, not an accident.
func TestEveryModulePatternCompiles(t *testing.T) {
	const runtimeBuiltPatterns = 1 // internal/openshell/profiles bedrockProfileRE (strings.Join of template ids)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("module root not found from the test directory: %v", err)
	}
	module := ""
	for _, line := range strings.Split(string(gomod), "\n") {
		if strings.HasPrefix(line, "module ") {
			module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			break
		}
	}
	type pkgFiles struct {
		files  []*ast.File
		values map[string]ast.Expr
	}
	fset := token.NewFileSet()
	pkgs := map[string]*pkgFiles{} // by import path
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		importPath := module
		if rel != "." {
			importPath += "/" + filepath.ToSlash(rel)
		}
		pkg := pkgs[importPath]
		if pkg == nil {
			pkg = &pkgFiles{values: map[string]ast.Expr{}}
			pkgs[importPath] = pkg
		}
		pkg.files = append(pkg.files, file)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				for i, name := range value.Names {
					if i < len(value.Values) {
						pkg.values[name.Name] = value.Values[i]
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	imports := func(file *ast.File) map[string]string {
		names := map[string]string{}
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			name := path[strings.LastIndex(path, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			names[name] = path
		}
		return names
	}
	var eval func(pkg *pkgFiles, imported map[string]string, expr ast.Expr, depth int) (string, bool)
	eval = func(pkg *pkgFiles, imported map[string]string, expr ast.Expr, depth int) (string, bool) {
		if depth > 32 {
			return "", false
		}
		switch e := expr.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		case *ast.ParenExpr:
			return eval(pkg, imported, e.X, depth+1)
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false
			}
			left, ok := eval(pkg, imported, e.X, depth+1)
			if !ok {
				return "", false
			}
			right, ok := eval(pkg, imported, e.Y, depth+1)
			return left + right, ok
		case *ast.Ident:
			if value, ok := pkg.values[e.Name]; ok {
				return eval(pkg, imported, value, depth+1)
			}
		case *ast.SelectorExpr:
			x, ok := e.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			if other := pkgs[imported[x.Name]]; other != nil {
				if value, ok := other.values[e.Sel.Name]; ok {
					// Constants of another package resolve in that package; its
					// own imports are not needed for literal values.
					return eval(other, nil, value, depth+1)
				}
			}
		case *ast.CallExpr:
			fun, ok := e.Fun.(*ast.SelectorExpr)
			if !ok || len(e.Args) != 1 {
				return "", false
			}
			if x, ok := fun.X.(*ast.Ident); ok && imported[x.Name] == "regexp" && fun.Sel.Name == "QuoteMeta" {
				s, ok := eval(pkg, imported, e.Args[0], depth+1)
				return regexp.QuoteMeta(s), ok
			}
		}
		return "", false
	}
	compiled, unread := 0, 0
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			imported := imports(file)
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "New" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || imported[x.Name] != module+"/internal/lazyregexp" {
					return true
				}
				pattern, ok := eval(pkg, imported, call.Args[0], 0)
				if !ok {
					unread++
					t.Logf("%s: built at run time; its package's tests use it", fset.Position(call.Pos()))
					return true
				}
				if _, err := regexp.Compile(pattern); err != nil {
					t.Errorf("%s: %v", fset.Position(call.Pos()), err)
				}
				compiled++
				return true
			})
		}
	}
	if compiled < 400 {
		t.Fatalf("checked only %d lazyregexp.New patterns; the source walk missed most of them", compiled)
	}
	if unread != runtimeBuiltPatterns {
		t.Fatalf("%d lazyregexp.New patterns are built at run time, want %d: make a new one a constant, or update runtimeBuiltPatterns with a test of it", unread, runtimeBuiltPatterns)
	}
}
