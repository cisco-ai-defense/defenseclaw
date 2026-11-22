// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bounded

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// readerPackages are the packages whose caps must be registered (DET111 step
// 2): the readers of a command, a path or a body. A subpackage is included.
var readerPackages = []string{
	"internal/hookpaths",
	"internal/actionfacts",
	"internal/effects",
	"internal/effectrules",
	"internal/shellparse",
	"internal/psparse",
	"internal/toolshape",
}

func isReaderDir(dir string) bool {
	for _, p := range readerPackages {
		if dir == p || strings.HasPrefix(dir, p+"/") {
			return true
		}
	}
	return false
}

// capIdent is the name of a cap: maxSomething, max8Dot3, ...
var capIdent = regexp.MustCompile(`^max[A-Z0-9]`)

// The registry check finds an unregistered cap and a misnamed registration,
// and passes a registered one, on a fixture module of its own.
func TestCapRegistryCatchesUnregistered(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	imp := "import \"" + boundedImportPath + "\"\n"
	write("go.mod", "module example.test\n")
	write("internal/hookpaths/walk.go", "package hookpaths\n"+imp+`
const maxSilent = 64
const maxCounted = 8
var maxMisnamed = 4
var _ = bounded.Register("hookpaths.maxCounted", bounded.Items, maxCounted)
var _ = bounded.Register("hookpaths.other", bounded.Items, maxMisnamed)
func walk(names []string) bool {
	n := 0
	for range names {
		n++
		if n > maxSilent || n >= maxCounted || len(names) < maxMisnamed {
			return false
		}
	}
	return true
}
`)
	write("internal/gateway/other.go", "package gateway\nconst maxOutside = 3\nfunc f(n int) bool { return n > maxOutside }\n")
	got := strings.Join(capRegistryProblems(t, root), "\n")
	for _, want := range []string{
		"internal/hookpaths: cap maxSilent (internal/hookpaths/walk.go:13) is compared and not registered",
		`internal/hookpaths/walk.go:8: bounded.Register name "hookpaths.other" does not name hookpaths.maxMisnamed`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing problem %q in:\n%s", want, got)
		}
	}
	for _, bad := range []string{"maxCounted", "maxOutside"} {
		if strings.Contains(got, bad+" (") {
			t.Errorf("%s is reported:\n%s", bad, got)
		}
	}
}

type capPackage struct {
	declared   map[string]bool
	compared   map[string]string // cap -> first file:line
	registered map[string]bool
}

func capRegistryProblems(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	packages := map[string]*capPackage{}
	names := map[string]string{} // registered name -> the file that registers it
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", ".venv", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		if !isReaderDir(dir) {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // the build reports it
		}
		p := packages[dir]
		if p == nil {
			p = &capPackage{declared: map[string]bool{}, compared: map[string]string{}, registered: map[string]bool{}}
			packages[dir] = p
		}
		problems = append(problems, scanCapFile(fset, file, rel, p, names)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dirs := make([]string, 0, len(packages))
	for dir := range packages {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		p := packages[dir]
		caps := make([]string, 0, len(p.compared))
		for name := range p.compared {
			if p.declared[name] && !p.registered[name] {
				caps = append(caps, name)
			}
		}
		sort.Strings(caps)
		for _, name := range caps {
			problems = append(problems, dir+": cap "+name+" ("+p.compared[name]+
				") is compared and not registered (bounded.Register)")
		}
	}
	return problems
}

// capOperand is the cap a comparison operand names: maxX, int(maxX),
// (maxX), maxX-1.
func capOperand(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.CallExpr:
			if len(x.Args) == 1 {
				if _, ok := x.Fun.(*ast.Ident); ok {
					e = x.Args[0]
					continue
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.ADD || x.Op == token.SUB || x.Op == token.MUL || x.Op == token.QUO || x.Op == token.SHL {
				if name := capOperand(x.X); name != "" {
					return name
				}
				e = x.Y
				continue
			}
		case *ast.Ident:
			if capIdent.MatchString(x.Name) {
				return x.Name
			}
		}
		return ""
	}
}

func scanCapFile(fset *token.FileSet, file *ast.File, rel string, p *capPackage, names map[string]string) []string {
	var problems []string
	at := func(n ast.Node) string { return rel + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }
	pkgName := file.Name.Name
	boundedName, imports := boundedImportName(file)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if capIdent.MatchString(name.Name) {
					p.declared[name.Name] = true
				}
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			switch node.Op {
			case token.LSS, token.LEQ, token.GTR, token.GEQ:
				for _, side := range []ast.Expr{node.X, node.Y} {
					if name := capOperand(side); name != "" {
						if _, seen := p.compared[name]; !seen {
							p.compared[name] = at(node)
						}
					}
				}
			}
		case *ast.CallExpr:
			if !imports || !isBoundedSel(node.Fun, boundedName, "Register") || len(node.Args) != 3 {
				return true
			}
			cap := capOperand(node.Args[2])
			if cap == "" {
				problems = append(problems, at(node)+": bounded.Register limit is not a max* cap name")
				return true
			}
			lit, ok := node.Args[0].(*ast.BasicLit)
			name, _ := strconv.Unquote(func() string {
				if ok {
					return lit.Value
				}
				return ""
			}())
			if name != pkgName+"."+cap {
				problems = append(problems, at(node)+": bounded.Register name "+strconv.Quote(name)+
					" does not name "+pkgName+"."+cap)
				return true
			}
			if other, dup := names[name]; dup && other != filepath.Dir(rel) {
				problems = append(problems, at(node)+": cap name "+strconv.Quote(name)+" is registered in "+other+" too")
			}
			names[name] = filepath.Dir(rel)
			p.registered[cap] = true
		}
		return true
	})
	return problems
}
