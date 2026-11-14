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
	"sort"
	"strconv"
	"strings"
	"testing"
)

const boundedImportPath = "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// TestAdopters walks every non-test Go file of the module and fails on the
// misuses no runtime check can see in time (review round 4 P3-1 step 2,
// P3-2):
//   - a zero Counter in the code: `var x bounded.Counter` or
//     `bounded.Counter{}`;
//   - a bounded.Counter struct field that no code of its package assigns from
//     bounded.NewCounter (a constructor path that forgets it reads unbound);
//   - a package that imports bounded and has no _test.go file calling
//     bounded.PanicOnMisuse(true), so its tests would run on the production
//     fallback instead of panicking where a misuse is made.
func TestAdopters(t *testing.T) {
	root := moduleRoot(t)
	problems := adopterProblems(t, root)
	for _, p := range problems {
		t.Error(p)
	}
}

// The checks find each misuse they name, on a fixture module of their own.
func TestAdoptersCatchesEachMisuse(t *testing.T) {
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
	write("good/good.go", "package good\n"+imp+`
type walker struct {
	trunc bounded.Truncated
	items bounded.Counter
}
func newWalker() *walker { w := &walker{}; w.items = bounded.NewCounter(&w.trunc, bounded.Items, 8); return w }
func local(t *bounded.Truncated) bool { c := bounded.NewCounter(t, bounded.Paths, 2); return c.Take() }
`)
	write("good/good_test.go", "package good\n"+imp+"func init() { bounded.PanicOnMisuse(true) }\n")
	write("bad/bad.go", "package bad\n"+imp+`
type walker struct {
	trunc bounded.Truncated
	items bounded.Counter
}
var global bounded.Counter
func lit() bool { c := bounded.Counter{}; return c.Take() }
`)
	got := strings.Join(adopterProblems(t, root), "\n")
	for _, want := range []string{
		"bad/bad.go:8: a zero Counter (var of type bounded.Counter)",
		"bad/bad.go:9: a zero Counter (bounded.Counter{} literal)",
		"bad: struct field walker.items of type bounded.Counter is never assigned from bounded.NewCounter",
		"bad: imports bounded but no _test.go file calls bounded.PanicOnMisuse(true)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing problem %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "good") {
		t.Errorf("the valid package is reported:\n%s", got)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

type adopterPackage struct {
	imports    bool
	hook       bool
	fields     map[string]string // field name -> "Struct.field"
	assigned   map[string]bool   // field names assigned from bounded.NewCounter
	fieldOrder []string
}

func adopterProblems(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	packages := map[string]*adopterPackage{}
	pkg := func(dir string) *adopterPackage {
		p := packages[dir]
		if p == nil {
			p = &adopterPackage{fields: map[string]string{}, assigned: map[string]bool{}}
			packages[dir] = p
		}
		return p
	}
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		head, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // not this test's concern; the build reports it
		}
		name, ok := boundedImportName(head)
		if !ok {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		dir := filepath.ToSlash(filepath.Dir(rel))
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		p := pkg(dir)
		if strings.HasSuffix(path, "_test.go") {
			if callsPanicOnMisuse(file, name) {
				p.hook = true
			}
			return nil
		}
		p.imports = true
		problems = append(problems, scanAdopterFile(fset, file, name, filepath.ToSlash(rel), p)...)
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
		if !p.imports {
			continue
		}
		for _, field := range p.fieldOrder {
			if !p.assigned[field] {
				problems = append(problems, dir+": struct field "+p.fields[field]+
					" of type bounded.Counter is never assigned from bounded.NewCounter")
			}
		}
		if !p.hook {
			problems = append(problems, dir+": imports bounded but no _test.go file calls bounded.PanicOnMisuse(true)")
		}
	}
	return problems
}

// boundedImportName is the local name of the bounded import, "." for this
// package's own files.
func boundedImportName(file *ast.File) (string, bool) {
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if path != boundedImportPath {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name, true
		}
		return "bounded", true
	}
	return "", false
}

func isBoundedSel(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}

func isNewCounterCall(expr ast.Expr, pkg string) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && isBoundedSel(call.Fun, pkg, "NewCounter")
}

func callsPanicOnMisuse(file *ast.File, pkg string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isBoundedSel(call.Fun, pkg, "PanicOnMisuse") && len(call.Args) == 1 {
			if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "true" {
				found = true
			}
		}
		return !found
	})
	return found
}

func scanAdopterFile(fset *token.FileSet, file *ast.File, pkg, rel string, p *adopterPackage) []string {
	var problems []string
	at := func(n ast.Node) string { return rel + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			if node.Type != nil && isBoundedSel(node.Type, pkg, "Counter") {
				problems = append(problems, at(node)+": a zero Counter (var of type bounded.Counter); use bounded.NewCounter")
			}
		case *ast.CompositeLit:
			if isBoundedSel(node.Type, pkg, "Counter") {
				problems = append(problems, at(node)+": a zero Counter (bounded.Counter{} literal); use bounded.NewCounter")
			}
			for _, elt := range node.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok && isNewCounterCall(kv.Value, pkg) {
					if key, ok := kv.Key.(*ast.Ident); ok {
						p.assigned[key.Name] = true
					}
				}
			}
		case *ast.TypeSpec:
			if st, ok := node.Type.(*ast.StructType); ok {
				for _, field := range st.Fields.List {
					if !isBoundedSel(field.Type, pkg, "Counter") {
						continue
					}
					for _, name := range field.Names {
						if _, seen := p.fields[name.Name]; !seen {
							p.fieldOrder = append(p.fieldOrder, name.Name)
						}
						p.fields[name.Name] = node.Name.Name + "." + name.Name
					}
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) || !isNewCounterCall(rhs, pkg) {
					continue
				}
				if sel, ok := node.Lhs[i].(*ast.SelectorExpr); ok {
					p.assigned[sel.Sel.Name] = true
				}
			}
		}
		return true
	})
	return problems
}
