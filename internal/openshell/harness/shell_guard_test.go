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

package harness

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// The POSIX shells a test may start come from the accessors below and from
// nowhere else. A Windows host has no /bin/sh: a test that starts one
// without a way to skip fails to start the process, and the cases that read
// the failure as a refusal go red. This file is the only place in the package
// that spells a shell path, so a test cannot start a shell without going
// through a check that skips (binSh, binBash) or reports the absence
// (maybeBinSh, maybeBinBash).

// shellIfPresent returns the shell at the path, or "" when the host has none.
func shellIfPresent(shell string) string {
	if fi, err := os.Stat(shell); err != nil || fi.IsDir() {
		return ""
	}
	return shell
}

// maybeBinSh and maybeBinBash return the host shell, or "" for a test that
// runs a lighter check without one.
func maybeBinSh() string   { return shellIfPresent("/bin/sh") }
func maybeBinBash() string { return shellIfPresent("/bin/bash") }

// needShell skips the test when the shell is empty (absent) and returns it.
func needShell(t testing.TB, shell string) string {
	t.Helper()
	if shell == "" {
		t.Skip("a POSIX shell is required")
	}
	return shell
}

// binSh and binBash skip the test when the host has no such shell. They are
// for the tests that run an image-build shell fragment; the fragments run in
// the Linux sandbox image, never on the host.
func binSh(t testing.TB) string   { t.Helper(); return needShell(t, maybeBinSh()) }
func binBash(t testing.TB) string { t.Helper(); return needShell(t, maybeBinBash()) }

func TestShellAccessorsSkipWhenTheShellIsMissing(t *testing.T) {
	if got := shellIfPresent(filepath.Join(t.TempDir(), "no-such-shell")); got != "" {
		t.Errorf("a missing shell came back as %q", got)
	}
	if got := shellIfPresent(t.TempDir()); got != "" {
		t.Errorf("a directory came back as the shell %q", got)
	}
	here := filepath.Join(t.TempDir(), "sh")
	if err := os.WriteFile(here, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := shellIfPresent(here); got != here {
		t.Errorf("a present shell came back as %q, want %q", got, here)
	}
	if got := needShell(t, here); got != here {
		t.Errorf("needShell returned %q, want %q", got, here)
	}
	skipped := false
	t.Run("without a shell", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		needShell(t, "")
		t.Error("the test ran on after needShell on an empty shell")
	})
	if !skipped {
		t.Error("a missing shell did not skip the test")
	}
}

// shellPaths are the shell programs by absolute path; shellNames are the
// bare names that a PATH lookup resolves to one.
var shellPaths = map[string]bool{}
var shellNames = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true}

func init() {
	for name := range shellNames {
		shellPaths["/bin/"+name] = true
		shellPaths["/usr/bin/"+name] = true
	}
}

// maxShellValues bounds the values tracked for one expression.
const maxShellValues = 64

// binding is an expression a name holds somewhere, with the function whose
// scope it is evaluated in ("" for the package).
type binding struct {
	expr ast.Expr
	fn   string
}

// valueIndex collects every expression each name can hold in the files: the
// constants and variables of the package, the declarations, assignments and
// range variables of each function, the arguments a package function is
// called with (for its parameters) and the values given to a struct field.
// It is flow-insensitive on purpose: a name holds a shell if any of its
// values is one, wherever it is set and in whatever order.
type valueIndex struct {
	names  map[string][]binding // fn + NUL + name
	fields map[string][]binding // field name
	params map[string][]string  // function name to its parameter names
	types  map[string]ast.Expr  // package type name to its declaration
}

func nameKey(fn, name string) string { return fn + "\x00" + name }

// bindName records e, evaluated in the scope from, as a value of the name
// in the scope fn.
func (v *valueIndex) bindName(fn, name string, e ast.Expr, from string) {
	if name != "_" {
		k := nameKey(fn, name)
		v.names[k] = append(v.names[k], binding{e, from})
	}
}

// bindTarget records e as a value of the assigned expression: a name, or a
// field of a value.
func (v *valueIndex) bindTarget(fn string, lhs, e ast.Expr) {
	switch l := lhs.(type) {
	case *ast.Ident:
		v.bindName(fn, l.Name, e, fn)
	case *ast.SelectorExpr:
		v.fields[l.Sel.Name] = append(v.fields[l.Sel.Name], binding{e, fn})
	}
}

func (v *valueIndex) bindSpec(fn string, spec ast.Spec) {
	if s, ok := spec.(*ast.ValueSpec); ok && len(s.Names) == len(s.Values) {
		for i := range s.Names {
			v.bindName(fn, s.Names[i].Name, s.Values[i], fn)
		}
	}
}

// callee names the package function or method a call may reach.
func callee(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func newValueIndex(files []*ast.File) *valueIndex {
	v := &valueIndex{names: map[string][]binding{}, fields: map[string][]binding{}, params: map[string][]string{}, types: map[string]ast.Expr{}}
	for _, file := range files {
		for _, d := range file.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				for _, spec := range gd.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						v.types[ts.Name.Name] = ts.Type
					}
				}
			}
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Type.Params != nil {
				for _, f := range fd.Type.Params.List {
					for _, n := range f.Names {
						v.params[fd.Name.Name] = append(v.params[fd.Name.Name], n.Name)
					}
				}
			}
		}
	}
	for _, file := range files {
		for _, d := range file.Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.GenDecl:
					for _, spec := range n.Specs {
						v.bindSpec(fn, spec)
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i := range n.Lhs {
							v.bindTarget(fn, n.Lhs[i], n.Rhs[i])
						}
					}
				case *ast.RangeStmt:
					if val, ok := n.Value.(*ast.Ident); ok {
						v.bindName(fn, val.Name, &ast.IndexExpr{X: n.X}, fn)
					}
				case *ast.CompositeLit:
					if n.Type != nil {
						v.bindLit(fn, n, n.Type, 0)
					}
				case *ast.KeyValueExpr:
					if k, ok := n.Key.(*ast.Ident); ok {
						v.fields[k.Name] = append(v.fields[k.Name], binding{n.Value, fn})
					}
				case *ast.CallExpr:
					if params, ok := v.params[callee(n)]; ok {
						for i, arg := range n.Args {
							if i < len(params) {
								v.bindName(callee(n), params[i], arg, fn)
							}
						}
					}
				}
				return true
			})
		}
	}
	return v
}

// bindLit records the elements of a composite literal as values of the
// fields they fill by position: a struct literal, a list of them or a map of
// them, with the inner type left out or spelled.
func (v *valueIndex) bindLit(fn string, lit *ast.CompositeLit, typ ast.Expr, depth int) {
	if depth > 8 {
		return
	}
	switch t := typ.(type) {
	case *ast.StarExpr:
		v.bindLit(fn, lit, t.X, depth+1)
	case *ast.Ident:
		if decl, ok := v.types[t.Name]; ok {
			v.bindLit(fn, lit, decl, depth+1)
		}
	case *ast.ArrayType:
		v.bindElts(fn, lit, t.Elt, depth)
	case *ast.MapType:
		v.bindElts(fn, lit, t.Value, depth)
	case *ast.StructType:
		var fields []string
		for _, f := range t.Fields.List {
			for _, n := range f.Names {
				fields = append(fields, n.Name)
			}
		}
		for i, el := range lit.Elts {
			if _, keyed := el.(*ast.KeyValueExpr); !keyed && i < len(fields) {
				v.fields[fields[i]] = append(v.fields[fields[i]], binding{el, fn})
			}
		}
	}
}

func (v *valueIndex) bindElts(fn string, lit *ast.CompositeLit, elem ast.Expr, depth int) {
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			el = kv.Value
		}
		if inner, ok := el.(*ast.CompositeLit); ok && inner.Type == nil {
			v.bindLit(fn, inner, elem, depth+1)
		}
	}
}

// lookup returns every binding of the name visible in the function.
func (v *valueIndex) lookup(fn, name string) []binding {
	out := v.names[nameKey(fn, name)]
	if fn != "" {
		out = append(out[:len(out):len(out)], v.names[nameKey("", name)]...)
	}
	return out
}

// combine folds the possible values of each part into the possible values of
// the whole, or nothing when a part has none.
func combine(parts [][]string, f func([]string) string) []string {
	for _, p := range parts {
		if len(p) == 0 {
			return nil
		}
	}
	var out []string
	pick := make([]string, len(parts))
	var rec func(i int)
	rec = func(i int) {
		if len(out) >= maxShellValues {
			return
		}
		if i == len(parts) {
			out = append(out, f(pick))
			return
		}
		for _, s := range parts[i] {
			pick[i] = s
			rec(i + 1)
		}
	}
	rec(0)
	return out
}

// strs returns the strings the expression can hold: a string literal, a
// name, a field, an element of a list, a sum of these or a path.Join /
// filepath.Join of them. It returns nothing for a value it cannot fold,
// such as the result of an accessor.
func (v *valueIndex) strs(e ast.Expr, fn string, seen map[string]bool) []string {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if s, err := strconv.Unquote(e.Value); err == nil {
				return []string{s}
			}
		}
	case *ast.ParenExpr:
		return v.strs(e.X, fn, seen)
	case *ast.Ident:
		return v.ofBindings(v.lookup(fn, e.Name), nameKey(fn, e.Name), seen, v.strs)
	case *ast.SelectorExpr:
		return v.ofBindings(v.fields[e.Sel.Name], "field\x00"+e.Sel.Name, seen, v.strs)
	case *ast.IndexExpr:
		var out []string
		for _, el := range v.elems(e.X, fn, seen) {
			out = append(out, v.strs(el.expr, el.fn, seen)...)
		}
		return out
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return combine([][]string{v.strs(e.X, fn, seen), v.strs(e.Y, fn, seen)},
				func(p []string) string { return p[0] + p[1] })
		}
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || sel.Sel.Name != "Join" || (pkg.Name != "path" && pkg.Name != "filepath") {
			return nil
		}
		parts := make([][]string, len(e.Args))
		for i, arg := range e.Args {
			parts[i] = v.strs(arg, fn, seen)
		}
		return combine(parts, func(p []string) string { return path.Join(p...) })
	}
	return nil
}

// ofBindings unions what a visible name or field can hold, once per chain so
// that a name set from itself ends.
func (v *valueIndex) ofBindings(bs []binding, key string, seen map[string]bool, f func(ast.Expr, string, map[string]bool) []string) []string {
	if len(bs) == 0 || seen[key] {
		return nil
	}
	seen[key] = true
	defer delete(seen, key)
	var out []string
	for _, b := range bs {
		out = append(out, f(b.expr, b.fn, seen)...)
	}
	return out
}

// elems returns the expressions a list expression can hold as elements.
func (v *valueIndex) elems(e ast.Expr, fn string, seen map[string]bool) []binding {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return v.elems(e.X, fn, seen)
	case *ast.SliceExpr:
		return v.elems(e.X, fn, seen)
	case *ast.CompositeLit:
		var out []binding
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			out = append(out, binding{el, fn})
		}
		return out
	case *ast.Ident:
		bs := v.lookup(fn, e.Name)
		key := "elems\x00" + nameKey(fn, e.Name)
		if len(bs) == 0 || seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		var out []binding
		for _, b := range bs {
			out = append(out, v.elems(b.expr, b.fn, seen)...)
		}
		return out
	}
	return nil
}

func anyShellPath(ss []string) (string, bool) {
	for _, s := range ss {
		if shellPaths[s] {
			return s, true
		}
	}
	return "", false
}

func anyShellName(ss []string) (string, bool) {
	for _, s := range ss {
		if shellNames[s] {
			return s, true
		}
	}
	return "", false
}

// shellNamings reports every place the files name a POSIX shell outside the
// accessors: any expression that can be a shell path (a literal, a constant,
// a variable, a parameter, a field or an element that holds one, a sum or a
// join of them, wherever it flows), and a bare shell name that can reach
// exec.Command, exec.CommandContext or exec.LookPath as the program, held
// directly or through any of those.
func shellNamings(files map[string]string) ([]string, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, file)
	}
	index := newValueIndex(parsed)
	var found []string
	report := func(n ast.Node, what string) {
		p := fset.Position(n.Pos())
		found = append(found, p.Filename+":"+strconv.Itoa(p.Line)+": "+what)
	}
	for _, file := range parsed {
		for _, d := range file.Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				e, ok := n.(ast.Expr)
				if !ok {
					return true
				}
				if s, ok := anyShellPath(index.strs(e, fn, map[string]bool{})); ok {
					report(e, strconv.Quote(s))
					return false
				}
				call, ok := e.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "exec" {
					return true
				}
				arg := -1
				switch sel.Sel.Name {
				case "Command", "LookPath":
					arg = 0
				case "CommandContext":
					arg = 1
				}
				if arg >= 0 && arg < len(call.Args) {
					if s, ok := anyShellName(index.strs(call.Args[arg], fn, map[string]bool{})); ok {
						report(call, strconv.Quote(s)+" looked up on PATH")
					}
				}
				return true
			})
		}
	}
	return found, nil
}

// windowsTestFiles reads the test files of this package that compile for
// Windows, except this file, which holds the accessors.
func windowsTestFiles(t *testing.T) map[string]string {
	t.Helper()
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "windows", "amd64", false
	names, err := filepath.Glob("*_test.go")
	if err != nil || len(names) == 0 {
		t.Fatalf("no test files found: %v", err)
	}
	files := map[string]string{}
	for _, name := range names {
		onWindows, err := ctx.MatchFile(".", name)
		if err != nil {
			t.Fatal(err)
		}
		if !onWindows || name == "shell_guard_test.go" {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(src)
	}
	return files
}

// TestTestsStartPosixShellsOnlyThroughTheAccessors keeps the image-build
// shell checks off hosts that cannot run them. Every test file that compiles
// on Windows gets its POSIX shell from binSh, binBash, maybeBinSh or
// maybeBinBash and never spells the path, whatever the test does with it: the
// rule does not depend on where a check sits relative to the use, on which
// side of a branch the skip is, or on what a helper does with the value.
func TestTestsStartPosixShellsOnlyThroughTheAccessors(t *testing.T) {
	found, err := shellNamings(windowsTestFiles(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("%s names a POSIX shell: take it from binSh(t), binBash(t) (skip when the host has none), or maybeBinSh(), maybeBinBash() (empty when it has none)", f)
	}
}

// TestShellGuardJudgesNearVariants pins the check itself: every way to spell
// a shell outside the accessors is named, wherever the value goes, and the
// uses of the accessors and the scripts that merely mention a shell are not.
func TestShellGuardJudgesNearVariants(t *testing.T) {
	const head = `package harness
import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)
`
	for _, tc := range []struct {
		name string
		body string
		bad  bool
	}{
		{"literal", `func TestX(t *testing.T) { exec.Command("/bin/sh", "-c", "true").Run() }`, true},
		{"local variable", `func TestX(t *testing.T) { shell := "/bin/sh"; exec.Command(shell, "-c", "true").Run() }`, true},
		{"var declaration", `func TestX(t *testing.T) { var shell = "/bin/bash"; exec.Command(shell).Run() }`, true},
		{"package constant", `const loginShell = "/bin/sh"
func TestX(t *testing.T) { exec.Command(loginShell).Run() }`, true},
		{"ranged list", `func TestX(t *testing.T) { for _, s := range []string{"/bin/dash", "/bin/sh"} { exec.Command(s).Run() } }`, true},
		{"shell as an argument", `func TestX(t *testing.T) { exec.Command("wrapper", "/bin/sh", "-c", "true").Run() }`, true},
		{"shell handed to a helper as data", `func note(string) {}
func TestX(t *testing.T) { note("/bin/sh") }`, true},
		{"stat alone", `func TestX(t *testing.T) { os.Stat("/bin/sh") }`, true},
		{"concatenation", `func TestX(t *testing.T) { exec.Command("/bin/" + "sh").Run() }`, true},
		{"constant concatenation", `const dir = "/usr/bin/"
const name = "bash"
func TestX(t *testing.T) { exec.Command(dir + name).Run() }`, true},
		{"parenthesized", `func TestX(t *testing.T) { exec.Command(("/bin/sh")).Run() }`, true},
		{"path.Join", `func TestX(t *testing.T) { exec.Command(path.Join("/bin", "sh")).Run() }`, true},
		{"filepath.Join", `func TestX(t *testing.T) { exec.Command(filepath.Join("/usr", "bin", "dash")).Run() }`, true},
		{"bare name", `func TestX(t *testing.T) { exec.Command("sh", "-c", "true").Run() }`, true},
		{"bare name with a context", `func TestX(t *testing.T) { exec.CommandContext(nil, "bash").Run() }`, true},
		{"bare name looked up", `func TestX(t *testing.T) { exec.LookPath("sh") }`, true},
		{"check in an unreachable branch", `func TestX(t *testing.T) { if false { if _, err := os.Stat("/bin/sh"); err != nil { t.Skip() } }
exec.Command("/bin/sh").Run() }`, true},
		{"missing-shell branch that only logs", `func TestX(t *testing.T) { if _, err := os.Stat("/bin/sh"); err != nil { t.Log("no shell") }
exec.Command("/bin/sh").Run() }`, true},
		{"skip on the present side", `func TestX(t *testing.T) { if _, err := os.Stat("/bin/sh"); err == nil { t.Skip() }
exec.Command("/bin/sh").Run() }`, true},
		{"skip on linux only", `func TestX(t *testing.T) { if runtime.GOOS == "linux" { return }
exec.Command("/bin/sh").Run() }`, true},
		{"helper with a conditional check", `func check(t *testing.T, on bool) { if on { if _, err := os.Stat("/bin/sh"); err != nil { t.Skip() } } }
func TestX(t *testing.T) { check(t, false)
exec.Command("/bin/sh").Run() }`, true},
		{"check after the use", `func TestX(t *testing.T) { exec.Command("/bin/sh").Run()
if _, err := os.Stat("/bin/sh"); err != nil { t.Skip() } }`, true},
		{"bare name held in a local variable", `func TestX(t *testing.T) { shell := "sh"; exec.Command(shell, "-c", "true").Run() }`, true},
		{"bare name in a var declaration", `func TestX(t *testing.T) { var shell = "bash"; exec.CommandContext(nil, shell).Run() }`, true},
		{"bare name set after the declaration", `func TestX(t *testing.T) { shell := "true"; shell = "sh"; exec.Command(shell).Run() }`, true},
		{"bare name in a package constant", `const shellName = "dash"
func TestX(t *testing.T) { exec.LookPath(shellName) }`, true},
		{"path joined from a local directory", `func TestX(t *testing.T) { dir := "/bin"; exec.Command(path.Join(dir, "sh")).Run() }`, true},
		{"path joined from two locals", `func TestX(t *testing.T) { dir, name := "/usr/bin", "bash"; exec.Command(filepath.Join(dir, name)).Run() }`, true},
		{"path summed from a local directory", `func TestX(t *testing.T) { dir := "/bin/"; exec.Command(dir + "sh").Run() }`, true},
		{"path joined from a ranged directory", `func TestX(t *testing.T) { for _, dir := range []string{"/opt", "/bin"} { exec.Command(path.Join(dir, "sh")).Run() } }`, true},
		{"bare names in a ranged list", `func TestX(t *testing.T) { for _, p := range []string{"python3", "sh"} { exec.Command(p).Run() } }`, true},
		{"bare name in a list element", `func TestX(t *testing.T) { progs := []string{"sh"}; exec.Command(progs[0]).Run() }`, true},
		{"bare name in a sliced list", `func TestX(t *testing.T) { progs := []string{"x", "sh"}; for _, p := range progs[1:] { exec.Command(p).Run() } }`, true},
		{"bare name given to a helper", `func run(prog string) { exec.Command(prog).Run() }
func TestX(t *testing.T) { run("sh") }`, true},
		{"path joined in a helper argument", `func run(prog string) { exec.Command(prog).Run() }
func TestX(t *testing.T) { dir := "/bin"; run(path.Join(dir, "bash")) }`, true},
		{"bare name in a keyed table", `func TestX(t *testing.T) { for _, tc := range []struct{ prog string }{{prog: "sh"}} { exec.Command(tc.prog).Run() } }`, true},
		{"bare name in a positional table", `func TestX(t *testing.T) { for _, tc := range []struct{ name, prog string }{{"case", "sh"}} { exec.Command(tc.prog).Run() } }`, true},
		{"bare name in a named struct table", `type job struct{ name, prog string }
func TestX(t *testing.T) { for _, tc := range []job{{"case", "bash"}} { exec.Command(tc.prog).Run() } }`, true},
		{"bare name in a positional struct", `type job struct{ prog string }
func TestX(t *testing.T) { j := job{"sh"}; exec.Command(j.prog).Run() }`, true},
		{"bare name in a map table", `func TestX(t *testing.T) { for _, tc := range map[string]struct{ prog string }{"a": {"sh"}} { exec.Command(tc.prog).Run() } }`, true},
		{"program names that are not shells in a table", `func TestX(t *testing.T) { for _, tc := range []struct{ name, prog string }{{"sh", "python3"}} { exec.Command(tc.prog, tc.name).Run() } }`, false},
		{"bare name set on a field", `type job struct{ prog string }
func TestX(t *testing.T) { var j job; j.prog = "zsh"; exec.Command(j.prog).Run() }`, true},
		{"name set from itself", `func TestX(t *testing.T) { shell := "x"; shell = shell + ""; shell = "sh"; exec.Command(shell).Run() }`, true},
		{"local name that is not a shell", `func TestX(t *testing.T) { prog := "python3"; dir := "/bin"; exec.Command(prog).Run(); exec.Command(path.Join(dir, "python3")).Run() }`, false},
		{"shell word held only as an argument", `func TestX(t *testing.T) { shell := "sh"; exec.Command("wrapper", shell, "one").Run() }`, false},
		{"same name in another function", `func other() { shell := "sh"; _ = shell }
func TestX(t *testing.T) { shell := binSh(t); exec.Command(shell, "-n").Run() }`, false},
		{"helper handed the accessor", `func run(prog string) { exec.Command(prog).Run() }
func TestX(t *testing.T) { run(binBash(t)) }`, false},
		{"binSh", `func TestX(t *testing.T) { exec.Command(binSh(t), "-c", "true").Run() }`, false},
		{"binBash as a wrapper argument", `func TestX(t *testing.T) { exec.Command("wrapper", binBash(t), "-c", "true").Run() }`, false},
		{"soft shell", `func TestX(t *testing.T) { sh := maybeBinSh()
if sh == "" { return }
exec.Command(sh, "-n").Run() }`, false},
		{"shebang text", `func TestX(t *testing.T) { os.WriteFile("f", []byte("#!/bin/sh\necho hi\n"), 0o755) }`, false},
		{"shell inside script text", `func TestX(t *testing.T) { inner := "x"; _ = "printf hi\nexec /bin/sh " + inner + "\n" }`, false},
		{"shell word as a script argument", `func TestX(t *testing.T) { exec.Command("wrapper", "sh", "one").Run() }`, false},
		{"other program", `func TestX(t *testing.T) { exec.Command("/usr/bin/python3").Run() }`, false},
	} {
		got, err := shellNamings(map[string]string{"x_test.go": head + tc.body})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: flagged %q, want flagged=%v", tc.name, got, tc.bad)
		}
	}
}
