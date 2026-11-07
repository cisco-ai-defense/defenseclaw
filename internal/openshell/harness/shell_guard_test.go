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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// posixShells are the host shells a Windows machine does not have.
var posixShells = map[string]bool{"/bin/sh": true, "/bin/bash": true}

// shellUse is a place a function starts a POSIX shell: directly through
// os/exec or by handing the shell path to a helper of this package.
type shellUse struct {
	pos   token.Pos
	shell string
}

// shellsOf reports the POSIX shells an expression can hold: a string
// literal, a name bound to one (package level, a local assignment or a range
// over a list of them) or a list that contains one.
func shellsOf(e ast.Expr, env map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	switch e := e.(type) {
	case *ast.BasicLit:
		if s, err := strconv.Unquote(e.Value); err == nil && e.Kind == token.STRING && posixShells[s] {
			out[s] = true
		}
	case *ast.Ident:
		for s := range env[e.Name] {
			out[s] = true
		}
	case *ast.ParenExpr:
		return shellsOf(e.X, env)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			for s := range shellsOf(elt, env) {
				out[s] = true
			}
		}
	}
	return out
}

// bindShells records every name the node binds to a shell path.
func bindShells(root ast.Node, env map[string]map[string]bool) {
	bind := func(name ast.Expr, value ast.Expr) {
		id, ok := name.(*ast.Ident)
		if !ok {
			return
		}
		for s := range shellsOf(value, env) {
			if env[id.Name] == nil {
				env[id.Name] = map[string]bool{}
			}
			env[id.Name][s] = true
		}
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i := range n.Lhs {
					bind(n.Lhs[i], n.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i := range n.Names {
					bind(n.Names[i], n.Values[i])
				}
			}
		case *ast.RangeStmt:
			if n.Value != nil {
				bind(n.Value, n.X)
			}
		}
		return true
	})
}

// shellsFromCall reports the shells named by the arguments of a call.
func shellsFromCall(call *ast.CallExpr, env map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, arg := range call.Args {
		for s := range shellsOf(arg, env) {
			out[s] = true
		}
	}
	return out
}

// pkgCall splits a call of the form pkg.Name(...).
func pkgCall(call *ast.CallExpr) (pkg, name string) {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name, sel.Sel.Name
		}
	}
	return "", ""
}

// skipCall reports whether the block calls t.Skip, t.SkipNow or t.Skipf.
func skipCall(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Skip") {
				found = true
			}
		}
		return !found
	})
	return found
}

// leaves reports whether the block ends the test or helper early: a skip or
// a return.
func leaves(block *ast.BlockStmt) bool {
	found := skipCall(block)
	ast.Inspect(block, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// shellScan is what one function does about POSIX shells, in source order.
type shellScan struct {
	uses   []shellUse      // places it starts a shell
	guards []shellUse      // checks that a shell exists, from the position they take effect
	skips  map[string]bool // shells whose absence skips the calling test
}

// scanShells reads one function. A check is requirePOSIXShell or any helper
// that skips the test when a shell is missing, an os.Stat or os.Lstat of the
// shell inside an if, or an if on runtime.GOOS that leaves; the shells of a
// helper's skip are those it checks itself or through its own helpers.
// unguarded holds the shells a helper starts before checking, which count as
// a use at each call.
func scanShells(fn *ast.FuncDecl, pkgEnv map[string]map[string]bool, funcs map[string]*ast.FuncDecl,
	skipHelpers, unguarded map[string]map[string]bool) shellScan {
	env := map[string]map[string]bool{}
	for k, v := range pkgEnv {
		env[k] = v
	}
	bindShells(fn.Body, env)
	scan := shellScan{skips: map[string]bool{}}
	guard := func(pos token.Pos, shell string, skip bool) {
		scan.guards = append(scan.guards, shellUse{pos, shell})
		if skip {
			scan.skips[shell] = true
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt:
			for _, part := range []ast.Node{n.Init, n.Cond} {
				if part == nil {
					continue
				}
				ast.Inspect(part, func(m ast.Node) bool {
					switch m := m.(type) {
					case *ast.CallExpr:
						if pkg, name := pkgCall(m); pkg == "os" && (name == "Stat" || name == "Lstat") {
							for s := range shellsFromCall(m, env) {
								guard(m.Pos(), s, skipCall(n.Body))
							}
						}
					case *ast.SelectorExpr:
						if id, ok := m.X.(*ast.Ident); ok && id.Name == "runtime" && m.Sel.Name == "GOOS" && leaves(n.Body) {
							guard(n.Pos(), "*", skipCall(n.Body))
						}
					}
					return true
				})
			}
		case *ast.CallExpr:
			pkg, name := pkgCall(n)
			id, _ := n.Fun.(*ast.Ident)
			switch {
			case pkg == "exec" && strings.HasPrefix(name, "Command"):
				for s := range shellsFromCall(n, env) {
					scan.uses = append(scan.uses, shellUse{n.Pos(), s})
				}
			case id != nil && funcs[id.Name] != nil:
				for s := range skipHelpers[id.Name] {
					guard(n.Pos(), s, true)
				}
				for s := range shellsFromCall(n, env) {
					scan.uses = append(scan.uses, shellUse{n.Pos(), s})
				}
				for s := range unguarded[id.Name] {
					scan.uses = append(scan.uses, shellUse{n.Pos(), s})
				}
			}
		}
		return true
	})
	return scan
}

// unguardedShells reports, per function of the package, the shells it can
// start before any check that the shell exists. The use is a direct os/exec
// call or a call to a helper that starts a shell without its own check; the
// check must come earlier in the source and cover that shell.
func unguardedShells(files map[string]string) (map[string]map[string]bool, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	pkgEnv := map[string]map[string]bool{}
	funcs := map[string]*ast.FuncDecl{}
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				bindShells(d, pkgEnv)
			case *ast.FuncDecl:
				if d.Body != nil && d.Recv == nil {
					funcs[d.Name.Name] = d
				}
			}
		}
	}
	skipHelpers := map[string]map[string]bool{}
	for changed, round := true, 0; changed && round <= len(funcs); round++ {
		changed = false
		for fname, fn := range funcs {
			for s := range scanShells(fn, pkgEnv, funcs, skipHelpers, nil).skips {
				if skipHelpers[fname] == nil {
					skipHelpers[fname] = map[string]bool{}
				}
				if !skipHelpers[fname][s] {
					skipHelpers[fname][s] = true
					changed = true
				}
			}
		}
	}
	unguarded := map[string]map[string]bool{}
	for changed, round := true, 0; changed && round <= len(funcs); round++ {
		changed = false
		for fname, fn := range funcs {
			scan := scanShells(fn, pkgEnv, funcs, skipHelpers, unguarded)
			for _, use := range scan.uses {
				covered := false
				for _, g := range scan.guards {
					covered = covered || (g.pos < use.pos && (g.shell == "*" || g.shell == use.shell))
				}
				if !covered && !unguarded[fname][use.shell] {
					if unguarded[fname] == nil {
						unguarded[fname] = map[string]bool{}
					}
					unguarded[fname][use.shell] = true
					changed = true
				}
			}
		}
	}
	return unguarded, nil
}

// unguardedShellTests names the tests among the files that start a POSIX
// shell on a host that may not have one.
func unguardedShellTests(files map[string]string) ([]string, error) {
	unguarded, err := unguardedShells(files)
	if err != nil {
		return nil, err
	}
	var bad []string
	for fname, shells := range unguarded {
		if !strings.HasPrefix(fname, "Test") {
			continue
		}
		var list []string
		for s := range shells {
			list = append(list, s)
		}
		sort.Strings(list)
		bad = append(bad, fname+" ("+strings.Join(list, ", ")+")")
	}
	sort.Strings(bad)
	return bad, nil
}

// TestTestsThatRunBinShSkipWithoutAPosixShell keeps the image-build shell
// checks off hosts that cannot run them. The fragments in this package run in
// the Linux sandbox image, never on the host; a test that executes one through
// /bin/sh fails to start the process on Windows, so every case reads as a
// refusal and the positive cases go red. Every test that compiles on Windows
// and starts /bin/sh or /bin/bash, directly, through a name that holds the
// path or through a helper of this package, must first check that the shell
// exists (requirePOSIXShell, an os.Stat of that shell in an if) or skip on
// runtime.GOOS.
func TestTestsThatRunBinShSkipWithoutAPosixShell(t *testing.T) {
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
		if !onWindows {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(src)
	}
	bad, err := unguardedShellTests(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Errorf("%s starts a POSIX shell without checking it exists (requirePOSIXShell, os.Stat of that shell in an if, or a runtime.GOOS skip)", b)
	}
}

// TestShellGuardJudgesNearVariants pins the check itself: the shapes that
// start a shell without a check that covers it are named, and the shapes
// with a covering check are not.
func TestShellGuardJudgesNearVariants(t *testing.T) {
	const head = "package harness\nimport (\n\"os\"\n\"os/exec\"\n\"runtime\"\n\"testing\"\n)\nfunc requirePOSIXShell(t *testing.T) { if _, err := os.Stat(\"/bin/sh\"); err != nil { t.Skip() } }\n"
	for _, tc := range []struct {
		name string
		body string
		bad  bool
	}{
		{"literal", "func TestX(t *testing.T) { exec.Command(\"/bin/sh\", \"-c\", \"true\").Run() }", true},
		{"local variable", "func TestX(t *testing.T) { shell := \"/bin/sh\"; exec.Command(shell, \"-c\", \"true\").Run() }", true},
		{"var declaration", "func TestX(t *testing.T) { var shell = \"/bin/bash\"; exec.Command(shell).Run() }", true},
		{"package constant", "const loginShell = \"/bin/sh\"\nfunc TestX(t *testing.T) { exec.Command(loginShell).Run() }", true},
		{"ranged list", "func TestX(t *testing.T) { for _, s := range []string{\"/bin/dash\", \"/bin/sh\"} { exec.Command(s).Run() } }", true},
		{"shell as an argument", "func TestX(t *testing.T) { exec.Command(\"wrapper\", \"/bin/sh\", \"-c\", \"true\").Run() }", true},
		{"unrelated stat", "func TestX(t *testing.T) { if _, err := os.Stat(\"ordinary\"); err != nil { t.Skip() }\nexec.Command(\"/bin/sh\").Run() }", true},
		{"stat that is not a branch", "func TestX(t *testing.T) { os.Stat(\"/bin/sh\")\nexec.Command(\"/bin/sh\").Run() }", true},
		{"stat of the other shell", "func TestX(t *testing.T) { if _, err := os.Stat(\"/bin/sh\"); err != nil { t.Skip() }\nexec.Command(\"/bin/bash\").Run() }", true},
		{"check after the use", "func TestX(t *testing.T) { exec.Command(\"/bin/sh\").Run()\nrequirePOSIXShell(t) }", true},
		{"mention of runtime.GOOS without a skip", "func TestX(t *testing.T) { t.Log(runtime.GOOS)\nexec.Command(\"/bin/sh\").Run() }", true},
		{"helper without a check", "func runIt() { exec.Command(\"/bin/sh\").Run() }\nfunc TestX(t *testing.T) { runIt() }", true},
		{"helper handed the shell", "func runIn(shell string) { exec.Command(shell).Run() }\nfunc TestX(t *testing.T) { runIn(\"/bin/sh\") }", true},
		{"helper two levels down", "func inner() { exec.Command(\"/bin/sh\").Run() }\nfunc outer() { inner() }\nfunc TestX(t *testing.T) { outer() }", true},
		{"required check", "func TestX(t *testing.T) { requirePOSIXShell(t)\nexec.Command(\"/bin/sh\").Run() }", false},
		{"stat of the shell", "func TestX(t *testing.T) { if _, err := os.Stat(\"/bin/sh\"); err != nil { t.Skip() }\nexec.Command(\"/bin/sh\").Run() }", false},
		{"stat of the shell by name", "func TestX(t *testing.T) { shell := \"/bin/bash\"\nif _, err := os.Stat(shell); err != nil { t.Skip() }\nexec.Command(shell).Run() }", false},
		{"stat that wraps the use", "func TestX(t *testing.T) { if _, err := os.Stat(\"/bin/bash\"); err == nil { exec.Command(\"/bin/bash\").Run() } }", false},
		{"goos skip", "func TestX(t *testing.T) { if runtime.GOOS == \"windows\" { t.Skip() }\nexec.Command(\"/bin/sh\").Run() }", false},
		{"helper after the check", "func runIt() { exec.Command(\"/bin/sh\").Run() }\nfunc TestX(t *testing.T) { requirePOSIXShell(t)\nrunIt() }", false},
		{"helper that checks itself", "func runIt() { if _, err := os.Stat(\"/bin/sh\"); err != nil { return }\nexec.Command(\"/bin/sh\").Run() }\nfunc TestX(t *testing.T) { runIt() }", false},
		{"helper that checks the other shell", "func needBash(t *testing.T) { if _, err := os.Stat(\"/bin/bash\"); err != nil { t.Skip() } }\nfunc TestX(t *testing.T) { needBash(t)\nexec.Command(\"/bin/sh\").Run() }", true},
		{"helper that only returns", "func check() { if _, err := os.Stat(\"/bin/sh\"); err != nil { return } }\nfunc TestX(t *testing.T) { check()\nexec.Command(\"/bin/sh\").Run() }", true},
		{"helper that checks the shell", "func needBash(t *testing.T) { if _, err := os.Stat(\"/bin/bash\"); err != nil { t.Skip() } }\nfunc TestX(t *testing.T) { needBash(t)\nexec.Command(\"/bin/bash\").Run() }", false},
		{"check through two helpers", "func outer(t *testing.T) { requirePOSIXShell(t) }\nfunc TestX(t *testing.T) { outer(t)\nexec.Command(\"/bin/sh\").Run() }", false},
		{"no shell", "func TestX(t *testing.T) { exec.Command(\"/usr/bin/python3\").Run() }", false},
	} {
		got, err := unguardedShellTests(map[string]string{"x_test.go": head + tc.body})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: flagged %q, want flagged=%v", tc.name, got, tc.bad)
		}
	}
}
