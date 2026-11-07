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

// constString folds an expression to the string it always holds: a string
// literal, a constant of the package, a sum of them or a path.Join /
// filepath.Join of them.
func constString(e ast.Expr, consts map[string]ast.Expr, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return constString(e.X, consts, depth+1)
	case *ast.Ident:
		if v, ok := consts[e.Name]; ok {
			return constString(v, consts, depth+1)
		}
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := constString(e.X, consts, depth+1)
		r, rok := constString(e.Y, consts, depth+1)
		return l + r, lok && rok
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || sel.Sel.Name != "Join" || (pkg.Name != "path" && pkg.Name != "filepath") {
			return "", false
		}
		parts := make([]string, len(e.Args))
		for i, arg := range e.Args {
			s, ok := constString(arg, consts, depth+1)
			if !ok {
				return "", false
			}
			parts[i] = s
		}
		return path.Join(parts...), true
	}
	return "", false
}

// shellNamings reports every place the files name a POSIX shell outside the
// accessors: any expression that is always a shell path (a literal, a
// constant, a sum or a join of them, wherever it flows: a variable, a list,
// an argument, the parameter of a helper), and a bare shell name handed to
// exec.Command, exec.CommandContext or exec.LookPath.
func shellNamings(files map[string]string) ([]string, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	parsed := map[string]*ast.File{}
	consts := map[string]ast.Expr{}
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			return nil, err
		}
		parsed[name] = file
		ast.Inspect(file, func(n ast.Node) bool {
			if d, ok := n.(*ast.GenDecl); ok && d.Tok == token.CONST {
				for _, spec := range d.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) == len(v.Values) {
						for i := range v.Names {
							consts[v.Names[i].Name] = v.Values[i]
						}
					}
				}
			}
			return true
		})
	}
	var found []string
	report := func(n ast.Node, what string) {
		p := fset.Position(n.Pos())
		found = append(found, p.Filename+":"+strconv.Itoa(p.Line)+": "+what)
	}
	for _, name := range names {
		ast.Inspect(parsed[name], func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if s, ok := constString(e, consts, 0); ok && shellPaths[s] {
				report(e, strconv.Quote(s))
				return false
			}
			if call, ok := e.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "exec" {
						arg := -1
						switch sel.Sel.Name {
						case "Command", "LookPath":
							arg = 0
						case "CommandContext":
							arg = 1
						}
						if arg >= 0 && arg < len(call.Args) {
							if s, ok := constString(call.Args[arg], consts, 0); ok && shellNames[s] {
								report(call, strconv.Quote(s)+" looked up on PATH")
							}
						}
					}
				}
			}
			return true
		})
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
