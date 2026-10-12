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

package packs

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoAmbientIdentity: the managed gateway resolves for the peer of a
// hook-socket call, so nothing in this package may read the identity of
// the process (its uid, its home, its account, its environment) instead of
// the Subject it was given. The two OSS defaults (ownUID, ownHome in
// subject.go) are the only reads, callerSubject the only user of them, and
// only the OSS entry points that resolve for the caller's own account call
// callerSubject.
func TestNoAmbientIdentity(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, problem := range ambientIdentityUses(fset, file) {
			t.Error(problem)
		}
	}
	if checked == 0 {
		t.Fatal("no package files checked")
	}
}

// The checker itself finds each kind of read it bans.
func TestAmbientIdentityChecker(t *testing.T) {
	const src = `package packs

import (
	"os"
	"os/user"
	"syscall"

	"golang.org/x/sys/unix"
)

var getenv = os.Getenv

func leaks(key string) {
	_ = syscall.Getuid()
	_ = unix.Geteuid()
	_ = os.Environ()
	_ = os.Getenv(key)
	_, _ = os.LookupEnv("USER")
	_ = os.Getenv("DEFENSECLAW_DEBUG")
	_ = ownHome
	_, _ = user.Current()
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "leaks.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ambientIdentityUses(fset, file), "\n")
	for _, want := range []string{
		"imports os/user", "uses os.Getenv as a value", "uses syscall.Getuid", "uses unix.Geteuid",
		"uses os.Environ", "reads an environment variable it does not name", "reads $USER", "uses ownHome in leaks",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("checker missed %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "DEFENSECLAW_DEBUG") || strings.Count(got, "\n")+1 != 8 {
		t.Errorf("checker problems:\n%s", got)
	}
}

// ambientIdentityUses lists file's reads of the process's identity outside
// the OSS defaults.
func ambientIdentityUses(fset *token.FileSet, file *ast.File) []string {
	// Where each guarded name may appear: "var" is the package-level
	// declaration of the two defaults, every other entry a function.
	allowed := map[string]map[string]bool{
		"os.Getuid":      {"var ownUID": true},
		"os.UserHomeDir": {"var ownHome": true},
		"ownUID":         {"var ownUID": true, "callerSubject": true},
		"ownHome":        {"var ownHome": true, "callerSubject": true},
		"callerSubject": {
			"func callerSubject": true, "subjectOf": true, "Load": true,
			"Validate": true, "List": true, "ParseIn": true, "ProfilePackCheck": true,
		},
	}
	banned := map[string]bool{
		"os.Geteuid": true, "os.Getgid": true, "os.Getegid": true, "os.Getgroups": true,
		// The environment names the process's account too ($HOME, $USER).
		"os.Environ": true, "os.ExpandEnv": true, "os.Expand": true,
		// The former ambient helpers must not come back.
		"userHomeDir": true, "currentUID": true,
	}
	for _, pkg := range []string{"syscall", "unix"} {
		for _, call := range []string{"Getuid", "Geteuid", "Getgid", "Getegid", "Getgroups", "Getenv", "Environ"} {
			banned[pkg+"."+call] = true
		}
	}
	// os.Getenv and os.LookupEnv may only be called, with a literal name
	// that is not an account's identity.
	identityEnv := map[string]bool{
		"HOME": true, "USER": true, "LOGNAME": true, "USERPROFILE": true, "USERNAME": true,
		"SUDO_UID": true, "SUDO_USER": true,
	}
	envReads := map[string]bool{"os.Getenv": true, "os.LookupEnv": true}

	var problems []string
	report := func(pos token.Pos, format string, args ...any) {
		problems = append(problems, fset.Position(pos).String()+" "+fmt.Sprintf(format, args...))
	}
	for _, imp := range file.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); path == "os/user" {
			report(imp.Pos(), "imports os/user: resolve for the Subject you are given")
		}
	}
	for _, decl := range file.Decls {
		scopes := map[ast.Node]string{}
		switch d := decl.(type) {
		case *ast.FuncDecl:
			scopes[d.Body] = d.Name.Name
			if d.Recv == nil {
				scopes[d.Name] = "func " + d.Name.Name
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, id := range vs.Names {
						scope := "var " + id.Name
						scopes[id] = scope
						if i < len(vs.Values) {
							scopes[vs.Values[i]] = scope
						}
					}
				}
			}
		}
		for node, scope := range scopes {
			if node == nil {
				continue
			}
			called := map[ast.Node]bool{}
			ast.Inspect(node, func(n ast.Node) bool {
				var guarded string
				switch x := n.(type) {
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						break
					}
					if pkg, ok := sel.X.(*ast.Ident); !ok || !envReads[pkg.Name+"."+sel.Sel.Name] {
						break
					}
					called[sel] = true
					var name string
					lit, ok := ast.Expr(nil), false
					if len(x.Args) == 1 {
						lit = x.Args[0]
						if bl, isLit := lit.(*ast.BasicLit); isLit && bl.Kind == token.STRING {
							name, _ = strconv.Unquote(bl.Value)
							ok = true
						}
					}
					switch {
					case !ok:
						report(x.Pos(), "reads an environment variable it does not name: resolve for the Subject you are given")
					case identityEnv[name]:
						report(x.Pos(), "reads $%s: resolve for the Subject you are given", name)
					}
				case *ast.SelectorExpr:
					pkg, ok := x.X.(*ast.Ident)
					if !ok || (pkg.Name != "os" && pkg.Name != "syscall" && pkg.Name != "unix") {
						break
					}
					guarded = pkg.Name + "." + x.Sel.Name
					if envReads[guarded] && !called[x] {
						report(x.Pos(), "uses %s as a value: call it with the variable's name", guarded)
					}
				case *ast.Ident:
					guarded = x.Name
				}
				if guarded == "" {
					return true
				}
				if banned[guarded] {
					report(n.Pos(), "uses %s: resolve for the Subject you are given", guarded)
				}
				if scopesOK, ok := allowed[guarded]; ok && !scopesOK[scope] {
					report(n.Pos(), "uses %s in %s, outside the OSS defaults", guarded, scope)
				}
				return true
			})
		}
	}
	return problems
}
