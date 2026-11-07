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
	"path/filepath"
	"strings"
	"testing"
)

// TestTestsThatRunBinShSkipWithoutAPosixShell keeps the image-build shell
// checks off hosts that cannot run them. The fragments in this package run in
// the Linux sandbox image, never on the host; a test that executes one through
// /bin/sh fails to start the process on Windows, so every case reads as a
// refusal and the positive cases go red. Every test that compiles on Windows
// and runs /bin/sh or /bin/bash itself must check for the shell first
// (requirePOSIXShell, os.Stat of the shell) or gate on runtime.GOOS.
func TestTestsThatRunBinShSkipWithoutAPosixShell(t *testing.T) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "windows", "amd64", false
	names, err := filepath.Glob("*_test.go")
	if err != nil || len(names) == 0 {
		t.Fatalf("no test files found: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range names {
		onWindows, err := ctx.MatchFile(".", name)
		if err != nil {
			t.Fatal(err)
		}
		if !onWindows {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			runsShell, guarded := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					switch fun := n.Fun.(type) {
					case *ast.Ident:
						guarded = guarded || fun.Name == "requirePOSIXShell"
					case *ast.SelectorExpr:
						pkg, _ := fun.X.(*ast.Ident)
						if pkg == nil {
							break
						}
						guarded = guarded || (pkg.Name == "os" && fun.Sel.Name == "Stat")
						if pkg.Name == "exec" && strings.HasPrefix(fun.Sel.Name, "Command") {
							for _, arg := range n.Args {
								if lit, ok := arg.(*ast.BasicLit); ok && (lit.Value == `"/bin/sh"` || lit.Value == `"/bin/bash"`) {
									runsShell = true
								}
							}
						}
					}
				case *ast.SelectorExpr:
					if pkg, ok := n.X.(*ast.Ident); ok && pkg.Name == "runtime" && n.Sel.Name == "GOOS" {
						guarded = true
					}
				}
				return true
			})
			if runsShell && !guarded {
				t.Errorf("%s: %s runs /bin/sh without requirePOSIXShell, an os.Stat of the shell or a runtime.GOOS check", name, fn.Name.Name)
			}
		}
	}
}
