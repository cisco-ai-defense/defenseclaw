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

package reasons

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const repoRoot = "../../.."

// sources are the files whose secret reason codes must all be in Table.
var sources = []string{
	"internal/gateway/substrate_secrets*.go",
	"internal/gateway/substrate_secret_*.go",
	"internal/substrate/render/*.go",
	"internal/substrate/secretbind/*.go",
	"internal/cli/substrate_*.go",
}

var secretCode = regexp.MustCompile(`^secret_[a-z0-9_]+$`)

// usedCodes walks the AST of every source file (tests excluded) and returns
// the reason codes it uses: any secret_* string literal, any string literal
// right after an http.Status* argument or result (the gateway's reason), and
// the value of every Reason* constant (the render drop reasons).
func usedCodes(t *testing.T) map[string]string {
	t.Helper()
	used := map[string]string{}
	fset := token.NewFileSet()
	files := 0
	for _, pat := range sources {
		matches, err := filepath.Glob(filepath.Join(repoRoot, pat))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			files++
			at := func(lit *ast.BasicLit) {
				if v, err := strconv.Unquote(lit.Value); err == nil && v != "" {
					if _, seen := used[v]; !seen {
						used[v] = fset.Position(lit.Pos()).String()
					}
				}
			}
			afterStatus := func(list []ast.Expr) {
				for i := 1; i < len(list); i++ {
					sel, ok := list[i-1].(*ast.SelectorExpr)
					lit, isLit := list[i].(*ast.BasicLit)
					if ok && isLit && lit.Kind == token.STRING && strings.HasPrefix(sel.Sel.Name, "Status") {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" {
							at(lit)
						}
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if n.Kind == token.STRING {
						if v, _ := strconv.Unquote(n.Value); secretCode.MatchString(v) {
							at(n)
						}
					}
				case *ast.CallExpr:
					afterStatus(n.Args)
				case *ast.ReturnStmt:
					afterStatus(n.Results)
				case *ast.ValueSpec:
					for i, name := range n.Names {
						if strings.HasPrefix(name.Name, "Reason") && i < len(n.Values) {
							if lit, ok := n.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								at(lit)
							}
						}
					}
				}
				return true
			})
		}
	}
	if files < 10 {
		t.Fatalf("drift walk read only %d files; the source globs are wrong", files)
	}
	return used
}

// TestB1ReasonTableCoversEverySecretCode is the drift test: a reason code
// used by the gateway, the render or the CLI must have a row.
func TestB1ReasonTableCoversEverySecretCode(t *testing.T) {
	used := usedCodes(t)
	// Guard the walker itself: these codes are known to be in the code.
	for _, c := range []string{"shared_secret_admin_only", "value_required", "secret_on_passthrough", "not_in_allow_only", "secret_bindings_off", "secret_binding_limit"} {
		if _, ok := used[c]; !ok {
			t.Fatalf("drift walk did not find %q; the walker is broken", c)
		}
	}
	var missing []string
	for code, where := range used {
		if !Known(code) {
			missing = append(missing, code+" ("+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("reason codes used in the code but not in reasons.Table:\n  %s", strings.Join(missing, "\n  "))
	}
}

func TestTableRowsWellFormed(t *testing.T) {
	code := regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	seen := map[string]bool{}
	for _, r := range Table {
		if !code.MatchString(r.Code) || seen[r.Code] {
			t.Errorf("bad or duplicate code %q", r.Code)
		}
		seen[r.Code] = true
		if !strings.HasSuffix(r.Words, ".") || r.Fix == "" || strings.Contains(r.Words+r.Fix, "\n") {
			t.Errorf("%s: words must be one sentence ending in a period and the fix must be set", r.Code)
		}
		if (r.Where == API) != (r.HTTP != 0) {
			t.Errorf("%s: an API code needs its HTTP status, and only an API code has one", r.Code)
		}
		if r.Audience != Person && r.Audience != Admin {
			t.Errorf("%s: audience %q", r.Code, r.Audience)
		}
	}
}

func TestMessageAndMust(t *testing.T) {
	if got := Message("shared_secret_admin_only"); got != "A shared secret is set by an administrator, in the store its source names (shared_secret_admin_only). Ask your administrator to change it." {
		t.Fatalf("Message = %q", got)
	}
	if Message("no_such_code") != "" || Known("no_such_code") {
		t.Fatal("unknown code has a message")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Must did not panic on an unknown code")
		}
	}()
	Must("no_such_code")
}

// TestGeneratedDocsUpToDate fails when the docs table drifts from Table.
func TestGeneratedDocsUpToDate(t *testing.T) {
	old, err := os.ReadFile(filepath.Join(repoRoot, DocsPage))
	if err != nil {
		t.Fatal(err)
	}
	page, err := Splice(string(old))
	if err != nil {
		t.Fatal(err)
	}
	if page != string(old) {
		t.Fatalf("%s is out of date; run: go run ./internal/substrate/reasons/gen", DocsPage)
	}
	for _, r := range Table {
		if !strings.Contains(page, "`"+r.Code+"`") {
			t.Fatalf("docs page lacks %s", r.Code)
		}
	}
}
