// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The gateway must use the hook path reader for identity checks, so a
// network share cannot hold a hook beyond its answer budget.
func TestG288GatewayPathReadersUseSharedAccessor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string]bool{"Stat": true, "Lstat": true, "Readlink": true, "ReadDir": true}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") ||
			!(strings.HasPrefix(name, "semantic_") || strings.HasPrefix(name, "trusted_")) ||
			!strings.HasSuffix(name, ".go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "os" && reads[selector.Sel.Name] ||
				pkg.Name == "filepath" && selector.Sel.Name == "EvalSymlinks" {
				t.Errorf("%s has a direct path identity read", name)
			}
			return true
		})
	}
}
