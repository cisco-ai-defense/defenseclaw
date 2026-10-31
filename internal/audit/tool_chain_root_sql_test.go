// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Every chain statement of the repository names its tables through repo.sql,
// so a root-set repository can never read or write a session table.
func TestToolChainRepositoryRoutesEverySQLStatementThroughItsTableSet(t *testing.T) {
	for _, file := range []string{"tool_chain_state.go", "tool_chain_pending.go"} {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		routed := map[*ast.BasicLit]bool{}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "sql" {
				for _, arg := range call.Args {
					if literal, ok := arg.(*ast.BasicLit); ok {
						routed[literal] = true
					}
				}
			}
			return true
		})
		count := 0
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || !strings.Contains(literal.Value, "guardrail_chain_") ||
				!strings.ContainsAny(literal.Value, " \n\t") {
				return true
			}
			count++
			if !routed[literal] {
				t.Errorf("%s: a chain statement is not routed through repo.sql", fset.Position(literal.Pos()))
			}
			return true
		})
		if count == 0 {
			t.Fatalf("%s: no chain statement found", file)
		}
	}
}
