// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// GAP-0916 (review S-F1). The guardian pass clears the off-roster markers of
// the connectors the config publishes before it syncs the enrollments, so a
// marker never survives into the pass that republishes a machine policy (the
// hook allows a removed connector only while its policy is absent). The call
// itself is a no-op off the Windows standalone guardian, so the order is pinned
// on the pass's source: the clearing call comes first, and it is the only one
// before the first sync call.
func TestGuardianPassClearsOffRosterMarkersBeforeSyncingEnrollments(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "enterprise_hooks.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pass *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "runEnterpriseHookReconcileOnce" {
			pass = fn
		}
	}
	if pass == nil {
		t.Fatal("runEnterpriseHookReconcileOnce not found in enterprise_hooks.go")
	}
	var clears, syncs []token.Pos
	ast.Inspect(pass.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "enterpriseHookStandalonePlatformClearStaleOffRoster":
				clears = append(clears, call.Pos())
			case "enterpriseHookReconcileSyncEnrollments":
				syncs = append(syncs, call.Pos())
			}
		}
		return true
	})
	if len(clears) != 1 || len(syncs) == 0 {
		t.Fatalf("the pass calls the marker clearing %d times and the enrollment sync %d times, want once and at least once", len(clears), len(syncs))
	}
	for _, sync := range syncs {
		if sync < clears[0] {
			t.Fatalf("the enrollment sync at %v comes before the marker clearing at %v: a stale off-roster marker would survive into the pass that republishes the policy",
				fset.Position(sync), fset.Position(clears[0]))
		}
	}
}
