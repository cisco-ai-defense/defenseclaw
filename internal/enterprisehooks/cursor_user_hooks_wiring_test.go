// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	_ "embed"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The source is embedded so that the test also runs from a test binary copied
// away from the source tree.
//
//go:embed install_windows_cursor_secure.go
var windowsCursorManagedInstallSource []byte

// The per-user Cursor cleanup edits the user's own hooks.json, so it runs only
// once the managed install or repair is committed and verified: right after
// the machine enrollment check succeeds, and on no path that rolls back. The
// Windows install cannot run end to end in a unit test, so this pins where
// installWindowsCursorManagedResult calls it. It parses the Windows source,
// so it runs on every platform.
func TestWindowsCursorManagedInstallCleansPerUserEntriesOnlyAfterVerification(t *testing.T) {
	const (
		source  = "install_windows_cursor_secure.go"
		install = "installWindowsCursorManagedResult"
		verify  = "verifyWindowsCursorMachineTarget"
		cleanup = "cleanupWindowsCursorPerUserHookRegistrations"
	)
	parsed, err := parser.ParseFile(token.NewFileSet(), source, windowsCursorManagedInstallSource, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	var function *ast.FuncDecl
	for _, decl := range parsed.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == install {
			function = candidate
		}
	}
	if function == nil || function.Body == nil {
		t.Fatalf("%s not found in %s: the scan is broken, not the code", install, source)
	}
	isCall := func(node ast.Node, name string) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return false
		}
		ident, ok := call.Fun.(*ast.Ident)
		return ok && ident.Name == name
	}
	count := func(node ast.Node, name string) int {
		calls := 0
		ast.Inspect(node, func(n ast.Node) bool {
			if isCall(n, name) {
				calls++
			}
			return true
		})
		return calls
	}

	if calls := count(function.Body, cleanup); calls != 1 {
		t.Fatalf("%s calls %s %d times, want once", install, cleanup, calls)
	}
	statements := function.Body.List
	cleanupAt, verifyAt := -1, -1
	for index, statement := range statements {
		if expr, ok := statement.(*ast.ExprStmt); ok && isCall(expr.X, cleanup) {
			cleanupAt = index
		}
		if check, ok := statement.(*ast.IfStmt); ok && check.Init != nil && count(check.Init, verify) == 1 {
			verifyAt = index
		}
	}
	if cleanupAt < 0 {
		t.Fatalf("%s is not a statement of %s's body; inside a branch or closure it could run on a failure path", cleanup, install)
	}
	if verifyAt < 0 {
		t.Fatalf("%s has no `if err := %s(...); err != nil` statement: the scan is broken, not the code", install, verify)
	}
	if cleanupAt != verifyAt+1 {
		t.Fatalf("%s is statement %d of %s, want it right after the %s check (statement %d)", cleanup, cleanupAt, install, verify, verifyAt)
	}
	failed := statements[verifyAt].(*ast.IfStmt)
	if len(failed.Body.List) == 0 {
		t.Fatalf("the %s check does not return on failure", verify)
	}
	if _, ok := failed.Body.List[len(failed.Body.List)-1].(*ast.ReturnStmt); !ok || failed.Else != nil {
		t.Fatalf("the %s check does not end in a return on failure, so a failed check could reach %s", verify, cleanup)
	}
	if cleanupAt+1 != len(statements)-1 {
		t.Fatalf("%s is followed by %d statements, want only the success return", cleanup, len(statements)-1-cleanupAt)
	}
	done, ok := statements[cleanupAt+1].(*ast.ReturnStmt)
	if !ok || len(done.Results) != 2 {
		t.Fatalf("the statement after %s is not the success return", cleanup)
	}
	if result, ok := done.Results[1].(*ast.Ident); !ok || result.Name != "nil" {
		t.Fatalf("the return after %s does not return a nil error", cleanup)
	}
}
