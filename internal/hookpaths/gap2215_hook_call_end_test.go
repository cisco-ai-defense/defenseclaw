// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// A hook call leaves no entry once the goroutine that began it has ended,
// whichever way it ends: a return, a panic recovered in the goroutine, a
// panic recovered by an outer frame of it, or runtime.Goexit (t.FailNow).
// Off Windows the key of a call is goroutineKey, the address of the
// goroutine's g on most hosts, and the runtime gives the g of an ended
// goroutine to a later one: a later goroutine finds no call it did not begin
// because no entry outlives its goroutine (rel-1-0-10:GAP-2215).
func TestGAP2215HookCallLeavesNoEntryAfterItsGoroutineEnds(t *testing.T) {
	const each = 64
	ends := map[string]func(){
		"return": func() { defer HookCall()() },
		"begin":  func() { _, end := beginHookCall(); defer end() },
		"panic": func() {
			defer func() { _ = recover() }()
			defer HookCall()()
			panic("hook call panic")
		},
		"outer recover": func() {
			defer func() { _ = recover() }()
			func() { defer HookCall()(); panic("hook call panic") }()
		},
		"goexit": func() { defer HookCall()(); runtime.Goexit() },
		"nested": func() { defer HookCall()(); func() { defer HookCall()() }(); panic("nested") },
	}
	ended := map[uint64]bool{}
	var mu sync.Mutex
	for name, end := range ends {
		var wg sync.WaitGroup
		for range each {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = recover() }() // "nested" panics past its calls
				mu.Lock()
				ended[goroutineKey()] = true
				mu.Unlock()
				end()
			}()
		}
		wg.Wait()
		hookCalls.mu.Lock()
		for key := range ended {
			if open := hookCalls.calls[key]; open != nil {
				hookCalls.mu.Unlock()
				t.Fatalf("%s: an ended goroutine left its hook call open under key %#x", name, key)
			}
		}
		hookCalls.mu.Unlock()
	}
	// Later goroutines, some on the g of an ended one, find no call.
	var wg sync.WaitGroup
	var reused, found int
	for range 4 * each {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, call := goroutineKey(), currentHookCall()
			mu.Lock()
			if ended[key] {
				reused++
			}
			if call != nil {
				found++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if found != 0 {
		t.Fatalf("%d goroutines found a hook call they did not begin", found)
	}
	t.Logf("%d of %d later goroutines ran under the key of an ended one", reused, 4*each)
}

// Every hook call the product begins ends when the function that began it
// returns, panics or exits: HookCall() is called only as defer HookCall()(),
// and the end beginHookCall returns is deferred by the next statement. With
// that, no hook call outlives the goroutine that began it, so no entry stays
// under a key the runtime gives to another goroutine (goroutineKey,
// rel-1-0-10:GAP-2215).
func TestGAP2215EveryHookCallBeginDefersItsEnd(t *testing.T) {
	root := filepath.Join("..", "..")
	var sites int
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" || entry.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(source, []byte("HookCall()")) {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				return err
			}
			sites += checkHookCallEnds(t, path, file)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if sites < 8 {
		t.Fatalf("found %d hook call begins; the scan is broken", sites)
	}
}

// checkHookCallEnds reports each begin of file whose end is not deferred and
// returns how many begins it read.
func checkHookCallEnds(t *testing.T, path string, file *ast.File) int {
	t.Helper()
	isBegin := func(expr ast.Expr, name string) bool {
		call, ok := expr.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			return fun.Name == name
		case *ast.SelectorExpr:
			return fun.Sel.Name == name
		}
		return false
	}
	// The begins whose end the caller must defer next, and the wrappers that
	// hand that end to their own caller (BeginHookCall, JoinHookCall and
	// joinHookCall came with the found-call path of GAP-2197).
	beginsCall := func(expr ast.Expr) bool {
		for _, name := range []string{"beginHookCall", "BeginHookCall", "JoinHookCall", "joinHookCall"} {
			if isBegin(expr, name) {
				return true
			}
		}
		return false
	}
	endReturners := map[string]bool{"HookCall": true, "BeginHookCall": true, "JoinHookCall": true, "joinHookCall": true}
	sites := 0
	ast.Inspect(file, func(node ast.Node) bool {
		decl, ok := node.(*ast.FuncDecl)
		if !ok || decl.Body == nil {
			return true
		}
		deferred := map[ast.Expr]bool{}
		ast.Inspect(decl.Body, func(node ast.Node) bool {
			if stmt, ok := node.(*ast.DeferStmt); ok {
				deferred[stmt.Call.Fun] = true
			}
			return true
		})
		ast.Inspect(decl.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				if isBegin(node, "HookCall") {
					sites++
					if !deferred[node] {
						t.Errorf("%s: %s calls HookCall() other than as defer HookCall()()", path, decl.Name.Name)
					}
				}
			case *ast.BlockStmt:
				for i, stmt := range node.List {
					assign, ok := stmt.(*ast.AssignStmt)
					if !ok || len(assign.Rhs) != 1 || !beginsCall(assign.Rhs[0]) {
						continue
					}
					sites++
					if endReturners[decl.Name.Name] {
						continue // returns the end to its caller, who defers it
					}
					end, _ := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
					next, _ := elementAt(node.List, i+1).(*ast.DeferStmt)
					if end == nil || next == nil || len(next.Call.Args) != 0 {
						t.Errorf("%s: %s does not defer the end of beginHookCall next", path, decl.Name.Name)
						continue
					}
					if fun, ok := next.Call.Fun.(*ast.Ident); !ok || fun.Name != end.Name {
						t.Errorf("%s: %s defers %v, not the end %s of beginHookCall", path, decl.Name.Name, next.Call.Fun, end.Name)
					}
				}
			}
			return true
		})
		return false
	})
	return sites
}

func elementAt(list []ast.Stmt, i int) ast.Stmt {
	if i < len(list) {
		return list[i]
	}
	return nil
}
