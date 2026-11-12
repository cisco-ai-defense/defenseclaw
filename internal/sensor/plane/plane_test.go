// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// TestBufferDropCounterIsSafeUnderConcurrentPush pins the counter against the
// Linux source's two readers.
//
// cn_proc and fanotify run as separate goroutines over one Buffer and both
// call Push. A plain int64 counter races there, and the lost increments
// understate the drop count -- which is exactly the number the service
// reports as reduced coverage, so undercounting reproduces the silent
// degradation this package exists to prevent. Run under -race.
func TestBufferDropCounterIsSafeUnderConcurrentPush(t *testing.T) {
	buffer := NewBuffer()

	// Fill it so every subsequent Push has to evict.
	for range eventBuffer {
		buffer.Push(Event{Kind: KindExec, PID: 1})
	}

	const writers, each = 4, 200
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range each {
				buffer.Push(Event{Kind: KindExec, PID: 2})
			}
		}()
	}
	wait.Wait()

	// Every push past a full buffer evicts one event and counts one drop, so
	// the total is exact rather than merely nonzero. A racing counter loses
	// increments and lands short.
	if got, want := buffer.Dropped(), int64(writers*each); got != want {
		t.Fatalf("Dropped() = %d, want %d: increments were lost to a race", got, want)
	}
}

// TestBufferProtectsLineageUnderBackPressure pins the retention bias that
// keeps attribution working on a busy host.
//
// A saturated buffer that drops uniformly loses exec events first, because
// file events outnumber them by orders of magnitude when an AI agent is
// reading its own configuration directory. Losing an exec does not cost one
// signal -- it orphans an entire subtree, so the lineage gate discards
// every tactic beneath it and the host reads as quiet.
func TestBufferProtectsLineageUnderBackPressure(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()

	// Fill it completely with file traffic, the way an agent's own config
	// reads do.
	for index := 0; index < eventBuffer; index++ {
		buffer.Push(Event{Kind: KindFileRead, Path: "/home/dev/.claude/settings.json"})
	}

	// More file traffic must not displace anything.
	buffer.Push(Event{Kind: KindFileRead, Path: "/home/dev/.claude/again.json"})

	// An exec must get in, because the tree depends on it.
	buffer.Push(Event{Kind: KindExec, PID: 4242, PPID: 1, Name: "claude"})

	events := buffer.Events()
	foundExec := false
	for drained := 0; drained < eventBuffer; drained++ {
		select {
		case event := <-events:
			if event.Kind == KindExec && event.Name == "claude" {
				foundExec = true
			}
		default:
			drained = eventBuffer
		}
	}
	if !foundExec {
		t.Fatal("an exec was dropped in favour of file reads: the process tree " +
			"loses the ancestor and every tactic below it becomes unattributable")
	}
	if buffer.Dropped() == 0 {
		t.Fatal("the buffer overflowed without counting a drop; reduced coverage " +
			"has to be reported, not absorbed")
	}
}

// cowork-1-0-8 GAP-0067 (S1 review 1 N1): an image digest that finds the
// buffer full displaces no exec or exit, and still reaches the consumer
// once there is room, ahead of the event that found the room.
func TestBufferKeepsTheTreeAndTheImageDigest(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		kind := KindExec
		if index%2 == 1 {
			kind = KindExit
		}
		buffer.Push(Event{Kind: kind, PID: index})
	}
	buffer.Push(Event{Kind: KindImageDigest, PID: 4242, ImageDigestState: DigestRead})
	if dropped := buffer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d with the digest kept for later", dropped)
	}
	events := buffer.Events()
	for index := 0; index < eventBuffer; index++ {
		if event := <-events; event.PID != index || !event.Kind.lineage() {
			t.Fatalf("event %d = %+v, want the tree's event %d in order", index, event, index)
		}
	}
	buffer.Push(Event{Kind: KindFileRead, PID: 7})
	if event := <-events; event.Kind != KindImageDigest || event.PID != 4242 {
		t.Fatalf("after room = %+v, want the kept digest", event)
	}
	if event := <-events; event.Kind != KindFileRead {
		t.Fatalf("then %+v, want the file read", event)
	}
	for index := 0; index <= maxLateDigests; index++ {
		for len(events) < eventBuffer {
			buffer.Push(Event{Kind: KindExec, PID: index})
		}
		buffer.Push(Event{Kind: KindImageDigest, PID: index})
	}
	if dropped := buffer.Dropped(); dropped != 1 {
		t.Fatalf("dropped %d past maxLateDigests kept digests, want 1", dropped)
	}
}

// S1 review 2 F1: a kept digest never takes the room an exec or exit that
// frees it needs; it follows that event.
func TestKeptImageDigestNeverDisplacesTheTree(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		kind := KindExec
		if index%2 == 1 {
			kind = KindExit
		}
		buffer.Push(Event{Kind: kind, PID: index})
	}
	buffer.Push(Event{Kind: KindImageDigest, PID: 4242})
	events := buffer.Events()
	if event := <-events; event.PID != 0 {
		t.Fatalf("first event %+v", event)
	}
	buffer.Push(Event{Kind: KindExec, PID: 9999})
	if dropped := buffer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d: the kept digest displaced a tree event", dropped)
	}
	for index := 1; index < eventBuffer; index++ {
		if event := <-events; event.PID != index || !event.Kind.lineage() {
			t.Fatalf("event %+v, want tree event %d in order", event, index)
		}
	}
	if event := <-events; event.PID != 9999 {
		t.Fatalf("last tree event %+v, want the exec that found room", event)
	}
	if kept := buffer.lateCount.Load(); kept != 1 {
		t.Fatalf("kept digests %d, want 1", kept)
	}
}

// TestBufferStillReportsEveryDrop keeps the counter honest for both classes.
func TestBufferStillReportsEveryDrop(t *testing.T) {
	t.Parallel()
	buffer := NewBuffer()
	for index := 0; index < eventBuffer; index++ {
		buffer.Push(Event{Kind: KindFileRead})
	}
	before := buffer.Dropped()
	buffer.Push(Event{Kind: KindFileRead})
	if buffer.Dropped() != before+1 {
		t.Fatalf("a refused file event was not counted: %d -> %d", before, buffer.Dropped())
	}
	buffer.Push(Event{Kind: KindExec})
	if buffer.Dropped() != before+2 {
		t.Fatalf("an eviction made room without being counted: %d", buffer.Dropped())
	}
}

// cowork-1-0-8 GAP-0072 (the class of GAP-0071): every host sensor source this
// OS builds (bufferedSources) names the events its own buffer dropped in its
// coverage, the same way, whatever dropped them: a file event at a full
// buffer, a process event displacing the oldest, an image digest past the
// late queue. A full buffer that dropped nothing is not a loss.
func TestEverySourceNamesItsBufferDropsInCoverage(t *testing.T) {
	sources := bufferedSources()
	if len(sources) == 0 {
		t.Fatal("no host sensor source listed for this OS")
	}
	for name, build := range sources {
		t.Run(name, func(t *testing.T) {
			source, buffer := build()
			before := source.Coverage()
			wantBufferDrops(t, before, 0)
			for index := 0; index < eventBuffer; index++ {
				buffer.Push(Event{Kind: KindFileRead, PID: index})
			}
			wantBufferDrops(t, source.Coverage(), 0)
			buffer.Push(Event{Kind: KindFileRead, PID: -1})
			wantBufferDrops(t, source.Coverage(), 1)
			buffer.Push(Event{Kind: KindExec, PID: -2})
			wantBufferDrops(t, source.Coverage(), 2)
			for index := 0; index <= maxLateDigests; index++ {
				buffer.Push(Event{Kind: KindImageDigest, PID: -3 - index})
			}
			after := source.Coverage()
			wantBufferDrops(t, after, 3)
			if again := source.Coverage(); !reflect.DeepEqual(again, after) {
				t.Fatalf("coverage changed between calls:\n%+v\n%+v", after, again)
			}
			if len(after.Limitations) != len(before.Limitations)+1 ||
				strings.Join(after.Limitations[:len(before.Limitations)], "\n") != strings.Join(before.Limitations, "\n") {
				t.Fatalf("limitations before the drops %q, after %q: want the same plus one drop line",
					before.Limitations, after.Limitations)
			}
		})
	}
}

// wantBufferDrops checks that coverage names exactly dropped buffer drops,
// in one line, or none when dropped is 0.
func wantBufferDrops(t *testing.T, coverage Coverage, dropped int64) {
	t.Helper()
	lines := 0
	for _, limitation := range coverage.Limitations {
		if strings.Contains(limitation, "dropped from the sensor's event buffer") {
			lines++
		}
	}
	joined := strings.Join(coverage.Limitations, "; ")
	switch {
	case dropped == 0 && lines != 0:
		t.Fatalf("limitations = %q, want no buffer drop line", joined)
	case dropped > 0 && (lines != 1 || !strings.Contains(joined, fmt.Sprintf(
		"%d events were dropped from the sensor's event buffer under back-pressure", dropped))):
		t.Fatalf("limitations = %q, want one line naming %d dropped events", joined, dropped)
	case coverage.BufferDropped != dropped:
		// The count the host plane carries across a restart (GAP-0080).
		t.Fatalf("BufferDropped = %d, want %d", coverage.BufferDropped, dropped)
	}
}

// cowork-1-0-8 GAP-0072 (review S5): TestEverySourceNamesItsBufferDropsInCoverage
// runs the sources each OS lists by hand, so a new source that forgot its
// drops was not caught. Every Coverage method of this package, whatever its
// build tags, calls WithBufferDrops, and so does every Coverage of the
// acquire package whose type owns a Buffer (the gateway's buffer for the
// helper stream): one function owns the line.
func TestEveryCoverageNamesItsBufferDrops(t *testing.T) {
	checked := map[string]bool{}
	for _, dir := range []string{".", "../acquire"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var files []*ast.File
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, file)
		}
		buffered := map[string]bool{}
		for _, file := range files {
			ast.Inspect(file, func(node ast.Node) bool {
				spec, ok := node.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if structType, ok := spec.Type.(*ast.StructType); ok {
					for _, field := range structType.Fields.List {
						if isBufferPointer(field.Type) {
							buffered[spec.Name.Name] = true
						}
					}
				}
				return false
			})
		}
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Name.Name != "Coverage" || fn.Body == nil ||
					len(fn.Type.Params.List) != 0 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 ||
					!isCoverageType(fn.Type.Results.List[0].Type) {
					continue
				}
				receiver := receiverName(fn.Recv.List[0].Type)
				if dir != "." && !buffered[receiver] {
					continue // a wrapper that passes another source's coverage on
				}
				checked[dir+":"+receiver] = true
				if !coverageNamesItsBufferDrops(fn) {
					t.Errorf("%s: (%s).Coverage does not name its buffer drops with WithBufferDrops on every return",
						fset.Position(fn.Pos()), receiver)
				}
			}
		}
	}
	for _, want := range []string{".:linuxSource", ".:tetragonSource", ".:darwinSource", ".:windowsSource", "../acquire:helperPlaneSource"} {
		if !checked[want] {
			t.Errorf("%s was not checked; checked %v", want, checked)
		}
	}
}

func isBufferPointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch x := star.X.(type) {
	case *ast.Ident:
		return x.Name == "Buffer"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Buffer"
	}
	return false
}

func isCoverageType(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name == "Coverage"
	case *ast.SelectorExpr:
		return x.Sel.Name == "Coverage"
	}
	return false
}

func receiverName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// coverageNamesItsBufferDrops reports whether every way out of fn, a
// Coverage method, gives a WithBufferDrops result: each return gives a
// WithBufferDrops call or a variable last assigned from one, or the method
// first defers a closure that sets its named result from one (Tetragon's
// form), before any return. One call on one path was not enough: the
// pre-fix Windows source returned its start coverage early when it had no
// reader (g072 review 2 S4).
func coverageNamesItsBufferDrops(fn *ast.FuncDecl) bool {
	named := ""
	if results := fn.Type.Results.List; len(results) == 1 && len(results[0].Names) == 1 {
		named = results[0].Names[0].Name
	}
	if named != "" {
		for _, stmt := range fn.Body.List {
			if containsReturn(stmt) {
				break // a return before the defer escapes it
			}
			if deferred, ok := stmt.(*ast.DeferStmt); ok && deferSetsWithBufferDrops(deferred, named) {
				return true
			}
		}
	}
	returns, every := 0, true
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if _, closure := node.(*ast.FuncLit); closure {
			return false
		}
		ret, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		var result ast.Expr
		switch {
		case len(ret.Results) == 1:
			result = ret.Results[0]
		case len(ret.Results) == 0 && named != "":
			result = ast.NewIdent(named)
		default:
			every = false
			return false
		}
		if !isWithBufferDropsCall(result) && !lastAssignedFromWithBufferDrops(fn.Body, result, ret.Pos()) {
			every = false
		}
		return false
	})
	return every && returns > 0
}

// isWithBufferDropsCall reports a call of WithBufferDrops or
// plane.WithBufferDrops.
func isWithBufferDropsCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "WithBufferDrops"
	case *ast.SelectorExpr:
		return fun.Sel.Name == "WithBufferDrops"
	}
	return false
}

// lastAssignedFromWithBufferDrops reports whether result is a variable whose
// last assignment in body before pos, in source order, is from a
// WithBufferDrops call.
func lastAssignedFromWithBufferDrops(body *ast.BlockStmt, result ast.Expr, pos token.Pos) bool {
	ident, ok := result.(*ast.Ident)
	if !ok {
		return false
	}
	var last ast.Expr
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil || node.Pos() >= pos {
			return false
		}
		if _, closure := node.(*ast.FuncLit); closure {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				if name, ok := lhs.(*ast.Ident); ok && name.Name == ident.Name {
					last = nil
					if len(stmt.Rhs) == len(stmt.Lhs) {
						last = stmt.Rhs[i]
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == ident.Name {
					last = nil
					if len(stmt.Values) == len(stmt.Names) {
						last = stmt.Values[i]
					}
				}
			}
		}
		return true
	})
	return last != nil && isWithBufferDropsCall(last)
}

// deferSetsWithBufferDrops reports a deferred closure that sets named from a
// WithBufferDrops call.
func deferSetsWithBufferDrops(deferred *ast.DeferStmt, named string) bool {
	closure, ok := deferred.Call.Fun.(*ast.FuncLit)
	if !ok {
		return false
	}
	for _, stmt := range closure.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name == named && isWithBufferDropsCall(assign.Rhs[0]) {
			return true
		}
	}
	return false
}

// containsReturn reports a return statement in stmt outside a closure.
func containsReturn(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = true
		}
		return !found
	})
	return found
}

// cowork-1-0-8 GAP-0080: the losses of replaced sources (buffer drops,
// kernel overflows, the backend's events lost) add to the running source's:
// drops and overflows in one line each of their own, the backend's in
// events_lost. Nothing is added when there are none, nothing is changed in
// place, and a coverage without a backend shows no backend loss.
func TestWithRetiredLosses(t *testing.T) {
	start := Coverage{Mechanism: "m", Limitations: []string{"start limitation"},
		Backend: &Backend{Kind: BackendTetragon, EventsLost: 4}}
	current := WithBufferDrops(WithKernelOverflows(start, 1), 2, HelperStreamBuffer)
	if got := current.Losses(); got != (Losses{BufferDropped: 2, KernelOverflows: 1, BackendLost: 4}) {
		t.Fatalf("losses = %+v", got)
	}
	if got := WithRetiredLosses(current, Losses{}); !reflect.DeepEqual(got, current) {
		t.Fatalf("no retired losses changed the coverage: %+v", got)
	}
	retired := Losses{BufferDropped: 3}.Add(Losses{KernelOverflows: 5, BackendLost: 6})
	got := WithRetiredLosses(current, retired)
	want := []string{
		"start limitation",
		"process events were lost 1 times when the netlink receive buffer overflowed (ENOBUFS)",
		"2 events were dropped from the gateway's event buffer for the sensor helper's stream under back-pressure " +
			"(file events first; process events displaced the oldest)",
		"3 events were dropped under back-pressure in earlier event streams of the sensor",
		"process events were lost 5 times when the netlink receive buffer overflowed (ENOBUFS) in earlier event streams of the sensor",
	}
	if !reflect.DeepEqual(got.Limitations, want) {
		t.Fatalf("limitations\n %q\nwant\n %q", got.Limitations, want)
	}
	if got.Losses() != (Losses{BufferDropped: 5, KernelOverflows: 6, BackendLost: 10}) {
		t.Fatalf("losses with the retired = %+v", got.Losses())
	}
	if len(current.Limitations) != 3 || len(start.Limitations) != 1 || start.Backend.EventsLost != 4 ||
		current.Backend.EventsLost != 4 {
		t.Fatalf("changed in place: %q, %q, events lost %d", start.Limitations, current.Limitations, start.Backend.EventsLost)
	}
	bare := WithRetiredLosses(Coverage{Mechanism: "cn_proc"}, Losses{BackendLost: 6})
	if bare.Backend != nil || len(bare.Limitations) != 0 {
		t.Fatalf("a coverage without a backend = %+v", bare)
	}
}

// WithKernelOverflows names the ENOBUFS overflows and counts them, without
// changing the limitations it was given.
func TestWithKernelOverflows(t *testing.T) {
	start := Coverage{Limitations: []string{"start limitation"}}
	if got := WithKernelOverflows(start, 0); !reflect.DeepEqual(got, start) {
		t.Fatalf("no overflow changed the coverage: %+v", got)
	}
	got := WithKernelOverflows(WithKernelOverflows(start, 2), 0)
	if got.KernelOverflows != 2 || len(got.Limitations) != 2 ||
		got.Limitations[1] != "process events were lost 2 times when the netlink receive buffer overflowed (ENOBUFS)" ||
		len(start.Limitations) != 1 {
		t.Fatalf("overflows = %+v (start %q)", got, start.Limitations)
	}
}

// The check itself: a Coverage without the call is caught, and so is one
// that calls it on one path and returns early on another (the pre-fix
// Windows shape); every return through it, a variable last assigned from it,
// and a deferred closure set before any return (Tetragon's) are not.
func TestCallsWithBufferDrops(t *testing.T) {
	for source, want := range map[string]bool{
		`package p; func (s *x) Coverage() Coverage { return s.coverage }`:                                                    false,
		`package p; func (s *x) Coverage() Coverage { return WithBufferDrops(s.coverage, 1, SensorEventBuffer) }`:             true,
		`package p; func (s *x) Coverage() (c Coverage) { defer func() { c = WithBufferDrops(c, 1, "b") }(); return }`:        true,
		`package p; func (s *x) Coverage() plane.Coverage { return plane.WithBufferDrops(s.c, 1, plane.HelperStreamBuffer) }`: true,
		// g072 review 2 S4: a planted early return.
		`package p; func (s *x) Coverage() Coverage { c := s.coverage; if s.reader == nil { return c }; return WithBufferDrops(c, 1, SensorEventBuffer) }`: false,
		`package p; func (s *x) Coverage() Coverage { if s.reader == nil { return s.coverage }; return WithBufferDrops(s.coverage, 1, "b") }`:              false,
		`package p; func (s *x) Coverage() Coverage { c := WithBufferDrops(s.c, 1, "b"); return c }`:                                                       true,
		`package p; func (s *x) Coverage() Coverage { var c = WithBufferDrops(s.c, 1, "b"); return c }`:                                                    true,
		`package p; func (s *x) Coverage() Coverage { c := WithBufferDrops(s.c, 1, "b"); c = s.c; return c }`:                                              false,
		`package p; func (s *x) Coverage() (c Coverage) { if s.r == nil { return s.c }; defer func() { c = WithBufferDrops(c, 1, "b") }(); return }`:       false,
		`package p; func (s *x) Coverage() (c Coverage) { c = s.c; return }`:                                                                               false,
		`package p; func (s *x) Coverage() (c Coverage) { c = WithBufferDrops(s.c, 1, "b"); return }`:                                                      true,
		`package p; func (s *x) Coverage() Coverage { f := func() Coverage { return s.c }; _ = f; return WithBufferDrops(s.c, 1, "b") }`:                   true,
		`package p; func (s *x) Coverage() Coverage { for { } }`:                                                                                           false,
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "x.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := coverageNamesItsBufferDrops(file.Decls[0].(*ast.FuncDecl)); got != want {
			t.Errorf("coverageNamesItsBufferDrops(%s) = %t, want %t", source, got, want)
		}
	}
	if !isBufferPointer(&ast.StarExpr{X: &ast.SelectorExpr{X: ast.NewIdent("plane"), Sel: ast.NewIdent("Buffer")}}) {
		t.Error("*plane.Buffer is not a buffer field")
	}
	if _, err := os.Stat("plane.go"); err != nil {
		t.Fatalf("the source check runs in the plane directory: %v", err)
	}
}
