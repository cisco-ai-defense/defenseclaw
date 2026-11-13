// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// Probe shapes of the reading budget (GAP-0254, GAP-0255): each is a small
// template repeated to the size under test, so no test file holds a huge
// literal.
var budgetShapes = map[string]struct{ unit, tail string }{
	"pipe":      {"a|", "a"},
	"or":        {"a||", "a"},
	"and":       {"a&&", "a"},
	"mixed":     {"a|b&&c||", "d"},
	"semi":      {"a;", "a"},
	"words":     {"a ", ""},
	"stmts":     {"a\n", "a"},
	"hugeWord":  {"aaaaaaaaaaaaaaaa", ""},
	"nestParen": {"(", "a" + strings.Repeat(")", 0)},
}

func budgetCommand(shape string, n int) string {
	s := budgetShapes[shape]
	return strings.Repeat(s.unit, n) + s.tail
}

// measure returns the bytes allocated and the time the call took.
func measure(call func()) (alloc uint64, took time.Duration) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	call()
	took = time.Since(start)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, took
}

// TestChainOperatorBudgetIsExact pins the bound: a chain of MaxChainOperators
// nodes reads; one more is past the budget, whatever the shape; and a
// past-budget command is never parsed (Parse reports false at once, with no
// tree, however large). It holds on both sides of MaxChainOperatorBytes,
// where the text is refused without a parse.
func TestChainOperatorBudgetIsExact(t *testing.T) {
	for _, shape := range []string{"pipe", "and", "or"} {
		within := budgetCommand(shape, MaxChainOperators)
		if reason := BudgetExceeded(within); reason != "" {
			t.Errorf("%s at the bound: BudgetExceeded=%q", shape, reason)
		}
		if _, ok := Parse(within); !ok {
			t.Errorf("%s at the bound does not parse", shape)
		}
		// Measured on the tree (5,000 nodes), and refused unparsed
		// (200,000 or more).
		for _, n := range []int{MaxChainOperators + 1, 16000, 200000} {
			past := budgetCommand(shape, n)
			if reason := BudgetExceeded(past); reason != BudgetChain {
				t.Errorf("%s n=%d past the bound: BudgetExceeded=%q, want %q", shape, n, reason, BudgetChain)
			}
			if !TooDeep(past) {
				t.Errorf("%s n=%d past the bound: TooDeep=false", shape, n)
			}
			if file, ok := Parse(past); ok || file != nil {
				t.Errorf("%s n=%d past the bound was parsed", shape, n)
			}
		}
	}
}

// TestChainBytesInTextAreNotAChain pins that a here-document of text with
// far more | and && bytes than the bound is not a chain: its tree has one
// statement, so the reading bound does not fire on it (a script or a patch
// written through a here-document).
func TestChainBytesInTextAreNotAChain(t *testing.T) {
	for _, line := range []string{"d | e\n", "a && b || c\n"} {
		command := "cat > notes.txt <<'EOF'\n" + strings.Repeat(line, 2*MaxChainOperators) + "EOF\n"
		if reason := BudgetExceeded(command); reason != "" {
			t.Errorf("%q: BudgetExceeded=%q", line, reason)
		}
		if _, ok := Parse(command); !ok {
			t.Errorf("%q: the here-document does not parse", line)
		}
	}
}

// TestProbeShapesAreBoundedInTimeAndMemory runs the two P1 probe shapes of
// the gateway (a 67 KB pipeline of 33,577 stages, a 499 KB left-deep list
// of 166,443 ||) and variants through the reading budget and the parser:
// each answers within a bound of time and memory, and none crashes. Before
// the budget the list killed the process with a stack overflow in the copy
// of the parse cache. A chain is refused before its parse (a few MiB); a
// flat command is parsed once (linear, about 300 bytes for each byte of its
// text) and measured on its nodes.
func TestProbeShapesAreBoundedInTimeAndMemory(t *testing.T) {
	const window = 2 * time.Second
	for _, row := range []struct {
		shape  string
		n      int
		memory uint64
	}{
		{"pipe", 33577, 16 << 20}, {"or", 166443, 16 << 20}, {"and", 166443, 16 << 20}, {"mixed", 100000, 16 << 20},
		{"semi", 300000, 512 << 20}, {"stmts", 300000, 512 << 20}, {"words", 400000, 512 << 20}, {"hugeWord", 60000, 128 << 20},
	} {
		command := budgetCommand(row.shape, row.n)
		alloc, took := measure(func() {
			BudgetExceeded(command)
			Parse(command)
			ParseWithComments(command)
		})
		if alloc > row.memory || took > window {
			t.Errorf("%s n=%d (%d bytes): %d MiB allocated in %s", row.shape, row.n, len(command), alloc>>20, took)
		}
	}
}

// TestParsedNodeBudget pins the node bound of a large command: flat words
// and statements past MaxParsedNodes read as unparseable (BudgetNodes), a
// long here-document or one huge word does not (it is a handful of nodes),
// and a command below largeCommandMin bytes is never measured.
func TestParsedNodeBudget(t *testing.T) {
	for _, row := range []struct {
		name, command string
		reason        string
	}{
		{"flat words", "echo " + strings.Repeat("a ", MaxParsedNodes/2), BudgetNodes},
		{"flat statements", strings.Repeat("a;", MaxParsedNodes/2), BudgetNodes},
		{"long here-document", "cat <<'EOF'\n" + strings.Repeat("plain line of text\n", 50000) + "EOF\n", ""},
		{"huge single word", "echo " + strings.Repeat("a", 1<<20-16), ""},
		{"below the measured size", "echo " + strings.Repeat("a ", 30000), ""},
	} {
		if got := BudgetExceeded(row.command); got != row.reason {
			t.Errorf("%s (%d bytes): BudgetExceeded=%q, want %q", row.name, len(row.command), got, row.reason)
		}
		_, ok := Parse(row.command)
		if ok != (row.reason == "") {
			t.Errorf("%s: Parse ok=%t with reason %q", row.name, ok, row.reason)
		}
	}
}

// TestCloneFileStopsAtDepth pins the copy of the parse cache: a tree
// deeper than maxCloneDepth (built node by node, which no command can reach
// through the budget) is refused with false instead of recursing until the
// goroutine stack overflows, which is fatal and cannot be recovered.
func TestCloneFileStopsAtDepth(t *testing.T) {
	leaf := &syntax.Stmt{Cmd: &syntax.CallExpr{}}
	deep := leaf
	for range maxCloneDepth / 4 {
		deep = &syntax.Stmt{Cmd: &syntax.BinaryCmd{Op: syntax.OrStmt, X: deep, Y: leaf}}
	}
	if _, ok := cloneFile(&syntax.File{Stmts: []*syntax.Stmt{deep}}); ok {
		t.Fatal("a tree past maxCloneDepth was copied")
	}
	shallow := &syntax.Stmt{Cmd: &syntax.BinaryCmd{Op: syntax.OrStmt, X: leaf, Y: leaf}}
	if copied, ok := cloneFile(&syntax.File{Stmts: []*syntax.Stmt{shallow}}); !ok || copied == nil {
		t.Fatal("a shallow tree was not copied")
	}
	// A command at the chain bound is far below maxCloneDepth and is cached.
	command := budgetCommand("or", MaxChainOperators/2) + strings.Repeat(" ", largeCommandMin)
	if _, ok := Parse(command); !ok {
		t.Fatal("a large command at the chain bound does not parse")
	}
	parseCache.Lock()
	kept := false
	for _, entry := range parseCache.entries {
		kept = kept || entry.key.command == command
	}
	parseCache.Unlock()
	if !kept {
		t.Fatal("a large command at the chain bound was not kept")
	}
}

// TestBudgetScalesLinearly doubles the size of each probe shape inside the
// budget and asserts allocation grows at most about three times (a quadratic
// reader grows four times or more).
func TestBudgetScalesLinearly(t *testing.T) {
	for _, shape := range []string{"pipe", "and", "semi", "words"} {
		small, large := budgetCommand(shape, 1500), budgetCommand(shape, 3000)
		smallAlloc, _ := measure(func() { Parse(small) })
		largeAlloc, _ := measure(func() { Parse(large) })
		if smallAlloc > 0 && largeAlloc > 3*smallAlloc+(1<<20) {
			t.Errorf("%s: %d KiB for 1500 units, %d KiB for 3000", shape, smallAlloc>>10, largeAlloc>>10)
		}
	}
}

// FuzzBudget generates large commands from the probe templates (and takes
// raw text as well) and asserts the invariants of the budget: it answers,
// a command past the budget is never parsed, and a command within it parses
// to a tree the copy of the parse cache can copy.
func FuzzBudget(f *testing.F) {
	for shape := range budgetShapes {
		f.Add(shape, uint32(1000), "")
	}
	f.Add("pipe", uint32(166443), "tail")
	f.Fuzz(func(t *testing.T, shape string, n uint32, extra string) {
		command := extra
		if _, known := budgetShapes[shape]; known {
			command = budgetCommand(shape, int(n%400000)) + extra
		}
		reason := BudgetExceeded(command)
		file, ok := Parse(command)
		if reason != "" && (ok || file != nil) {
			t.Fatalf("a command past the budget (%s) was parsed", reason)
		}
		if ok {
			if _, cloned := cloneFile(file); !cloned {
				t.Fatal("a parsed command could not be copied")
			}
		}
	})
}
