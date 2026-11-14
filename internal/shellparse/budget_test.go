// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// budgetShape is a family of generated command text: head, then unit
// repeated n times, then tail. Every input of these tests is built from the
// table and a size; none is stored.
type budgetShape struct{ head, unit, tail string }

var budgetShapes = map[string]budgetShape{
	"pipe":       {"", "a|", "a"},
	"and":        {"", "a&&", "a"},
	"or":         {"", "a||", "a"},
	"mixed":      {"", "a|b&&c||", "d"},
	"subst":      {"", "$(a)|", "a"},
	"group":      {"", "(a)|", "a"},
	"semi":       {"", "a;", "a"},
	"words":      {"echo ", "a ", ""},
	"arith":      {"echo $((1", "+1", "))"},
	"heredoc":    {"cat > f <<'EOF'\n", "d | e && f\n", "EOF\n"},
	"heredoc-q":  {"cat > f <<'EOF'\n", "d | e\n", "EOF\n"},
	"heredoc-u":  {"cat > f <<EOF\n", "d | e\n", "EOF\n"},
	"heredoc-s":  {"cat > f <<EOF\n", "d | $(e)\n", "EOF\n"},
	"heredoc-d":  {"cat <<-'EOF'\n", "\td | e\n", "\tEOF\n"},
	"squote":     {"echo '", "a|a&&", "'"},
	"comment":    {"echo a # ", "a|", "\n"},
	"hugeword":   {"echo ", "aaaaaaaaaaaaaaaa", ""},
	"unparsed":   {"", "a|", "fi"},
	"wrapped":    {"(((", "a|", "a"},
	"background": {"", "a&", "a"},
}

func (s budgetShape) command(n int) string {
	return s.head + strings.Repeat(s.unit, n) + s.tail
}

func shape(name string, n int) string { return budgetShapes[name].command(n) }

// cost is what a call spent: the bytes and the heap objects it allocated
// (both counted by the runtime, so they do not depend on the host) and the
// wall time it took (which does).
type cost struct {
	alloc, mallocs uint64
	took           time.Duration
}

func measureCost(call func()) cost {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	call()
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	return cost{after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs, took}
}

// measure returns the bytes allocated and the time the call took.
func measure(call func()) (alloc uint64, took time.Duration) {
	c := measureCost(call)
	return c.alloc, c.took
}

// The bounds of these tests are counts first: the bytes and the heap objects
// a call allocates, which the runtime counts and no host changes. A refused
// text allocates a handful of objects and a parse of the same text allocates
// one or more per node, so a count bound says whether the reader parsed.
// The time is a guard against a stall or a runaway loop, and it is read
// against the host that runs the test: the same calls on a reference command,
// a fixed in-budget text of a few KB, give the cost of one byte of a full
// parse on this host in this process (-race, coverage and a loaded or small
// runner included), and a bound is timeFactor times that cost per byte of the
// command. A refusal or a parse of a flat text is a fraction of the
// reference per byte on every host, so the factor leaves a wide margin
// where a shared runner is 50 times slower than the dev host (a fixed
// second does not, and failed on one: PR 1457, shard 9).
const (
	timeFactor     = 10
	timeFloor      = 100 * time.Millisecond
	referenceUnits = 2000 // 4 KB of "words"
	referenceRuns  = 3
	refusalObjects = 256  // objects of a refusal: a handful
	probeObjects   = 2048 // objects of a probe: a refusal, or the parse of one long word
)

// timeBound is the most a call over bytes of text may take on this host.
func timeBound(bytes int, call func(command string)) time.Duration {
	best := time.Duration(-1)
	var size int
	for run := range referenceRuns {
		// Each run is a text of its own: a repeated text is a parse-cache hit.
		command := shape("words", referenceUnits+run)
		size = len(command)
		c := measureCost(func() { call(command) })
		if best < 0 || c.took < best {
			best = c.took
		}
	}
	return timeFloor + time.Duration(float64(best)/float64(size)*float64(bytes)*timeFactor)
}

// readAll is the work of the probes: the budget, then both parses.
func readAll(command string) {
	BudgetExceeded(command)
	Parse(command)
	ParseWithComments(command)
}

// TestChainBudgetIsExact pins the chain bound on its tree: a chain of
// MaxChainOperators nodes reads, one more is past the budget, whatever the
// operator, and a past-budget command is never parsed.
func TestChainBudgetIsExact(t *testing.T) {
	for _, name := range []string{"pipe", "and", "or", "subst", "group"} {
		within := shape(name, MaxChainOperators)
		if reason := BudgetExceeded(within); reason != "" {
			t.Errorf("%s at the bound: BudgetExceeded=%q", name, reason)
		}
		if _, ok := Parse(within); !ok {
			t.Errorf("%s at the bound does not parse", name)
		}
		for _, n := range []int{MaxChainOperators + 1, 2000, MaxChainBytes + 1, 100000} {
			past := shape(name, n)
			if reason := BudgetExceeded(past); reason != BudgetChain {
				t.Errorf("%s n=%d: BudgetExceeded=%q, want %q", name, n, reason, BudgetChain)
			}
			if file, ok := Parse(past); ok || file != nil {
				t.Errorf("%s n=%d was parsed", name, n)
			}
			if !TooDeep(past) {
				t.Errorf("%s n=%d: TooDeep=false", name, n)
			}
		}
	}
}

// TestChainBytesFollowTheParser pins the first stage against the lexer: the
// parser skips a NUL byte and a line continuation, so two & with one between
// them are one && (found by FuzzBudget: the tree held a chain node the first
// stage counted none for). The first stage never counts fewer chain bytes
// than the tree has chain nodes.
func TestChainBytesFollowTheParser(t *testing.T) {
	for _, between := range []string{"", "\x00", "\\\n", "\x00\x00"} {
		command := "a&" + between + "&b"
		file, ok := Parse(command)
		if !ok {
			continue
		}
		if _, aware, _, _ := scanCounts(command); aware.chain < treeChain(file) {
			t.Errorf("%q: %d chain bytes, tree has %d chain nodes", command, aware.chain, treeChain(file))
		}
	}
}

// TestUnparsedChainIsOverTheBudget pins GAP-0284: a chain past the soft
// bound that cannot be parsed (a syntax error, a wrapper that fails) has no
// tree to measure and is over the budget, not within it.
func TestUnparsedChainIsOverTheBudget(t *testing.T) {
	for _, name := range []string{"unparsed", "wrapped"} {
		for _, n := range []int{MaxChainOperators + 1, 5000, MaxChainBytes} {
			if reason := BudgetExceeded(shape(name, n)); reason != BudgetUnparsed && reason != BudgetChain {
				t.Errorf("%s n=%d: BudgetExceeded=%q, want an over-budget reason", name, n, reason)
			}
		}
		if reason := BudgetExceeded(shape(name, 100)); reason != "" {
			t.Errorf("%s n=100: BudgetExceeded=%q, want within", name, reason)
		}
	}
}

// TestTreeBudgetCoversEveryTreeKind pins the node and depth bounds on trees
// that are not chains: flat words and statements (nodes), and arithmetic
// (depth, GAP-0285).
func TestTreeBudgetCoversEveryTreeKind(t *testing.T) {
	for _, row := range []struct {
		name   string
		n      int
		reason string
	}{
		{"words", 3000, ""},
		{"words", 20000, BudgetNodes},
		{"semi", 2000, ""},
		{"semi", 12000, BudgetNodes},
		{"semi", 4000, ""},
		{"arith", MaxTreeDepth/2 - 10, ""},
		{"arith", MaxTreeDepth + 100, BudgetDepth},
		{"arith", 9000, BudgetDepth},
		{"heredoc", 3 * MaxChainOperators, ""},
		// The first stage counts what the shell parses, not data (the P3
		// of the review: base reads these in full).
		{"heredoc-q", 100000, ""},
		{"heredoc-u", 100000, ""},
		{"heredoc-d", 100000, ""},
		{"squote", 20000, ""},
		{"comment", 60000, ""},
		// A here-document that expands a command substitution is code.
		{"heredoc-s", 20000, BudgetChain},
		{"hugeword", 20000, ""},
	} {
		command := shape(row.name, row.n)
		if got := BudgetExceeded(command); got != row.reason {
			t.Errorf("%s n=%d (%d bytes): BudgetExceeded=%q, want %q", row.name, row.n, len(command), got, row.reason)
		}
		if _, ok := Parse(command); ok != (row.reason == "") {
			t.Errorf("%s n=%d: Parse ok=%t with reason %q", row.name, row.n, ok, row.reason)
		}
	}
}

// TestHardBoundsRefuseWithoutAParse pins the bounds of the first stage: a
// text past MaxCommandBytes, MaxChainBytes or MaxWords is refused whatever
// it holds, and the check costs a linear pass: no parse (a handful of
// objects) and a time within a multiple of the reference parse.
func TestHardBoundsRefuseWithoutAParse(t *testing.T) {
	for _, row := range []struct {
		name, command, reason string
	}{
		{"bytes", "echo " + strings.Repeat("a", MaxCommandBytes), BudgetBytes},
		{"tokens", "echo " + strings.Repeat("a ", MaxTokens), BudgetTokens},
		{"statements", strings.Repeat("a;", MaxTokens/2+1), BudgetTokens},
		{"heredoc raw bound", shape("heredoc-q", rawChainBytes+1), BudgetChain},
		{"nesting", strings.Repeat("(", MaxNestingDepth+1) + "a", BudgetNesting},
	} {
		bound := timeBound(len(row.command), readAll)
		spent := measureCost(func() {
			if got := BudgetExceeded(row.command); got != row.reason {
				t.Errorf("%s: BudgetExceeded=%q, want %q", row.name, got, row.reason)
			}
		})
		t.Logf("%s: %d bytes, %d KiB in %d objects, %s (bound %s)", row.name, len(row.command), spent.alloc>>10, spent.mallocs, spent.took, bound)
		if spent.alloc > 4<<20 || spent.mallocs > refusalObjects || spent.took > bound {
			t.Errorf("%s: %d KiB in %d objects allocated in %s (bound %s)", row.name, spent.alloc>>10, spent.mallocs, spent.took, bound)
		}
	}
}

// TestProbeShapesAreBoundedInTimeAndMemory runs the probes of the gateway
// (a pipeline of 33,577 stages, a left-deep list of 166,443 ||) and every
// family at sizes far past the budget through the budget and the parser:
// each is decided within a few MiB and a few objects (counts, which no host
// changes) and within a multiple of the cost of a reference parse on this
// host, and none crashes. Before the budget the list killed the process with
// a stack overflow in the copy of the parse cache. The bounds hold under
// -race on a loaded or small runner.
func TestProbeShapesAreBoundedInTimeAndMemory(t *testing.T) {
	for name, n := range map[string]int{
		"pipe": 33577, "or": 166443, "and": 166443, "mixed": 100000, "subst": 50000, "group": 50000,
		"semi": 300000, "words": 400000, "arith": 300000, "hugeword": 60000, "unparsed": 100000, "wrapped": 60000,
		"background": 200000, "heredoc": 100000,
	} {
		command := shape(name, n)
		bound := timeBound(len(command), readAll)
		spent := measureCost(func() { readAll(command) })
		t.Logf("%s n=%d (%d bytes): %d KiB in %d objects, %s (bound %s)", name, n, len(command), spent.alloc>>10, spent.mallocs, spent.took, bound)
		if spent.alloc > 24<<20 || spent.mallocs > probeObjects || spent.took > bound {
			t.Errorf("%s n=%d (%d bytes): %d MiB in %d objects allocated in %s (bound %s)", name, n, len(command), spent.alloc>>20, spent.mallocs, spent.took, bound)
		}
	}
}

// TestBudgetCostGrowsLinearly doubles each family inside the budget and
// asserts allocation grows at most about three times (a quadratic reader
// grows four times or more).
func TestBudgetCostGrowsLinearly(t *testing.T) {
	for name, n := range map[string]int{"pipe": 120, "and": 120, "subst": 120, "words": 800, "semi": 800, "heredoc": 800} {
		small, large := shape(name, n), shape(name, 2*n)
		smallAlloc, _ := measure(func() { Parse(small) })
		largeAlloc, _ := measure(func() { Parse(large) })
		if largeAlloc > 3*smallAlloc+(1<<20) {
			t.Errorf("%s: %d KiB for %d units, %d KiB for %d", name, smallAlloc>>10, n, largeAlloc>>10, 2*n)
		}
	}
}

// TestCloneFileDoesNotRecurse pins the copy of the parse cache: a tree
// 200,000 levels deep (built node by node; no command passes the budget
// with one) is copied under a 1 MiB goroutine stack limit, where a
// recursive copy dies with a fatal stack overflow that nothing recovers.
func TestCloneFileDoesNotRecurse(t *testing.T) {
	const depth = 200000
	leaf := &syntax.Stmt{Cmd: &syntax.CallExpr{}}
	deep := leaf
	for range depth {
		deep = &syntax.Stmt{Cmd: &syntax.BinaryCmd{Op: syntax.OrStmt, X: deep, Y: leaf}}
	}
	old := debug.SetMaxStack(1 << 20)
	defer debug.SetMaxStack(old)
	copied := cloneFile(&syntax.File{Stmts: []*syntax.Stmt{deep}})
	levels := 0
	for stmt, original := copied.Stmts[0], deep; ; levels++ {
		binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
		if !ok {
			break
		}
		if stmt == original || binary == original.Cmd {
			t.Fatalf("level %d shares a node with the original", levels)
		}
		stmt, original = binary.X, original.Cmd.(*syntax.BinaryCmd).X
	}
	if levels != depth {
		t.Fatalf("the copy has %d levels, want %d", levels, depth)
	}
}

// TestMeasureTreeDoesNotRecurse pins the measure of the budget the same
// way: a tree far deeper than any stack limit is measured, and reported,
// without recursion.
func TestMeasureTreeDoesNotRecurse(t *testing.T) {
	leaf := &syntax.Stmt{Cmd: &syntax.CallExpr{}}
	deep := leaf
	for range 100000 {
		deep = &syntax.Stmt{Cmd: &syntax.BinaryCmd{Op: syntax.Pipe, X: deep, Y: leaf}}
	}
	old := debug.SetMaxStack(1 << 20)
	defer debug.SetMaxStack(old)
	if got := measureTree(&syntax.File{Stmts: []*syntax.Stmt{deep}}); got == "" {
		t.Fatal("a 100,000-level tree was within the budget")
	}
}

// TestBudgetAnswersAreStableAcrossTheMemo asks about more distinct texts
// than the memo holds, in turn, and expects the same answer every time.
func TestBudgetAnswersAreStableAcrossTheMemo(t *testing.T) {
	var commands []string
	want := map[string]string{}
	for i, name := range []string{"pipe", "or", "subst", "words", "arith", "heredoc", "semi", "unparsed", "group", "and", "mixed"} {
		command := shape(name, 700+i)
		commands = append(commands, command)
		want[command] = computeBudget(command)
	}
	for range 3 {
		for _, command := range commands {
			if got := BudgetExceeded(command); got != want[command] {
				t.Fatalf("%.20q (%d bytes): %q then %q", command, len(command), want[command], got)
			}
		}
	}
}

// treeChain counts the chain nodes of file.
func treeChain(file *syntax.File) int {
	chain := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if binary, ok := node.(*syntax.BinaryCmd); ok {
			switch binary.Op {
			case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
				chain++
			}
		}
		return true
	})
	return chain
}

// FuzzBudget generates large commands from the family table (and takes raw
// text as well) and asserts the invariants of the budget: it answers; a
// command past the budget is never parsed; a command within it parses to a
// tree the copy of the parse cache can copy and the measure accepts.
func FuzzBudget(f *testing.F) {
	for name := range budgetShapes {
		f.Add(name, uint32(1000), "")
	}
	f.Add("pipe", uint32(166443), "tail")
	f.Fuzz(func(t *testing.T, name string, n uint32, extra string) {
		command := extra
		if s, known := budgetShapes[name]; known {
			command = s.command(int(n%200000)) + extra
		}
		reason := BudgetExceeded(command)
		file, ok := Parse(command)
		if reason != "" && (ok || file != nil) {
			t.Fatalf("a command past the budget (%s) was parsed", reason)
		}
		if ok {
			if cloneFile(file) == nil {
				t.Fatal("a parsed command could not be copied")
			}
			got := measureTree(file)
			if reason == "" && got != "" {
				t.Fatalf("a command within the budget measures as %q", got)
			}
			// The first stage never counts fewer chain operators than the
			// tree holds (its reading of data may skip real code only up to
			// the raw bound, which this check does not excuse).
			if _, aware, _, nesting := scanCounts(command); nesting == "" && aware.chain < treeChain(file) {
				t.Fatalf("the first stage counts %d chain bytes but the tree has %d chain nodes", aware.chain, treeChain(file))
			}
			// The soft bounds hold: a text under both is never past a
			// tree bound, so it is not parsed to find out.
			if chain := strings.Count(command, "|") + strings.Count(command, "&&"); got != "" && len(command) <= softBytes && chain <= softChainBytes {
				t.Fatalf("a %d-byte command with %d chain bytes measures as %q but the first stage passes it", len(command), chain, got)
			}
		}
	})
}
