// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// functionFirstCallsReference is functionFirstCalls as rel/1.0.11
// dfb6d9c707 had it: every call read for every function. The by-name index
// must give the same answer on every scan (substrate-1 GAP-1153).
func (scan *commandPathScan) functionFirstCallsReference() []int {
	outer := make([]int, len(scan.calls))
	for index, call := range scan.calls {
		outer[index] = scan.functionAt(call.start)
	}
	first := make([]int, len(scan.functions))
	const (
		unread = iota
		reading
		read
	)
	state := make([]int, len(scan.functions))
	var firstCall func(function int) int
	firstCall = func(function int) int {
		switch state[function] {
		case reading:
			return -1
		case read:
			return first[function]
		}
		state[function] = reading
		named, unnamed := -1, -1
		for index, call := range scan.calls {
			if call.name != "" && call.name != scan.functions[function].name {
				continue
			}
			start := call.start
			if outer[index] >= 0 {
				if start = firstCall(outer[index]); start < 0 {
					continue
				}
			}
			if start < scan.functions[function].body[1] {
				continue
			}
			if call.name == "" {
				if unnamed < 0 || start < unnamed {
					unnamed = start
				}
			} else if named < 0 || start < named {
				named = start
			}
		}
		if named < 0 {
			named = unnamed
		}
		first[function], state[function] = named, read
		return named
	}
	for function := range scan.functions {
		firstCall(function)
	}
	return first
}

// gap1153Script is a random script of function definitions (nested,
// redefined, recursive, mutually recursive), named and dynamic calls, eval
// and sh -c bodies, loops and directory changes.
func gap1153Script(r *rand.Rand, depth int) string {
	names := []string{"f", "g", "h", "k", "run", "f"}
	var parts []string
	for n := r.Intn(9) + 1; n > 0; n-- {
		name := names[r.Intn(len(names))]
		switch r.Intn(11) {
		case 0, 1:
			body := "cat keylink"
			if depth < 3 && r.Intn(2) == 0 {
				body = gap1153Script(r, depth+1)
			}
			parts = append(parts, fmt.Sprintf("%s() { %s; }", name, body))
		case 2, 3:
			parts = append(parts, name)
		case 4:
			parts = append(parts, "$C")
		case 5:
			parts = append(parts, "cd /tmp")
		case 6:
			if depth < 3 {
				parts = append(parts, fmt.Sprintf("eval %q", gap1153Script(r, depth+1)))
			} else {
				parts = append(parts, "eval $C")
			}
		case 7:
			if depth < 3 {
				parts = append(parts, fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(gap1153Script(r, depth+1), "'", "")))
			} else {
				parts = append(parts, name)
			}
		case 8:
			parts = append(parts, fmt.Sprintf("for i in 1; do %s; done", name))
		case 9:
			parts = append(parts, "source ./x")
		default:
			parts = append(parts, "cp /tmp/x keylink")
		}
	}
	seps := []string{"; ", " && ", "\n", " || ", " | "}
	out := parts[0]
	for _, part := range parts[1:] {
		out += seps[r.Intn(len(seps))] + part
	}
	return out
}

func TestGAP1153FunctionFirstCallsMatchReference(t *testing.T) {
	r := rand.New(rand.NewSource(1153))
	scripts := []string{
		"f() { cat keylink; }; cd /tmp; f",
		"f() { g; }; g() { f; }; f; g",
		"f() { cat a; }; $C; f() { cat b; }; f",
		"eval 'f() { cat keylink; }'; cd /tmp; f",
	}
	for k := 0; k < 550; k += 50 {
		scripts = append(scripts, strings.Repeat("$C;", 2)+fmt.Sprintf("f%d(){ :;};f%d;", k, k))
	}
	for len(scripts) < 4000 {
		scripts = append(scripts, gap1153Script(r, 0))
	}
	scanned := 0
	for _, script := range scripts {
		var scan commandPathScan
		commandPathWordsIn(script, 0, 0, 0, "/home/u", &scan)
		if len(scan.functions) > 0 {
			scanned++
		}
		got, want := scan.functionFirstCalls(), scan.functionFirstCallsReference()
		if !slices.Equal(got, want) {
			t.Fatalf("functionFirstCalls(%q) = %v, rel reading %v", script, got, want)
		}
	}
	if scanned < 2000 {
		t.Fatalf("only %d of %d scripts define a function", scanned, len(scripts))
	}
}

func TestGAP1153FunctionAtMatchesEveryBody(t *testing.T) {
	r := rand.New(rand.NewSource(11530))
	checked := 0
	for n := 0; n < 3000; n++ {
		script := gap1153Script(r, 0)
		var scan commandPathScan
		commandPathWordsIn(script, 0, 0, 0, "/home/u", &scan)
		if len(scan.functions) > 1 {
			checked++
		}
		for at := -1; at <= len(script)+1; at++ {
			if got, want := scan.functionAt(at), scan.functionAtEach(at); got != want {
				t.Fatalf("functionAt(%d) of %q = %d, every body %d", at, script, got, want)
			}
		}
	}
	// Bodies that share a start, and bodies that overlap without one holding
	// the other, which no parse makes: the index answers as every body does.
	for _, functions := range [][]commandPathFunction{
		{{name: "a", body: [2]int{10, 50}}, {name: "b", body: [2]int{10, 30}}, {name: "c", body: [2]int{10, 50}}},
		{{name: "a", body: [2]int{10, 30}}, {name: "b", body: [2]int{20, 40}}},
		{{name: "a", body: [2]int{5, 5}}, {name: "b", body: [2]int{5, 9}}, {name: "c", body: [2]int{0, 60}}, {name: "d", body: [2]int{12, 14}}},
	} {
		scan := commandPathScan{functions: functions}
		for at := -1; at <= 61; at++ {
			if got, want := scan.functionAt(at), scan.functionAtEach(at); got != want {
				t.Fatalf("functionAt(%d) of %v = %d, every body %d", at, functions, got, want)
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d scripts define two functions", checked)
	}
}
