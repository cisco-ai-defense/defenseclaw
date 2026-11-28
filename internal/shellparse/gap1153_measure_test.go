// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// measureTreeByType is measureTree as it was before the per-type shapes:
// every check asked of the value. It is the oracle of the cached walk.
func measureTreeByType(file *syntax.File) string {
	nodes, chain := 0, 0
	stack := []measureFrame{{reflect.ValueOf(file), 0}}
	for len(stack) > 0 {
		if len(stack) > 4*MaxParsedNodes {
			return BudgetNodes
		}
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		value, depth := frame.value, frame.depth
		switch value.Kind() {
		case reflect.Pointer:
			if value.IsNil() {
				continue
			}
			if value.Type().Implements(nodeType) {
				if nodes++; nodes > MaxParsedNodes {
					return BudgetNodes
				}
				if depth++; depth > MaxTreeDepth {
					return BudgetDepth
				}
				if binary, ok := value.Interface().(*syntax.BinaryCmd); ok {
					switch binary.Op {
					case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
						if chain++; chain > MaxChainOperators {
							return BudgetChain
						}
					}
				}
			}
			stack = append(stack, measureFrame{value.Elem(), depth})
		case reflect.Interface:
			if !value.IsNil() {
				stack = append(stack, measureFrame{value.Elem(), depth})
			}
		case reflect.Slice:
			for i := range value.Len() {
				stack = append(stack, measureFrame{value.Index(i), depth})
			}
		case reflect.Struct:
			for i := range value.NumField() {
				if !value.Type().Field(i).IsExported() {
					continue
				}
				switch value.Field(i).Kind() {
				case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Struct:
					stack = append(stack, measureFrame{value.Field(i), depth})
				}
			}
		}
	}
	return ""
}

func gap1153Fit(prefix, unit, suffix string, size int) string {
	var out strings.Builder
	out.WriteString(prefix)
	for k := 0; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if out.Len()+len(piece)+len(suffix) > size {
			break
		}
		out.WriteString(piece)
	}
	return out.String() + suffix
}

func gap1153MeasureCorpus() []string {
	o20, c20 := strings.Repeat("for i in 1; do ", 20), strings.Repeat("done; ", 20)
	return []string{
		gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done", 8190),
		gap1153Fit("", "$C;f{k}(){ :;};", "true", 8190),
		gap1153Fit(o20, "$C;f{k}(){ :;};", c20+"true", 8190),
		gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done", 8190),
		gap1153Fit("", "test -e f{k} && :;", "true", 8190),
		gap1153Fit("", "a{k} | b{k} || c{k};", "true", 8190),
		"cat <<EOF\n$(id) ${x:-y} $((1+2))\nEOF\nif [[ -n $a ]]; then case $b in x) echo; esac; fi",
		"echo {a,b}{1..3} >(cat) <(ls) 2>&1 | tee -a f && arr=(1 2) && echo ${arr[@]}",
		// Past each bound of the tree: chain operators, nodes and depth.
		strings.Repeat("a | ", MaxChainOperators+8) + "a",
		strings.Repeat("a;", MaxParsedNodes/2+64) + "a",
		"echo $((" + strings.Repeat("1+", MaxTreeDepth+8) + "1))",
		strings.Repeat("a && ", MaxChainOperators/2) + strings.Repeat("b | ", MaxChainOperators/2+8) + "c",
	}
}

// TestGAP1153MeasureTreeKeepsEveryAnswer: the per-type shapes walk the same
// values in the same order, so every tree gets the reason the walk that
// asked each value gave, including the bound that trips first.
func TestGAP1153MeasureTreeKeepsEveryAnswer(t *testing.T) {
	reasons := map[string]bool{}
	for _, command := range gap1153MeasureCorpus() {
		file, ok, _ := parseUnbudgeted(command)
		if !ok {
			t.Fatalf("%.60q does not parse", command)
		}
		want, got := measureTreeByType(file), measureTree(file)
		if got != want {
			t.Fatalf("%.60q: measureTree %q, the per-value walk %q", command, got, want)
		}
		reasons[want] = true
	}
	for _, want := range []string{"", BudgetChain, BudgetNodes, BudgetDepth} {
		if !reasons[want] {
			t.Errorf("corpus reaches no tree with reason %q: %v", want, reasons)
		}
	}
}

var gap1153Fresh atomic.Int64

// gap1153FreshCommand is an 8 KB script no earlier ask has read, so its
// budget is computed (not remembered) on the next parse.
func gap1153FreshCommand() string {
	return fmt.Sprintf("x%d=1;", gap1153Fresh.Add(1)) + gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done", 8190)
}

// TestGAP1153ParseTakesTheMeasuredTree: the budget measure of an 8 KB call
// parses it, and Parse returns that tree instead of parsing again. The tree
// is the one a parse of its own gives, it is handed out once (the next
// Parse of the text is a tree of its own), a parse that keeps comments
// still parses, and a fresh Parse costs no more than its budget measure.
func TestGAP1153ParseTakesTheMeasuredTree(t *testing.T) {
	command := gap1153FreshCommand()
	first, ok := Parse(command)
	if !ok {
		t.Fatal("does not parse")
	}
	own, _, _ := parseUnbudgeted(command)
	if !reflect.DeepEqual(first, own) {
		t.Fatal("the measured tree is not the tree of a parse")
	}
	again, _ := Parse(command)
	if again == first || again.Stmts[0] == first.Stmts[0] || !reflect.DeepEqual(again, first) {
		t.Fatal("the second Parse shares the first tree or reads another")
	}
	noted := "# note\n" + gap1153FreshCommand()
	if file, ok := ParseWithComments(noted); !ok || len(file.Stmts) == 0 || len(file.Stmts[0].Comments) == 0 {
		t.Fatalf("ParseWithComments lost the comment: %v", ok)
	}
	parse := testing.AllocsPerRun(5, func() { Parse(gap1153FreshCommand()) })
	budget := testing.AllocsPerRun(5, func() { computeBudget(gap1153FreshCommand()) })
	one := testing.AllocsPerRun(5, func() { parseUnbudgeted(gap1153FreshCommand()) })
	t.Logf("allocations: fresh Parse %.0f, its budget measure %.0f, one parse %.0f", parse, budget, one)
	if parse > budget+one/4 {
		t.Errorf("a fresh Parse of an 8 KB call allocates %.0f, its budget measure %.0f and %.0f more, %.1f parses (%.0f each): it parses the text again (substrate-1 GAP-1153)", parse, budget, parse-budget, (parse-budget)/one, one)
	}
}
