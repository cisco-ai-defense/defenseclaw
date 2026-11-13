// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"strings"
)

// budgetShape is one family of generated hook-call text for the reading
// budget: unit repeated n times, then tail. Every test input of the budget
// is built from these small templates and a size, never stored.
type budgetShape struct {
	name       string
	unit, tail string
	// sizes are the unit counts of the cost curve.
	sizes []int
}

var budgetChainSizes = []int{32, 64, 128, 256, 512, 1024, 2048, 4096}
var budgetFlatSizes = []int{256, 1024, 4096, 16384, 65536}

// budgetShapes are the families of tree the hook builds: chains of every
// operator, chains of compound stages (substitutions, groups, redirects,
// assignments), flat lists, deep arithmetic and a here-document.
var budgetShapes = []budgetShape{
	{"pipe", "a|", "a", budgetChainSizes},
	{"and", "a&&", "a", budgetChainSizes},
	{"or", "a||", "a", budgetChainSizes},
	{"mixed", "a|b&&c||", "d", budgetChainSizes},
	{"subst-pipe", "$(a)|", "a", budgetChainSizes},
	{"group-pipe", "(a)|", "a", budgetChainSizes},
	{"block-pipe", "{ a; }|", "a", budgetChainSizes},
	{"redirect-pipe", "a>b|", "a", budgetChainSizes},
	{"assign-pipe", "x=1 a|", "a", budgetChainSizes},
	{"unparsed-pipe", "a|", "fi", budgetChainSizes},
	{"nest", "(", ")", budgetChainSizes},
	{"arith", "echo $((1", ")) ", budgetChainSizes},
	{"flat-words", "a ", "", budgetFlatSizes},
	{"flat-stmts", "a;", "a", budgetFlatSizes},
	{"heredoc-lines", "d | e\n", "EOF\n", budgetFlatSizes},
}

// command builds the text of the shape at n units.
func (s budgetShape) command(n int) string {
	switch s.name {
	case "nest":
		return strings.Repeat("(", n) + "true" + strings.Repeat(")", n)
	case "arith":
		return "echo $((1" + strings.Repeat("+1", n) + "))"
	case "heredoc-lines":
		return "cat > notes.txt <<'EOF'\n" + strings.Repeat(s.unit, n) + s.tail
	case "flat-words":
		return "echo " + strings.Repeat(s.unit, n)
	}
	return strings.Repeat(s.unit, n) + s.tail
}

func budgetShapeNamed(name string) budgetShape {
	for _, shape := range budgetShapes {
		if shape.name == name {
			return shape
		}
	}
	panic("unknown budget shape " + strconv.Quote(name))
}
