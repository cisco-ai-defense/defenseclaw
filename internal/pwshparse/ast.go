// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

// Node is one AST node. The reference parser has ~60 node classes; they
// share this one shape: the class name, the extent, the children in visit
// order and the few scalar properties detection reads (Props, plus Str for a
// string constant's value and SCT for its StringConstantType).
type Node struct {
	Type  string
	Start int
	End   int
	Kids  []*Node
	Props map[string]string
	// Str is the Value of a (Expandable)StringConstantExpressionAst; SCT its StringConstantType.
	Str string
	SCT string
	// Num is the value of a ConstantExpressionAst.
	Num *NumberValue
	// parent is set by setParents.
	parent *Node
}

func (n *Node) ext() extent { return extent{n.Start, n.End} }

func (n *Node) is(types ...string) bool {
	for _, t := range types {
		if n.Type == t {
			return true
		}
	}
	return false
}

func newNode(typ string, e extent, kids ...*Node) *Node {
	n := &Node{Type: typ, Start: e.Start, End: e.End}
	for _, k := range kids {
		if k != nil {
			n.Kids = append(n.Kids, k)
		}
	}
	return n
}

func (n *Node) prop(k, v string) *Node {
	if n.Props == nil {
		n.Props = map[string]string{}
	}
	n.Props[k] = v
	return n
}

func appendKids(n *Node, kids []*Node) *Node {
	for _, k := range kids {
		if k != nil {
			n.Kids = append(n.Kids, k)
		}
	}
	return n
}
