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
	// props holds the scalar properties detection reads, in insertion order: two inline, the rest in moreProps.
	props     [2]propKV
	nprops    uint8
	moreProps []propKV
	// Str is the Value of a (Expandable)StringConstantExpressionAst; its StringConstantType is the property of that name.
	Str string
	// Num is the value of a ConstantExpressionAst.
	Num *NumberValue
	// kidsBuf is the backing store of the first two children (most nodes have at most two).
	kidsBuf [2]*Node
}

func (n *Node) ext() extent { return extent{n.Start, n.End} }

func newNode(typ string, e extent, kids ...*Node) *Node {
	n := &Node{Type: typ, Start: e.Start, End: e.End}
	if len(kids) > len(n.kidsBuf) {
		n.Kids = make([]*Node, 0, len(kids))
	} else {
		n.Kids = n.kidsBuf[:0]
	}
	for _, k := range kids {
		if k != nil {
			n.Kids = append(n.Kids, k)
		}
	}
	return n
}

type propKV struct{ k, v string }

func (n *Node) prop(k, v string) *Node {
	for i := 0; i < int(n.nprops); i++ {
		if n.props[i].k == k {
			n.props[i].v = v
			return n
		}
	}
	for i := range n.moreProps {
		if n.moreProps[i].k == k {
			n.moreProps[i].v = v
			return n
		}
	}
	if int(n.nprops) < len(n.props) {
		n.props[n.nprops] = propKV{k, v}
		n.nprops++
	} else {
		n.moreProps = append(n.moreProps, propKV{k, v})
	}
	return n
}

// getProp returns the property k and whether it is set.
func (n *Node) getProp(k string) (string, bool) {
	for i := 0; i < int(n.nprops); i++ {
		if n.props[i].k == k {
			return n.props[i].v, true
		}
	}
	for _, kv := range n.moreProps {
		if kv.k == k {
			return kv.v, true
		}
	}
	return "", false
}

// propv returns the property k, or "" when it is not set.
func (n *Node) propv(k string) string {
	v, _ := n.getProp(k)
	return v
}

// Prop returns the scalar property k (see the dump property table), or "" when it is not set.
func (n *Node) Prop(k string) string { return n.propv(k) }
