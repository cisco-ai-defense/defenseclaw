// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// typeName is one ITypeName of the reference: a plain name, a generic name or an array.
type typeName struct {
	ext extent
	// kind: 0 plain, 1 generic, 2 array
	kind  uint8
	name  string
	asm   string
	open  *typeName   // generic: the open type
	args  []*typeName // generic arguments
	elem  *typeName   // array element
	rank  int
	count int // plain: generic argument count (unused by the dump)
}

func newTypeName(e extent, name string) *typeName {
	if strings.Contains(name, "`") {
		name = strings.ReplaceAll(name, "``", "`")
	}
	return &typeName{ext: e, name: name}
}

func newTypeNameAsm(e extent, name, asm string) *typeName {
	t := newTypeName(e, name)
	t.asm = asm
	return t
}

func (t *typeName) assemblyName() string {
	switch t.kind {
	case 1:
		return t.open.asm
	case 2:
		return t.elem.assemblyName()
	}
	return t.asm
}

func (t *typeName) setAssemblyName(a string) {
	switch t.kind {
	case 1:
		t.open.asm = a
	case 2:
		t.elem.setAssemblyName(a)
	default:
		t.asm = a
	}
}

func (t *typeName) typeNameOnly() string {
	switch t.kind {
	case 1:
		var sb strings.Builder
		sb.WriteString(t.open.name)
		sb.WriteByte('[')
		for i, a := range t.args {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(a.typeNameOnly())
		}
		sb.WriteByte(']')
		return sb.String()
	case 2:
		var sb strings.Builder
		sb.WriteString(t.elem.typeNameOnly())
		sb.WriteByte('[')
		if t.rank > 1 {
			sb.WriteString(strings.Repeat(",", t.rank-1))
		}
		sb.WriteByte(']')
		return sb.String()
	}
	return t.name
}

func (t *typeName) fullName() string {
	switch t.kind {
	case 1:
		var sb strings.Builder
		sb.WriteString(t.open.name)
		sb.WriteByte('[')
		for i, a := range t.args {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(a.fullName())
		}
		sb.WriteByte(']')
		if a := t.open.asm; a != "" {
			sb.WriteByte(',')
			sb.WriteString(a)
		}
		return sb.String()
	case 2:
		s := t.typeNameOnly()
		if a := t.elem.assemblyName(); a != "" {
			return s + "," + a
		}
		return s
	}
	if t.asm != "" {
		return t.name + "," + t.asm
	}
	return t.name
}

// firstOf returns the first non-empty extent (ExtentFromFirstOf).
func firstOf(es ...extent) extent {
	for _, e := range es {
		if !e.empty() {
			return e
		}
	}
	return emptyExtent
}

// nx is the extent of a node, empty for a nil node.
func nx(n *Node) extent {
	if n == nil {
		return emptyExtent
	}
	return extent{n.Start, n.End}
}

// tx is the extent of a token, empty for a nil token.
func tx(t *Token) extent {
	if t == nil {
		return emptyExtent
	}
	return extent{t.Start, t.End}
}

func (n *Node) isStringConst() bool { return n != nil && n.Type == "StringConstantExpressionAst" }

// stmtBlock builds a StatementBlockAst: the reference visits traps before statements.
func stmtBlock(e extent, stmts []*Node, traps []*Node) *Node {
	n := &Node{Type: "StatementBlockAst", Start: e.Start, End: e.End}
	n.Kids = append(n.Kids, traps...)
	n.Kids = append(n.Kids, stmts...)
	return n
}

// namedBlock builds a NamedBlockAst from a statement block (its children move onto the named block).
func namedBlock(e extent, kind TokenKind, sb *Node, unnamed bool) *Node {
	n := &Node{Type: "NamedBlockAst", Start: e.Start, End: e.End, Kids: sb.Kids}
	n.prop("BlockKind", kind.String())
	if unnamed {
		n.prop("Unnamed", "true")
	} else {
		n.prop("Unnamed", "false")
	}
	return n
}

// scriptBlockAst builds a ScriptBlockAst; the visit order is using statements, attributes, param block,
// dynamicparam, begin, process, end, clean.
func scriptBlockAst(e extent, usings []*Node, attrs []*Node, param *Node, begin, process, end, clean, dyn *Node) *Node {
	n := &Node{Type: "ScriptBlockAst", Start: e.Start, End: e.End}
	n.Kids = append(n.Kids, usings...)
	n.Kids = append(n.Kids, attrs...)
	for _, k := range []*Node{param, dyn, begin, process, end, clean} {
		if k != nil {
			n.Kids = append(n.Kids, k)
		}
	}
	return n
}

// scriptBlockOfStatements is the ScriptBlockAst(...StatementBlockAst statements, isFilter) constructor.
func scriptBlockOfStatements(e extent, usings []*Node, attrs []*Node, param *Node, sb *Node, isFilter bool) *Node {
	if isFilter {
		return scriptBlockAst(e, usings, attrs, param, nil, namedBlock(nx(sb), TkProcess, sb, true), nil, nil, nil)
	}
	return scriptBlockAst(e, usings, attrs, param, nil, nil, namedBlock(nx(sb), TkEnd, sb, true), nil, nil)
}

func newVariableNode(e extent, path string, splatted bool) *Node {
	n := newNode("VariableExpressionAst", e)
	n.prop("VariablePath", path)
	n.prop("Splatted", boolStr(splatted))
	return n
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func newErrorExpr(e extent, nested ...*Node) *Node {
	return newNode("ErrorExpressionAst", e, nested...)
}

func newErrorStmt(e extent, nested ...*Node) *Node { return newNode("ErrorStatementAst", e, nested...) }

func newConstBool(e extent, v bool) *Node {
	n := newNode("ConstantExpressionAst", e)
	n.prop("StaticType", "System.Boolean").prop("Value", boolStr(v))
	return n
}

func newStringConst(e extent, v string, sct string) *Node {
	n := newNode("StringConstantExpressionAst", e)
	n.Str = v
	n.prop("StringConstantType", sct).prop("Value", v)
	return n
}
