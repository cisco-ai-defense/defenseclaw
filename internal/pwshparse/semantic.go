// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

// A subset of SemanticChecks.cs: the checks that decide "this script is not valid
// PowerShell" for shapes the detection reads. The rest of SemanticChecks (class
// member rules, attribute argument constness, duplicate parameters, automatic
// variable assignment, ...) is not ported: a script with only those errors reads as
// valid here, which only matters for scripts the real parser would refuse to run.
//
// Ported: SplattingNotPermitted(InArgumentList) (VisitVariableExpression),
// OperatorRequiresVariableOrProperty for ++ and -- (VisitUnaryExpression with
// CheckAssignmentTarget).

func (p *Parser) semanticChecks(root *Node) {
	if root == nil {
		return
	}
	var parents []*Node
	var walk func(n *Node)
	walk = func(n *Node) {
		switch n.Type {
		case "VariableExpressionAst":
			if n.Props["Splatted"] == "true" && len(parents) > 0 {
				parent := parents[len(parents)-1]
				if parent.Type != "CommandAst" && parent.Type != "UsingExpressionAst" {
					id := "SplattingNotPermitted"
					if parent.Type == "ArrayLiteralAst" && len(parents) > 1 && parents[len(parents)-2].Type == "CommandAst" {
						id = "SplattingNotPermittedInArgumentList"
					}
					p.reportError(n.ext(), id)
				}
			}
		case "UnaryExpressionAst":
			switch n.Props["TokenKind"] {
			case "PlusPlus", "PostfixPlusPlus", "MinusMinus", "PostfixMinusMinus":
				if len(n.Kids) > 0 {
					p.checkIncDecTarget(n.Kids[0])
				}
			}
		}
		parents = append(parents, n)
		for _, k := range n.Kids {
			walk(k)
		}
		parents = parents[:len(parents)-1]
	}
	walk(root)
}

// checkIncDecTarget is CheckAssignmentTarget(ast, simpleAssignment: false) for the ++/-- operand.
func (p *Parser) checkIncDecTarget(ast *Node) {
	switch ast.Type {
	case "ArrayLiteralAst":
		p.reportError(ast.ext(), "OperatorRequiresVariableOrProperty")
	case "ParenExpressionAst":
		if len(ast.Kids) == 0 {
			return
		}
		pipeline := ast.Kids[0]
		if expr := pureExpression(pipeline); expr != nil {
			p.checkIncDecTarget(expr)
		} else {
			p.reportError(pipeline.ext(), "OperatorRequiresVariableOrProperty")
		}
	case "VariableExpressionAst", "AttributedExpressionAst", "ConvertExpressionAst":
		// assignable (the attribute chain checks beyond the reference-type rules are not ported)
	case "MemberExpressionAst", "InvokeMemberExpressionAst", "BaseCtorInvokeMemberExpressionAst", "IndexExpressionAst":
		if ast.Props["NullConditional"] == "true" {
			p.reportError(ast.ext(), "OperatorRequiresVariableOrProperty")
		}
	default:
		p.reportError(ast.ext(), "OperatorRequiresVariableOrProperty")
	}
}

// pureExpression is PipelineBaseAst.GetPureExpression.
func pureExpression(n *Node) *Node {
	if n.Type != "PipelineAst" || len(n.Kids) != 1 || n.Kids[0].Type != "CommandExpressionAst" {
		return nil
	}
	ce := n.Kids[0]
	if len(ce.Kids) != 1 {
		return nil
	}
	return ce.Kids[0]
}
