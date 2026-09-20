// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
)

var permittedCalls = map[string]struct{}{
	operators.LogicalAnd:       {},
	operators.LogicalOr:        {},
	operators.LogicalNot:       {},
	operators.Equals:           {},
	operators.NotEquals:        {},
	operators.In:               {},
	operators.OldIn:            {},
	operators.NotStrictlyFalse: {},
	overloads.StartsWith:       {},
	overloads.EndsWith:         {},
	overloads.Contains:         {},
	overloads.Matches:          {},
}

func validateSurface(ast *cel.Ast) bool {
	valid := true
	celast.PostOrderVisit(ast.NativeRep().Expr(), celast.NewExprVisitor(func(expr celast.Expr) {
		if !valid {
			return
		}
		switch expr.Kind() {
		case celast.CallKind:
			call := expr.AsCall()
			_, valid = permittedCalls[call.FunctionName()]
			valid = valid && validateCallOperandTypes(ast, call)
		case celast.ComprehensionKind:
			valid = ast.NativeRep().GetType(expr.ID()).IsExactType(types.BoolType)
		case celast.IdentKind, celast.ListKind:
		case celast.LiteralKind:
			switch expr.AsLiteral().(type) {
			case types.Bool, types.Int, types.String:
			default:
				valid = false
			}
		case celast.SelectKind:
			valid = !expr.AsSelect().IsTestOnly()
		default:
			valid = false
		}
	}))
	return valid
}

func validateCallOperandTypes(ast *cel.Ast, call celast.CallExpr) bool {
	operands := call.Args()
	if call.IsMemberFunction() {
		operands = append([]celast.Expr{call.Target()}, operands...)
	}
	switch call.FunctionName() {
	case operators.Equals, operators.NotEquals:
		return len(operands) == 2 &&
			isBoundedScalar(ast.NativeRep().GetType(operands[0].ID())) &&
			isBoundedScalar(ast.NativeRep().GetType(operands[1].ID()))
	case operators.In, operators.OldIn:
		if len(operands) != 2 ||
			!isBoundedScalar(ast.NativeRep().GetType(operands[0].ID())) {
			return false
		}
		listType := ast.NativeRep().GetType(operands[1].ID())
		return listType.Kind() == types.ListKind &&
			len(listType.Parameters()) == 1 &&
			isBoundedScalar(listType.Parameters()[0])
	default:
		return true
	}
}

func isBoundedScalar(valueType *types.Type) bool {
	switch valueType.Kind() {
	case types.BoolKind, types.IntKind, types.StringKind:
		return true
	default:
		return false
	}
}

func validateComprehensionDepth(ast *cel.Ast) bool {
	var visit func(celast.Expr, int) bool
	visit = func(expr celast.Expr, depth int) bool {
		switch expr.Kind() {
		case celast.CallKind:
			call := expr.AsCall()
			if call.IsMemberFunction() && !visit(call.Target(), depth) {
				return false
			}
			for _, argument := range call.Args() {
				if !visit(argument, depth) {
					return false
				}
			}
		case celast.ComprehensionKind:
			depth++
			if depth > maxComprehensionDepth {
				return false
			}
			comprehension := expr.AsComprehension()
			for _, child := range []celast.Expr{
				comprehension.IterRange(),
				comprehension.AccuInit(),
				comprehension.LoopCondition(),
				comprehension.LoopStep(),
				comprehension.Result(),
			} {
				if !visit(child, depth) {
					return false
				}
			}
		case celast.ListKind:
			for _, element := range expr.AsList().Elements() {
				if !visit(element, depth) {
					return false
				}
			}
		case celast.SelectKind:
			return visit(expr.AsSelect().Operand(), depth)
		}
		return true
	}
	return visit(ast.NativeRep().Expr(), 0)
}
