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
	"github.com/google/cel-go/common/types"
)

// RedirectReductionSafe reports whether a match of this expression on the
// view returned by actionfacts.DynamicRedirectTargetReduction also holds for
// the whole action, whose runtime-expanded redirect targets the view left
// out.
//
// The view is the complete analysis of a static-target twin of the action
// without the twin's placeholder redirects and paths. Compared with the
// action it lacks redirects and paths (the action has more, and so may have
// more artifacts and archive lineages built from them), and it is complete
// where the action is not (argv_complete, parse, and a lineage's
// authoritative flag). An expression is safe when it reads none of
// argv_complete, parse and authoritative, and reads redirects, paths,
// artifacts and archive_lineages only as the range of an exists() reached
// from the root through &&, || and exists() or all() predicates alone: more
// of them can then only keep a match. Any other use (under !, ==, !=, in, or
// as the range of all()) could turn a match off, so it is unsafe. The other
// facts, including commands, operations, wrappers, network and data flows,
// are those of a complete analysis; negation over them is unaffected, except
// for facts only the target's real path could produce, which the view never
// has.
func (p *Program) RedirectReductionSafe() bool {
	return p != nil && p.redirectReductionSafe
}

func redirectReductionSafe(ast *cel.Ast) bool {
	if ast == nil || ast.NativeRep() == nil {
		return false
	}
	// monotone is true while every operator between the root and expr keeps
	// a true result true when the action gains redirects, paths, artifacts
	// or archive lineages.
	var visit func(expr celast.Expr, monotone bool) bool
	visit = func(expr celast.Expr, monotone bool) bool {
		switch expr.Kind() {
		case celast.IdentKind, celast.LiteralKind:
			return true
		case celast.SelectKind:
			selected := expr.AsSelect()
			switch selected.FieldName() {
			case "parse", "argv_complete", "authoritative":
				return false
			case "redirects", "paths", "artifacts", "archive_lineages":
				if !monotone {
					return false
				}
			}
			return visit(selected.Operand(), false)
		case celast.CallKind:
			call := expr.AsCall()
			name := call.FunctionName()
			argumentsMonotone := monotone &&
				(name == operators.LogicalAnd || name == operators.LogicalOr)
			if call.IsMemberFunction() && !visit(call.Target(), false) {
				return false
			}
			for _, argument := range call.Args() {
				if !visit(argument, argumentsMonotone) {
					return false
				}
			}
			return true
		case celast.ComprehensionKind:
			loop := expr.AsComprehension()
			exists := quantifierComprehension(loop, false, operators.LogicalOr)
			all := quantifierComprehension(loop, true, operators.LogicalAnd)
			// exists() only gains matches from a longer range; all() can
			// lose them, so only an exists() range may read redirects.
			return visit(loop.IterRange(), monotone && exists) &&
				visit(loop.AccuInit(), false) &&
				visit(loop.LoopCondition(), false) &&
				visit(loop.LoopStep(), monotone && (exists || all)) &&
				visit(loop.Result(), monotone && (exists || all))
		case celast.ListKind:
			for _, element := range expr.AsList().Elements() {
				if !visit(element, false) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return visit(ast.NativeRep().Expr(), true)
}

// quantifierComprehension reports whether loop is the expansion of exists()
// (initial false, step "result || predicate") or all() (initial true, step
// "result && predicate"), selected by initial and step.
func quantifierComprehension(
	loop celast.ComprehensionExpr,
	initial bool,
	step string,
) bool {
	init := loop.AccuInit()
	if init.Kind() != celast.LiteralKind ||
		init.AsLiteral() != types.Bool(initial) ||
		loop.Result().Kind() != celast.IdentKind ||
		loop.Result().AsIdent() != loop.AccuVar() ||
		loop.LoopStep().Kind() != celast.CallKind {
		return false
	}
	call := loop.LoopStep().AsCall()
	arguments := call.Args()
	return call.FunctionName() == step && len(arguments) == 2 &&
		arguments[0].Kind() == celast.IdentKind &&
		arguments[0].AsIdent() == loop.AccuVar()
}
