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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
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
// where the action is not (parse, a lineage's authoritative flag, and a
// command's argv_complete). Each command's argv_complete there is that of a
// complete analysis of its own static argv, so reading it on a command
// (c.argv_complete) is safe; parse and authoritative describe the whole
// analysis and are not. An expression is safe when it reads neither parse
// nor authoritative, reads argv_complete only on a command, and reads
// redirects, paths, artifacts and archive_lineages only as the range of an
// exists() reached from the root through &&, || and exists() or all()
// predicates alone: more of them can then only keep a match. Any other use
// (under !, ==, !=, in, or as the range of all()) could turn a match off, so
// it is unsafe. The other facts, including commands, operations, wrappers,
// network and data flows, are those of a complete analysis; negation over
// them is unaffected, except for facts only the target's real path could
// produce, which the view never has.
func (p *Program) RedirectReductionSafe() bool {
	return p != nil && p.redirectReductionSafe
}

// ListReductionSafe reports whether the result of this expression on the
// view returned by actionfacts.ShortCircuitListReduction also holds for the
// whole action, read as if every command of its && and || lists runs.
//
// The view is the complete analysis of a twin of the action in which each
// list is the sequence of its commands. It has every command of the action
// and every fact they own, so negation over them decides as it does for the
// same commands joined by ";". It differs from the action only in being
// complete, so an expression is safe when it reads neither parse nor
// authoritative, and reads argv_complete only on a command.
func (p *Program) ListReductionSafe() bool {
	return p != nil && p.listReductionSafe
}

// StaticCommandSubsetSafe reports whether a match of this expression on the
// view returned by actionfacts.StaticCommandSubsetReduction also holds for
// the whole action.
//
// The view keeps only the commands the action is certain to run with a
// static argv, so the action has more commands, redirects, paths, network
// facts and data flows (and so artifacts and archive lineages) than the view,
// never fewer. A kept command's own fields are those of the action, and its
// argv_complete is true because its argv is static. An expression is safe
// when it reads neither parse nor authoritative, reads argv_complete only on
// a command, and reads each of those collections only as the range of an
// exists() reached from the root through &&, || and exists() or all()
// predicates alone.
func (p *Program) StaticCommandSubsetSafe() bool {
	return p != nil && p.subsetReductionSafe
}

func subsetReductionSafe(ast *cel.Ast) bool {
	return reductionSafe(ast, map[string]bool{
		"commands": true, "redirects": true, "paths": true, "network": true,
		"data_flows": true, "artifacts": true, "archive_lineages": true,
	})
}

func redirectReductionSafe(ast *cel.Ast) bool {
	return reductionSafe(ast, map[string]bool{
		"redirects": true, "paths": true, "artifacts": true, "archive_lineages": true,
	})
}

func listReductionSafe(ast *cel.Ast) bool {
	return reductionSafe(ast, nil)
}

// commandFactType is the CEL type name of a command fact.
var commandFactType = string((&semanticpb.CommandFact{}).ProtoReflect().Descriptor().FullName())

// reductionSafe reports whether ast reads neither parse nor authoritative,
// reads argv_complete only on a command, and reads each field in lacking,
// the facts a reduced view may have fewer of, only where more of them can
// only keep a match.
func reductionSafe(ast *cel.Ast, lacking map[string]bool) bool {
	if ast == nil || ast.NativeRep() == nil {
		return false
	}
	checked := ast.NativeRep()
	// monotone is true while every operator between the root and expr keeps
	// a true result true when the action gains facts in lacking.
	var visit func(expr celast.Expr, monotone bool) bool
	visit = func(expr celast.Expr, monotone bool) bool {
		switch expr.Kind() {
		case celast.IdentKind, celast.LiteralKind:
			return true
		case celast.SelectKind:
			selected := expr.AsSelect()
			switch field := selected.FieldName(); {
			case field == "parse", field == "authoritative":
				return false
			case field == "argv_complete" &&
				checked.GetType(selected.Operand().ID()).TypeName() != commandFactType:
				return false
			case lacking[field] && !monotone:
				return false
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
			// lose them, so only an exists() range may read a lacking field.
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
	return visit(checked.Expr(), true)
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
