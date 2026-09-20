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
	"regexp"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/overloads"
)

func validateRegexes(ast *cel.Ast) CompileCode {
	root := celast.NavigateAST(ast.NativeRep())
	for _, match := range celast.MatchDescendants(
		root,
		celast.FunctionMatcher(overloads.Matches),
	) {
		call := match.AsCall()
		if !call.IsMemberFunction() || len(call.Args()) != 1 {
			return CompileRegexForm
		}
		patternExpr := call.Args()[0]
		if patternExpr.Kind() != celast.LiteralKind {
			return CompileRegexDynamic
		}
		pattern, ok := patternExpr.AsLiteral().Value().(string)
		if !ok {
			return CompileRegexDynamic
		}
		if len(pattern) > maxRegexBytes {
			return CompileRegexSize
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return CompileRegexSyntax
		}
	}
	return CompileOK
}
