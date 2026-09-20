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

// ProjectionCode is a value-free reason why ActionFacts could not be safely
// projected. Callers must use the owning regex fallback for every non-OK code.
type ProjectionCode string

const (
	ProjectionOK               ProjectionCode = "ok"
	ProjectionCountLimit       ProjectionCode = "count_limit"
	ProjectionScalarLimit      ProjectionCode = "scalar_limit"
	ProjectionInvalidEnum      ProjectionCode = "invalid_enum"
	ProjectionInvalidCommand   ProjectionCode = "invalid_command"
	ProjectionInvalidReference ProjectionCode = "invalid_reference"
	ProjectionInvalidNetwork   ProjectionCode = "invalid_network"
	ProjectionInvalidDataFlow  ProjectionCode = "invalid_data_flow"
)

// CompileCode is a stable, value-free expression admission result.
type CompileCode string

const (
	CompileOK                  CompileCode = "ok"
	CompileExpressionEncoding  CompileCode = "expression_encoding"
	CompileExpressionSize      CompileCode = "expression_size"
	CompileSyntax              CompileCode = "syntax"
	CompileASTNodes            CompileCode = "ast_nodes"
	CompileASTDepth            CompileCode = "ast_depth"
	CompileType                CompileCode = "type"
	CompileResultType          CompileCode = "result_type"
	CompileSurface             CompileCode = "surface"
	CompileEnumDomain          CompileCode = "enum_domain"
	CompileComprehensionDepth  CompileCode = "comprehension_depth"
	CompileRegexForm           CompileCode = "regex_form"
	CompileRegexDynamic        CompileCode = "regex_dynamic"
	CompileRegexSize           CompileCode = "regex_size"
	CompileRegexSyntax         CompileCode = "regex_syntax"
	CompileStaticCostUnbounded CompileCode = "static_cost_unbounded"
	CompileStaticCost          CompileCode = "static_cost"
	CompileProgram             CompileCode = "program"
)

// EvalCode is a stable, value-free CEL evaluation result.
type EvalCode string

const (
	EvalOK                EvalCode = "ok"
	EvalCancelled         EvalCode = "cancelled"
	EvalDeadline          EvalCode = "deadline"
	EvalCost              EvalCode = "cost"
	EvalUnknown           EvalCode = "unknown"
	EvalError             EvalCode = "error"
	EvalNonBool           EvalCode = "non_bool"
	EvalProjectionInvalid EvalCode = "projection_invalid"
)
