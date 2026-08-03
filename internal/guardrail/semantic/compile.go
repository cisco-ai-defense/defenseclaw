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
	"math"
	"unicode/utf8"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
)

type cachedCompile struct {
	program *Program
	code    CompileCode
}

// Compiler owns one candidate-local expression cache. It is construction
// state, not a process-global service, and need not be used concurrently.
type Compiler struct {
	env   *cel.Env
	cache map[string]cachedCompile
}

// Program is an immutable, reusable checked CEL program.
type Program struct {
	program    cel.Program
	staticCost uint64
}

// NewCompiler constructs an isolated compiler for one rulepack candidate.
func NewCompiler() (*Compiler, error) {
	env, err := newEnvironment()
	if err != nil {
		return nil, err
	}
	return &Compiler{
		env:   env,
		cache: make(map[string]cachedCompile),
	}, nil
}

// Compile admits and compiles one Boolean semantic expression.
func (c *Compiler) Compile(expression string) (*Program, CompileCode) {
	if c == nil || c.env == nil {
		return nil, CompileProgram
	}
	if cached, ok := c.cache[expression]; ok {
		return cached.program, cached.code
	}
	program, code := c.compile(expression)
	c.cache[expression] = cachedCompile{program: program, code: code}
	return program, code
}

func (c *Compiler) compile(expression string) (*Program, CompileCode) {
	if !utf8.ValidString(expression) {
		return nil, CompileExpressionEncoding
	}
	if len(expression) > maxExpressionBytes ||
		utf8.RuneCountInString(expression) > maxExpressionRunes {
		return nil, CompileExpressionSize
	}
	parsed, issues := c.env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return nil, CompileSyntax
	}
	if parsed == nil || parsed.NativeRep() == nil {
		return nil, CompileSyntax
	}
	if celast.NodeCount(parsed.NativeRep()) > maxExpressionNodes {
		return nil, CompileASTNodes
	}
	if celast.ExceedsDepth(parsed.NativeRep(), maxExpressionDepth+1) {
		return nil, CompileASTDepth
	}

	checked, issues := c.env.Check(parsed)
	if issues != nil && issues.Err() != nil {
		return nil, CompileType
	}
	if checked == nil || checked.NativeRep() == nil {
		return nil, CompileType
	}
	if celast.NodeCount(checked.NativeRep()) > maxExpressionNodes {
		return nil, CompileASTNodes
	}
	if celast.ExceedsDepth(checked.NativeRep(), maxExpressionDepth+1) {
		return nil, CompileASTDepth
	}
	if !checked.OutputType().IsExactType(cel.BoolType) {
		return nil, CompileResultType
	}
	if !validateSurface(checked) {
		return nil, CompileSurface
	}
	if !validateEnumDomains(checked) {
		return nil, CompileEnumDomain
	}
	if !validateComprehensionDepth(checked) {
		return nil, CompileComprehensionDepth
	}
	if code := validateRegexes(checked); code != CompileOK {
		return nil, code
	}
	estimate, err := c.env.EstimateCost(checked, boundedCostEstimator{})
	if err != nil || estimate.Max == math.MaxUint64 {
		return nil, CompileStaticCostUnbounded
	}
	if estimate.Max > maxRuleStaticCost {
		return nil, CompileStaticCost
	}
	evaluable, err := c.env.Program(
		checked,
		cel.EvalOptions(cel.OptOptimize),
		cel.InterruptCheckFrequency(interruptFrequency),
		cel.CostLimit(maxRuleRuntimeCost),
	)
	if err != nil {
		return nil, CompileProgram
	}
	return &Program{
		program:    evaluable,
		staticCost: estimate.Max,
	}, CompileOK
}

// StaticCost returns the admitted checked-expression maximum.
func (p *Program) StaticCost() uint64 {
	if p == nil {
		return 0
	}
	return p.staticCost
}
