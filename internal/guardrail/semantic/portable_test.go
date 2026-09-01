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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

const (
	parseUnspecified = "defenseclaw.guardrail.semantic.v1." +
		"ParseStatus.PARSE_STATUS_UNSPECIFIED"
	pathAccessRead = "defenseclaw.guardrail.semantic.v1." +
		"PathAccess.PATH_ACCESS_READ"
)

func TestCompilePortableCanonicalIdentityAndCache(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	sources := []string{
		`f.commands.exists(c, c.id == 9007199254740993 && ` +
			`c.pipeline_id == 9223372036854775807 && ` +
			operationDelete + ` in c.operations)`,
		`f.commands.exists(command, command.id==9007199254740993 && ` +
			`command.pipeline_id==9223372036854775807 && ` +
			operationDelete + ` in command.operations)`,
	}
	first, code := compiler.CompilePortable(sources[0])
	if code != CompileOK || first == nil {
		t.Fatalf("CompilePortable(first) = (%v, %q)", first, code)
	}
	second, code := compiler.CompilePortable(sources[1])
	if code != CompileOK || second == nil {
		t.Fatalf("CompilePortable(second) = (%v, %q)", second, code)
	}
	if first.Expression() != second.Expression() || first.Identity() != second.Identity() {
		t.Fatalf(
			"alpha/whitespace-equivalent translation changed identity:\nfirst:  %s %s\nsecond: %s %s",
			first.Identity(), first.Expression(), second.Identity(), second.Expression(),
		)
	}
	if first.Expression() == "" ||
		!strings.Contains(first.Expression(), `input.commands.exists(item0`) ||
		!strings.Contains(first.Expression(), `"9007199254740993"`) ||
		!strings.Contains(first.Expression(), `"9223372036854775807"`) ||
		!strings.Contains(first.Expression(), `"OPERATION_KIND_DELETE"`) ||
		strings.Contains(first.Expression(), "defenseclaw.guardrail.semantic.v1") {
		t.Fatalf("unexpected portable expression: %s", first.Expression())
	}
	if !strings.HasPrefix(first.Identity(), "sha256:") || len(first.Identity()) != len("sha256:")+64 {
		t.Fatalf("portable identity = %q", first.Identity())
	}
	if first.SourceStaticCost() == 0 {
		t.Fatal("portable program lost typed source cost")
	}
	cached, code := compiler.CompilePortable(sources[0])
	if code != CompileOK || cached != first {
		t.Fatalf("cached CompilePortable() = (%v, %q)", cached, code)
	}

	facts := &semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{{
			Id:         9007199254740993,
			PipelineId: 9223372036854775807,
			Operations: []semanticpb.OperationKind{semanticpb.OperationKind_OPERATION_KIND_DELETE},
		}},
	}
	assertPortableEquivalent(t, compiler, sources[0], facts, true)
}

func TestPortableEvaluationDefaultsEmptyListsAndPipelineIDs(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defaultExpression := `f.tool == "" && f.cwd == "" && f.active_home == "" && ` +
		`f.parse.status == ` + parseUnspecified +
		` && !f.commands.exists(c, c.argv_complete)`
	assertPortableEquivalent(t, compiler, defaultExpression, &semanticpb.Facts{}, true)
	commandDefaults := `f.commands.exists(c, c.id == 0 && c.program == "" && ` +
		`!c.argv_complete && !c.operations.exists(o, o == ` + operationDelete + `))`
	assertPortableEquivalent(t, compiler, commandDefaults, &semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{{}},
	}, true)

	pipelineExpression := `f.commands.exists(src, f.commands.exists(dst, ` +
		`src.id != dst.id && src.pipeline_id != 0 && ` +
		`src.pipeline_id == dst.pipeline_id))`
	assertPortableEquivalent(t, compiler, pipelineExpression, &semanticpb.Facts{}, false)
	assertPortableEquivalent(t, compiler, pipelineExpression, &semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{
			{Id: 1, PipelineId: 0},
			{Id: 2, PipelineId: 0},
		},
	}, false)
	assertPortableEquivalent(t, compiler, pipelineExpression, &semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{
			{Id: 9007199254740993, PipelineId: 9223372036854775807},
			{Id: 9007199254740994, PipelineId: 9223372036854775807},
		},
	}, true)
}

func TestPortableTranslationResolvesRootAndShadowedVariables(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	expression := `f.commands.exists(input, input.id == 7 && ` +
		`f.paths.exists(f, f.command_id == input.id && ` +
		`f.access == ` + pathAccessRead + `))`
	facts := &semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{{Id: 7}},
		Paths: []*semanticpb.PathFact{{
			CommandId: 7,
			Access:    semanticpb.PathAccess_PATH_ACCESS_READ,
		}},
	}
	portable, code := compiler.CompilePortable(expression)
	if code != CompileOK || portable == nil {
		t.Fatalf("CompilePortable() = (%v, %q)", portable, code)
	}
	if !strings.Contains(portable.Expression(), "input.commands.exists(item0") ||
		!strings.Contains(portable.Expression(), "input.paths.exists(item1") {
		t.Fatalf("root/local resolution was not canonical: %s", portable.Expression())
	}
	assertPortableEquivalent(t, compiler, expression, facts, true)
}

func TestPortableDocumentProtoJSONContract(t *testing.T) {
	document, err := PortableDocument(&semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{{
			Id:         9007199254740993,
			PipelineId: 9223372036854775807,
			Operations: []semanticpb.OperationKind{semanticpb.OperationKind_OPERATION_KIND_DELETE},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	parse, ok := document["parse"].(map[string]any)
	if !ok {
		t.Fatalf("default parse document = %#v", document["parse"])
	}
	if parse["status"] != "PARSE_STATUS_UNSPECIFIED" ||
		parse["dialect"] != "DIALECT_UNSPECIFIED" ||
		len(parse["issues"].([]any)) != 0 {
		t.Fatalf("default parse document = %#v", parse)
	}
	commands := document["commands"].([]any)
	command := commands[0].(map[string]any)
	if command["id"] != "9007199254740993" ||
		command["parent_command_id"] != "0" ||
		command["pipeline_id"] != "9223372036854775807" {
		t.Fatalf("int64 document contract = %#v", command)
	}
	operations := command["operations"].([]any)
	if len(operations) != 1 || operations[0] != "OPERATION_KIND_DELETE" {
		t.Fatalf("enum document contract = %#v", operations)
	}
	if command["argv_complete"] != false || len(command["argv"].([]any)) != 0 {
		t.Fatalf("unpopulated document contract = %#v", command)
	}
	if _, err := PortableDocument(nil); err == nil {
		t.Fatal("nil Facts document was accepted")
	}
	if _, err := PortableDocument(&semanticpb.Facts{
		Parse: &semanticpb.ParseResult{Status: semanticpb.ParseStatus(999)},
	}); err == nil {
		t.Fatal("unknown enum value was accepted")
	}
}

func TestCompilePortableEnumDomainsFailClosed(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		expression string
		want       CompileCode
	}{
		{
			name:       "numeric enum",
			expression: `f.parse.status == 0`,
			want:       CompileEnumDomain,
		},
		{
			name: "cross-domain enum",
			expression: `f.parse.status == defenseclaw.guardrail.semantic.v1.` +
				`Dialect.DIALECT_UNSPECIFIED`,
			want: CompileEnumDomain,
		},
		{
			name: "mixed enum list",
			expression: `f.commands.exists(c, c.operations.exists(o, ` +
				`o in [` + operationDelete + `, 5]))`,
			want: CompileEnumDomain,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, code := compiler.CompilePortable(test.expression)
			if code != test.want || program != nil {
				t.Fatalf("CompilePortable() = (%v, %q), want (nil, %q)", program, code, test.want)
			}
		})
	}
}

func TestPortableCheckedASTRejectsUnsupportedNodes(t *testing.T) {
	environment, err := newEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"all comprehension": `f.commands.all(c, c.argv_complete)`,
		"arithmetic":        `1 + 1 == 2`,
		"conditional":       `true ? f.tool == "exec" : false`,
		"index":             `[f.tool][0] == "exec"`,
		"map":               `{"tool": f.tool}["tool"] == "exec"`,
		"presence":          `has(f.parse.status)`,
	}
	for name, expression := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, issues := environment.Parse(expression)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("parse unsupported checked form: %v", issues.Err())
			}
			checked, issues := environment.Check(parsed)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("check unsupported checked form: %v", issues.Err())
			}
			if translated, ok := translatePortableCheckedAST(checked); ok {
				t.Fatalf("unsupported checked AST translated to %q", translated)
			}
		})
	}
}

func assertPortableEquivalent(
	t *testing.T,
	compiler *Compiler,
	expression string,
	facts *semanticpb.Facts,
	want bool,
) {
	t.Helper()
	native, code := compiler.Compile(expression)
	if code != CompileOK || native == nil {
		t.Fatalf("Compile(%q) = (%v, %q)", expression, native, code)
	}
	portable, code := compiler.CompilePortable(expression)
	if code != CompileOK || portable == nil {
		t.Fatalf("CompilePortable(%q) = (%v, %q)", expression, portable, code)
	}
	nativeResult, nativeCode := native.EvalBool(t.Context(), facts)
	portableResult, portableCode := portable.EvalBool(t.Context(), facts)
	if nativeCode != portableCode || nativeResult.Matched != portableResult.Matched {
		t.Fatalf(
			"native=(matched=%t code=%s) portable=(matched=%t code=%s) expression=%q portable_expression=%q",
			nativeResult.Matched,
			nativeCode,
			portableResult.Matched,
			portableCode,
			expression,
			portable.Expression(),
		)
	}
	if nativeCode != EvalOK || nativeResult.Matched != want {
		t.Fatalf("evaluation = (matched=%t code=%s), want (matched=%t code=%s)",
			nativeResult.Matched, nativeCode, want, EvalOK)
	}
}
