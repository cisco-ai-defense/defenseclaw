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
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const operationDelete = "defenseclaw.guardrail.semantic.v1." +
	"OperationKind.OPERATION_KIND_DELETE"

func TestCompilerAdmissionAndCache(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	valid := `f.commands.exists(c, c.program == "rm" && ` +
		operationDelete + ` in c.operations)`
	first, code := compiler.Compile(valid)
	if code != CompileOK || first == nil || first.StaticCost() == 0 {
		t.Fatalf("Compile(valid) = (%v, %q)", first, code)
	}
	second, code := compiler.Compile(valid)
	if code != CompileOK || second != first {
		t.Fatalf("cached Compile(valid) = (%v, %q)", second, code)
	}

	tests := []struct {
		name       string
		expression string
		want       CompileCode
	}{
		{"invalid UTF-8", string([]byte{0xff}), CompileExpressionEncoding},
		{
			"expression bytes",
			strings.Repeat("x", maxExpressionBytes+1),
			CompileExpressionSize,
		},
		{"syntax", `f.tool ==`, CompileSyntax},
		{"unknown field", `f.unknown == "x"`, CompileType},
		{"non Boolean", `f.tool`, CompileResultType},
		{"surface", `f.tool + "x" == "y"`, CompileSurface},
		{"message equality", `f.parse == f.parse`, CompileSurface},
		{"message inequality", `f.parse != f.parse`, CompileSurface},
		{"list equality", `f.commands == f.commands`, CompileSurface},
		{"message membership", `f.parse in [f.parse]`, CompileSurface},
		{"list membership", `f.commands in [f.commands]`, CompileSurface},
		{
			"enum integer",
			`f.parse.status == 2`,
			CompileEnumDomain,
		},
		{
			"cross enum",
			`f.parse.status == defenseclaw.guardrail.semantic.v1.` +
				`Dialect.DIALECT_POSIX`,
			CompileEnumDomain,
		},
		{
			"mixed enum list",
			`f.commands.exists(c, c.operations.exists(o, ` +
				`o in [5, ` + operationDelete + `]))`,
			CompileEnumDomain,
		},
		{
			"dynamic regex",
			`f.tool.matches(f.cwd)`,
			CompileRegexDynamic,
		},
		{
			"global regex",
			`matches(f.tool, "^exec$")`,
			CompileRegexForm,
		},
		{
			"regex size",
			fmt.Sprintf(`f.tool.matches(%q)`,
				strings.Repeat("x", maxRegexBytes+1)),
			CompileRegexSize,
		},
		{
			"regex syntax",
			`f.tool.matches("[")`,
			CompileRegexSyntax,
		},
		{
			"comprehension depth",
			`f.commands.exists(c, c.arguments.exists(a, ` +
				`c.wrappers.exists(w, w.executable == a.value)))`,
			CompileComprehensionDepth,
		},
		{
			"AST nodes",
			`[` + strings.Repeat("0,", maxExpressionNodes) + `0] == [0]`,
			CompileASTNodes,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, code := compiler.Compile(test.expression)
			if code != test.want || program != nil {
				t.Fatalf("Compile() = (%v, %q), want (nil, %q)",
					program, code, test.want)
			}
		})
	}

	for name, expression := range map[string]string{
		"same enum": `f.commands.exists(c, ` + operationDelete +
			` in c.operations)`,
		"enum list": `f.commands.exists(c, c.operations.exists(o, ` +
			`o in [` + operationDelete + `]))`,
		"depth two": `f.commands.exists(c, ` +
			`c.arguments.exists(a, a.value == "x"))`,
		"literal regex": `f.tool.matches("^exec$")`,
		"scalar list":   `"exec" in [f.tool]`,
	} {
		t.Run(name, func(t *testing.T) {
			program, code := compiler.Compile(expression)
			if code != CompileOK || program == nil {
				t.Fatalf("Compile() = (%v, %q)", program, code)
			}
		})
	}
}

func TestDescriptorMatchesCostBoundsAndClosedSchema(t *testing.T) {
	file := semanticpb.File_facts_proto
	if got := string(file.Messages().ByName("Facts").FullName()); got != "defenseclaw.guardrail.semantic.v1.Facts" {
		t.Fatalf("Facts full name = %q", got)
	}
	if file.Imports().Len() != 0 ||
		file.Services().Len() != 0 ||
		file.Extensions().Len() != 0 {
		t.Fatal("semantic schema has imports, services, or extensions")
	}

	descriptorPaths := make(map[string]struct{})
	var walk func(protoreflect.MessageDescriptor, string)
	walk = func(message protoreflect.MessageDescriptor, base string) {
		if message.IsMapEntry() ||
			message.Oneofs().Len() != 0 ||
			message.Extensions().Len() != 0 {
			t.Fatalf("message %s is not closed", message.FullName())
		}
		for index := 0; index < message.Fields().Len(); index++ {
			field := message.Fields().Get(index)
			if field.ContainingOneof() != nil ||
				field.IsMap() ||
				field.Kind() == protoreflect.BytesKind {
				t.Fatalf("field %s is not closed", field.FullName())
			}
			fieldPath := base + "." + string(field.Name())
			if field.IsList() {
				descriptorPaths[fieldPath] = struct{}{}
				fieldPath += ".@items"
			}
			switch field.Kind() {
			case protoreflect.StringKind:
				descriptorPaths[fieldPath] = struct{}{}
			case protoreflect.MessageKind:
				walk(field.Message(), fieldPath)
			}
		}
	}
	walk(file.Messages().ByName("Facts"), "f")

	boundedPaths := make(map[string]struct{}, len(semanticSizeBounds))
	for _, bound := range semanticSizeBounds {
		if bound.max == 0 {
			t.Fatalf("zero bound for %q", bound.path)
		}
		if _, duplicate := boundedPaths[bound.path]; duplicate {
			t.Fatalf("duplicate bound for %q", bound.path)
		}
		boundedPaths[bound.path] = struct{}{}
	}
	for path := range descriptorPaths {
		if _, ok := boundedPaths[path]; !ok {
			t.Errorf("descriptor path %q has no cost bound", path)
		}
	}
	for path := range boundedPaths {
		if _, ok := descriptorPaths[path]; !ok {
			t.Errorf("cost bound %q has no variable-length field", path)
		}
	}
}
