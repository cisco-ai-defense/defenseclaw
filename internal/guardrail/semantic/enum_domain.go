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
	"google.golang.org/protobuf/reflect/protoreflect"
)

type enumValueDomain struct {
	name protoreflect.FullName
	list bool
}

func (d enumValueDomain) empty() bool {
	return d.name == ""
}

type enumDomainValidator struct {
	ast       *cel.Ast
	messages  map[string]protoreflect.MessageDescriptor
	constants map[string]protoreflect.FullName
}

func validateEnumDomains(ast *cel.Ast) bool {
	validator := newEnumDomainValidator(ast)
	_, ok := validator.visit(ast.NativeRep().Expr(), nil)
	return ok
}

func newEnumDomainValidator(ast *cel.Ast) *enumDomainValidator {
	validator := &enumDomainValidator{
		ast:       ast,
		messages:  make(map[string]protoreflect.MessageDescriptor),
		constants: make(map[string]protoreflect.FullName),
	}
	file := semanticpb.File_facts_proto
	var addMessages func(protoreflect.MessageDescriptors)
	addMessages = func(messages protoreflect.MessageDescriptors) {
		for index := 0; index < messages.Len(); index++ {
			message := messages.Get(index)
			validator.messages[string(message.FullName())] = message
			addMessages(message.Messages())
		}
	}
	addMessages(file.Messages())
	var addEnums func(protoreflect.EnumDescriptors)
	addEnums = func(enums protoreflect.EnumDescriptors) {
		for index := 0; index < enums.Len(); index++ {
			enum := enums.Get(index)
			for valueIndex := 0; valueIndex < enum.Values().Len(); valueIndex++ {
				value := enum.Values().Get(valueIndex)
				name := string(enum.FullName()) + "." + string(value.Name())
				validator.constants[name] = enum.FullName()
			}
		}
	}
	addEnums(file.Enums())
	for index := 0; index < file.Messages().Len(); index++ {
		var walkMessage func(protoreflect.MessageDescriptor)
		walkMessage = func(message protoreflect.MessageDescriptor) {
			addEnums(message.Enums())
			for childIndex := 0; childIndex < message.Messages().Len(); childIndex++ {
				walkMessage(message.Messages().Get(childIndex))
			}
		}
		walkMessage(file.Messages().Get(index))
	}
	return validator
}

func (v *enumDomainValidator) visit(
	expr celast.Expr,
	scope map[string]enumValueDomain,
) (enumValueDomain, bool) {
	if reference, ok := v.ast.NativeRep().ReferenceMap()[expr.ID()]; ok {
		if domain, exists := v.constants[reference.Name]; exists {
			return enumValueDomain{name: domain}, true
		}
	}
	switch expr.Kind() {
	case celast.IdentKind:
		if domain, ok := scope[expr.AsIdent()]; ok {
			return domain, true
		}
		return enumValueDomain{}, true
	case celast.LiteralKind:
		return enumValueDomain{}, true
	case celast.SelectKind:
		selection := expr.AsSelect()
		if _, ok := v.visit(selection.Operand(), scope); !ok {
			return enumValueDomain{}, false
		}
		operandType := v.ast.NativeRep().GetType(selection.Operand().ID())
		message := v.messages[operandType.TypeName()]
		if message == nil {
			return enumValueDomain{}, true
		}
		field := message.Fields().ByName(protoreflect.Name(selection.FieldName()))
		if field == nil {
			for index := 0; index < message.Fields().Len(); index++ {
				candidate := message.Fields().Get(index)
				if candidate.JSONName() == selection.FieldName() {
					field = candidate
					break
				}
			}
		}
		if field != nil && field.Kind() == protoreflect.EnumKind {
			return enumValueDomain{
				name: field.Enum().FullName(),
				list: field.Cardinality() == protoreflect.Repeated,
			}, true
		}
		return enumValueDomain{}, true
	case celast.ListKind:
		var listDomain enumValueDomain
		haveDomain := false
		havePlain := false
		for _, element := range expr.AsList().Elements() {
			domain, ok := v.visit(element, scope)
			if !ok {
				return enumValueDomain{}, false
			}
			if domain.empty() {
				if haveDomain {
					return enumValueDomain{}, false
				}
				havePlain = true
				continue
			}
			if havePlain || domain.list {
				return enumValueDomain{}, false
			}
			if !haveDomain {
				listDomain = domain
				haveDomain = true
				continue
			}
			if listDomain.name != domain.name {
				return enumValueDomain{}, false
			}
		}
		if haveDomain {
			listDomain.list = true
			return listDomain, true
		}
		return enumValueDomain{}, true
	case celast.CallKind:
		call := expr.AsCall()
		operands := make([]enumValueDomain, 0, len(call.Args())+1)
		if call.IsMemberFunction() {
			domain, ok := v.visit(call.Target(), scope)
			if !ok {
				return enumValueDomain{}, false
			}
			operands = append(operands, domain)
		}
		for _, argument := range call.Args() {
			domain, ok := v.visit(argument, scope)
			if !ok {
				return enumValueDomain{}, false
			}
			operands = append(operands, domain)
		}
		haveEnum := false
		for _, domain := range operands {
			haveEnum = haveEnum || !domain.empty()
		}
		if !haveEnum {
			return enumValueDomain{}, true
		}
		switch call.FunctionName() {
		case operators.Equals, operators.NotEquals:
			if len(operands) != 2 ||
				operands[0].empty() ||
				operands[1].empty() ||
				operands[0] != operands[1] {
				return enumValueDomain{}, false
			}
		case operators.In, operators.OldIn:
			if len(operands) != 2 ||
				operands[0].empty() || operands[0].list ||
				operands[1].empty() || !operands[1].list ||
				operands[0].name != operands[1].name {
				return enumValueDomain{}, false
			}
		default:
			return enumValueDomain{}, false
		}
		return enumValueDomain{}, true
	case celast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		iterDomain, ok := v.visit(comprehension.IterRange(), scope)
		if !ok {
			return enumValueDomain{}, false
		}
		accuDomain, ok := v.visit(comprehension.AccuInit(), scope)
		if !ok || !accuDomain.empty() {
			return enumValueDomain{}, false
		}
		nested := cloneEnumScope(scope)
		if !iterDomain.empty() {
			if !iterDomain.list {
				return enumValueDomain{}, false
			}
			iterDomain.list = false
			nested[comprehension.IterVar()] = iterDomain
		} else {
			delete(nested, comprehension.IterVar())
		}
		if comprehension.HasIterVar2() {
			delete(nested, comprehension.IterVar2())
		}
		delete(nested, comprehension.AccuVar())
		for _, child := range []celast.Expr{
			comprehension.LoopCondition(),
			comprehension.LoopStep(),
			comprehension.Result(),
		} {
			if _, ok := v.visit(child, nested); !ok {
				return enumValueDomain{}, false
			}
		}
		return enumValueDomain{}, true
	default:
		return enumValueDomain{}, true
	}
}

func cloneEnumScope(scope map[string]enumValueDomain) map[string]enumValueDomain {
	cloned := make(map[string]enumValueDomain, len(scope)+1)
	for name, domain := range scope {
		cloned[name] = domain
	}
	return cloned
}
