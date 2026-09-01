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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/parser"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const portableIdentityDomain = "defenseclaw.guardrail.semantic.portable-cel.v1\x00"

// PortableProgram is the stock document-CEL form of one admitted typed Facts
// expression. Its source expression is canonical and evaluates against a
// single dyn variable named input.
type PortableProgram struct {
	program          cel.Program
	expression       string
	identity         string
	sourceStaticCost uint64
}

// Expression returns the canonical stock CEL source.
func (p *PortableProgram) Expression() string {
	if p == nil {
		return ""
	}
	return p.expression
}

// Identity returns the versioned SHA-256 identity of Expression.
func (p *PortableProgram) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}

// SourceStaticCost returns the admitted maximum for the typed source rule.
// The document form is executed with the runtime cost limit; its dyn input
// does not provide enough static size information for the typed estimator.
func (p *PortableProgram) SourceStaticCost() uint64 {
	if p == nil {
		return 0
	}
	return p.sourceStaticCost
}

// CompilePortable admits a typed Facts expression, translates only its
// resolved checked AST, canonically unparses it, and checks the result in a
// schema-free stock CEL environment.
func (c *Compiler) CompilePortable(expression string) (*PortableProgram, CompileCode) {
	if c == nil {
		return nil, CompileProgram
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.env == nil {
		return nil, CompileProgram
	}
	if c.portableEnv == nil {
		portableEnv, err := newPortableEnvironment()
		if err != nil {
			return nil, CompileProgram
		}
		c.portableEnv = portableEnv
	}
	if c.portableCache == nil {
		c.portableCache = make(map[string]cachedPortableCompile)
	}
	if cached, ok := c.portableCache[expression]; ok {
		return cached.program, cached.code
	}
	program, code := c.compilePortable(expression)
	c.portableCache[expression] = cachedPortableCompile{program: program, code: code}
	return program, code
}

func (c *Compiler) compilePortable(expression string) (*PortableProgram, CompileCode) {
	checked, sourceStaticCost, code := c.check(expression)
	if code != CompileOK {
		return nil, code
	}
	canonical, ok := translatePortableCheckedAST(checked)
	if !ok {
		return nil, CompileSurface
	}
	if !utf8.ValidString(canonical) ||
		len(canonical) > maxExpressionBytes ||
		utf8.RuneCountInString(canonical) > maxExpressionRunes {
		return nil, CompileExpressionSize
	}
	parsed, issues := c.portableEnv.Parse(canonical)
	if issues != nil && issues.Err() != nil {
		return nil, CompileProgram
	}
	if parsed == nil || parsed.NativeRep() == nil ||
		celast.NodeCount(parsed.NativeRep()) > maxExpressionNodes ||
		celast.ExceedsDepth(parsed.NativeRep(), maxExpressionDepth+1) {
		return nil, CompileProgram
	}
	portableChecked, issues := c.portableEnv.Check(parsed)
	if issues != nil && issues.Err() != nil {
		return nil, CompileProgram
	}
	if portableChecked == nil || portableChecked.NativeRep() == nil ||
		!portableChecked.OutputType().IsExactType(cel.BoolType) {
		return nil, CompileProgram
	}
	evaluable, err := c.portableEnv.Program(
		portableChecked,
		cel.EvalOptions(cel.OptOptimize),
		cel.InterruptCheckFrequency(interruptFrequency),
		cel.CostLimit(maxRuleRuntimeCost),
	)
	if err != nil {
		return nil, CompileProgram
	}
	digest := sha256.Sum256([]byte(portableIdentityDomain + canonical))
	return &PortableProgram{
		program:          evaluable,
		expression:       canonical,
		identity:         "sha256:" + hex.EncodeToString(digest[:]),
		sourceStaticCost: sourceStaticCost,
	}, CompileOK
}

// EvalBool evaluates the portable expression against the canonical document
// projection of facts. The document is ephemeral policy material and must not
// be logged, persisted, audited, or exposed through an API.
func (p *PortableProgram) EvalBool(
	ctx context.Context,
	facts *semanticpb.Facts,
) (Result, EvalCode) {
	if p == nil || p.program == nil {
		return Result{}, EvalError
	}
	if ctx == nil || facts == nil {
		return Result{}, EvalProjectionInvalid
	}
	document, err := PortableDocument(facts)
	if err != nil {
		return Result{}, EvalProjectionInvalid
	}
	return evalBoolProgram(ctx, p.program, map[string]any{"input": document})
}

// PortableDocument converts Facts to the exact stock-CEL activation contract.
// Proto field names and unpopulated values are emitted, enums use canonical
// proto names, and every int64 is a canonical decimal string as required by
// protojson. Invalid enum values fail closed instead of changing the document
// type from string to number.
func PortableDocument(facts *semanticpb.Facts) (map[string]any, error) {
	if facts == nil {
		return nil, errors.New("portable Facts document is nil")
	}
	cloned, ok := proto.Clone(facts).(*semanticpb.Facts)
	if !ok || cloned == nil {
		return nil, errors.New("clone portable Facts document")
	}
	// Typed CEL reads an absent proto3 message as its default message. Ensure
	// the stock document has the same selectable object rather than JSON null.
	if cloned.Parse == nil {
		cloned.Parse = &semanticpb.ParseResult{}
	}
	if err := validatePortableProto(cloned.ProtoReflect()); err != nil {
		return nil, err
	}
	encoded, err := (protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}).Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("marshal portable Facts document: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("decode portable Facts document: %w", err)
	}
	if document == nil {
		return nil, errors.New("portable Facts document is not an object")
	}
	return document, nil
}

func validatePortableProto(message protoreflect.Message) error {
	if !message.IsValid() {
		return errors.New("portable Facts document contains an invalid message")
	}
	fields := message.Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		value := message.Get(field)
		if field.IsList() {
			list := value.List()
			for item := 0; item < list.Len(); item++ {
				switch field.Kind() {
				case protoreflect.EnumKind:
					if field.Enum().Values().ByNumber(list.Get(item).Enum()) == nil {
						return fmt.Errorf("portable Facts field %s has an unknown enum value", field.FullName())
					}
				case protoreflect.MessageKind:
					if err := validatePortableProto(list.Get(item).Message()); err != nil {
						return err
					}
				}
			}
			continue
		}
		switch field.Kind() {
		case protoreflect.EnumKind:
			if field.Enum().Values().ByNumber(value.Enum()) == nil {
				return fmt.Errorf("portable Facts field %s has an unknown enum value", field.FullName())
			}
		case protoreflect.MessageKind:
			if message.Has(field) {
				if err := validatePortableProto(value.Message()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type portableTranslator struct {
	checked       *cel.Ast
	factory       celast.ExprFactory
	messages      map[string]protoreflect.MessageDescriptor
	enumConstants map[string]protoreflect.EnumValueDescriptor
	nextIter      int
}

func translatePortableCheckedAST(checked *cel.Ast) (string, bool) {
	if checked == nil || checked.NativeRep() == nil || !checked.IsChecked() {
		return "", false
	}
	translator := &portableTranslator{
		checked:       checked,
		factory:       celast.NewExprFactory(),
		messages:      make(map[string]protoreflect.MessageDescriptor),
		enumConstants: make(map[string]protoreflect.EnumValueDescriptor),
	}
	translator.addFile(semanticpb.File_facts_proto)
	rewritten, ok := translator.rewrite(checked.NativeRep().Expr(), nil)
	if !ok {
		return "", false
	}
	canonical, err := parser.Unparse(rewritten, celast.NewSourceInfo(nil))
	if err != nil {
		return "", false
	}
	return canonical, true
}

func (t *portableTranslator) addFile(file protoreflect.FileDescriptor) {
	var addEnums func(protoreflect.EnumDescriptors)
	addEnums = func(enums protoreflect.EnumDescriptors) {
		for index := 0; index < enums.Len(); index++ {
			enum := enums.Get(index)
			for valueIndex := 0; valueIndex < enum.Values().Len(); valueIndex++ {
				value := enum.Values().Get(valueIndex)
				name := string(enum.FullName()) + "." + string(value.Name())
				t.enumConstants[name] = value
			}
		}
	}
	var addMessages func(protoreflect.MessageDescriptors)
	addMessages = func(messages protoreflect.MessageDescriptors) {
		for index := 0; index < messages.Len(); index++ {
			message := messages.Get(index)
			t.messages[string(message.FullName())] = message
			addEnums(message.Enums())
			addMessages(message.Messages())
		}
	}
	addEnums(file.Enums())
	addMessages(file.Messages())
}

func (t *portableTranslator) rewrite(
	expr celast.Expr,
	scope map[string]string,
) (celast.Expr, bool) {
	if expr == nil || !t.allowedType(t.checked.NativeRep().GetType(expr.ID())) {
		return nil, false
	}
	if reference, ok := t.checked.NativeRep().ReferenceMap()[expr.ID()]; ok &&
		reference.Value != nil {
		value := t.enumConstants[reference.Name]
		if value == nil {
			return nil, false
		}
		return t.factory.NewLiteral(expr.ID(), types.String(value.Name())), true
	}

	switch expr.Kind() {
	case celast.CallKind:
		call := expr.AsCall()
		if !t.allowedCall(call) {
			return nil, false
		}
		arguments := make([]celast.Expr, 0, len(call.Args()))
		for _, argument := range call.Args() {
			rewritten, ok := t.rewrite(argument, scope)
			if !ok {
				return nil, false
			}
			arguments = append(arguments, rewritten)
		}
		if call.IsMemberFunction() {
			target, ok := t.rewrite(call.Target(), scope)
			if !ok {
				return nil, false
			}
			return t.factory.NewMemberCall(expr.ID(), call.FunctionName(), target, arguments...), true
		}
		return t.factory.NewCall(expr.ID(), call.FunctionName(), arguments...), true

	case celast.ComprehensionKind:
		return t.rewriteExists(expr, scope)

	case celast.IdentKind:
		name := expr.AsIdent()
		if translated, ok := scope[name]; ok {
			return t.factory.NewIdent(expr.ID(), translated), true
		}
		reference := t.checked.NativeRep().ReferenceMap()[expr.ID()]
		factsName := string((&semanticpb.Facts{}).ProtoReflect().Descriptor().FullName())
		if name == "f" && reference != nil && reference.Name == "f" &&
			t.checked.NativeRep().GetType(expr.ID()).TypeName() == factsName {
			return t.factory.NewIdent(expr.ID(), "input"), true
		}
		return nil, false

	case celast.ListKind:
		list := expr.AsList()
		if len(list.OptionalIndices()) != 0 {
			return nil, false
		}
		elements := make([]celast.Expr, 0, list.Size())
		for _, element := range list.Elements() {
			rewritten, ok := t.rewrite(element, scope)
			if !ok {
				return nil, false
			}
			elements = append(elements, rewritten)
		}
		return t.factory.NewList(expr.ID(), elements, nil), true

	case celast.LiteralKind:
		switch value := expr.AsLiteral().(type) {
		case types.Bool, types.String:
			return t.factory.NewLiteral(expr.ID(), value), true
		case types.Int:
			return t.factory.NewLiteral(
				expr.ID(),
				types.String(strconv.FormatInt(int64(value), 10)),
			), true
		default:
			return nil, false
		}

	case celast.SelectKind:
		selection := expr.AsSelect()
		if selection.IsTestOnly() {
			return nil, false
		}
		operandType := t.checked.NativeRep().GetType(selection.Operand().ID())
		message := t.messages[operandType.TypeName()]
		if message == nil ||
			message.Fields().ByName(protoreflect.Name(selection.FieldName())) == nil {
			return nil, false
		}
		operand, ok := t.rewrite(selection.Operand(), scope)
		if !ok {
			return nil, false
		}
		return t.factory.NewSelect(expr.ID(), operand, selection.FieldName()), true

	default:
		return nil, false
	}
}

func (t *portableTranslator) rewriteExists(
	expr celast.Expr,
	scope map[string]string,
) (celast.Expr, bool) {
	comprehension := expr.AsComprehension()
	if comprehension.HasIterVar2() ||
		comprehension.IterVar() == "" ||
		comprehension.AccuVar() == "" ||
		!isBoolLiteral(comprehension.AccuInit(), false) ||
		!isAccumulatorIdent(comprehension.Result(), comprehension.AccuVar()) ||
		!isExistsCondition(comprehension.LoopCondition(), comprehension.AccuVar()) {
		return nil, false
	}
	step := comprehension.LoopStep()
	if step.Kind() != celast.CallKind {
		return nil, false
	}
	stepCall := step.AsCall()
	if stepCall.IsMemberFunction() ||
		stepCall.FunctionName() != operators.LogicalOr ||
		len(stepCall.Args()) != 2 ||
		!isAccumulatorIdent(stepCall.Args()[0], comprehension.AccuVar()) {
		return nil, false
	}
	iterType := t.checked.NativeRep().GetType(comprehension.IterRange().ID())
	if iterType.Kind() != types.ListKind ||
		!t.checked.NativeRep().GetType(stepCall.Args()[1].ID()).IsExactType(types.BoolType) {
		return nil, false
	}
	rangeExpr, ok := t.rewrite(comprehension.IterRange(), scope)
	if !ok {
		return nil, false
	}
	iterName := "item" + strconv.Itoa(t.nextIter)
	t.nextIter++
	nested := clonePortableScope(scope)
	nested[comprehension.IterVar()] = iterName
	predicate, ok := t.rewrite(stepCall.Args()[1], nested)
	if !ok {
		return nil, false
	}
	return t.factory.NewMemberCall(
		expr.ID(),
		operators.Exists,
		rangeExpr,
		t.factory.NewIdent(expr.ID(), iterName),
		predicate,
	), true
}

func (t *portableTranslator) allowedType(valueType *types.Type) bool {
	if valueType == nil {
		return false
	}
	switch valueType.Kind() {
	case types.BoolKind, types.IntKind, types.StringKind:
		return true
	case types.ListKind:
		parameters := valueType.Parameters()
		return len(parameters) == 1 && t.allowedType(parameters[0])
	case types.StructKind:
		_, ok := t.messages[valueType.TypeName()]
		return ok
	default:
		return false
	}
}

func (t *portableTranslator) allowedCall(call celast.CallExpr) bool {
	operands := call.Args()
	if call.IsMemberFunction() {
		operands = append([]celast.Expr{call.Target()}, operands...)
	}
	allExact := func(kind types.Kind) bool {
		for _, operand := range operands {
			if t.checked.NativeRep().GetType(operand.ID()).Kind() != kind {
				return false
			}
		}
		return true
	}
	switch call.FunctionName() {
	case operators.LogicalAnd, operators.LogicalOr:
		return !call.IsMemberFunction() && len(operands) == 2 && allExact(types.BoolKind)
	case operators.LogicalNot:
		return !call.IsMemberFunction() && len(operands) == 1 && allExact(types.BoolKind)
	case operators.Equals, operators.NotEquals:
		if call.IsMemberFunction() || len(operands) != 2 {
			return false
		}
		leftType := t.checked.NativeRep().GetType(operands[0].ID())
		rightType := t.checked.NativeRep().GetType(operands[1].ID())
		return isPortableScalar(leftType) && isPortableScalar(rightType) &&
			leftType.Kind() == rightType.Kind()
	case operators.In, operators.OldIn:
		if call.IsMemberFunction() || len(operands) != 2 ||
			!isPortableScalar(t.checked.NativeRep().GetType(operands[0].ID())) {
			return false
		}
		listType := t.checked.NativeRep().GetType(operands[1].ID())
		return listType.Kind() == types.ListKind && len(listType.Parameters()) == 1 &&
			isPortableScalar(listType.Parameters()[0]) &&
			t.checked.NativeRep().GetType(operands[0].ID()).Kind() == listType.Parameters()[0].Kind()
	case overloads.StartsWith, overloads.EndsWith, overloads.Contains, overloads.Matches:
		return call.IsMemberFunction() && len(operands) == 2 && allExact(types.StringKind)
	default:
		return false
	}
}

func isPortableScalar(valueType *types.Type) bool {
	if valueType == nil {
		return false
	}
	switch valueType.Kind() {
	case types.BoolKind, types.IntKind, types.StringKind:
		return true
	default:
		return false
	}
}

func isBoolLiteral(expr celast.Expr, want bool) bool {
	if expr == nil || expr.Kind() != celast.LiteralKind {
		return false
	}
	value, ok := expr.AsLiteral().(types.Bool)
	return ok && bool(value) == want
}

func isAccumulatorIdent(expr celast.Expr, name string) bool {
	return expr != nil && expr.Kind() == celast.IdentKind && expr.AsIdent() == name
}

func isExistsCondition(expr celast.Expr, accumulator string) bool {
	if expr == nil || expr.Kind() != celast.CallKind {
		return false
	}
	outer := expr.AsCall()
	if outer.IsMemberFunction() || outer.FunctionName() != operators.NotStrictlyFalse ||
		len(outer.Args()) != 1 || outer.Args()[0].Kind() != celast.CallKind {
		return false
	}
	inner := outer.Args()[0].AsCall()
	return !inner.IsMemberFunction() && inner.FunctionName() == operators.LogicalNot &&
		len(inner.Args()) == 1 && isAccumulatorIdent(inner.Args()[0], accumulator)
}

func clonePortableScope(scope map[string]string) map[string]string {
	cloned := make(map[string]string, len(scope)+1)
	for name, translated := range scope {
		cloned[name] = translated
	}
	return cloned
}
