// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// Tier 2 of the port: class and enum definitions (Parser.cs ClassDefinitionRule,
// ClassMemberRule, EnumDefinitionRule, EnumMemberRule, MethodDeclarationRule).

// nestedTypeConstraints returns the TypeConstraintAst entries of a statement's attribute list.
func nestedTypeConstraints(attrs []*Node) []*Node {
	var out []*Node
	for _, a := range attrs {
		if a.Type == "TypeConstraintAst" {
			out = append(out, a)
		}
	}
	return out
}

func attributeAsts(attrs []*Node) []*Node {
	var out []*Node
	for _, a := range attrs {
		if a.Type == "AttributeAst" {
			out = append(out, a)
		}
	}
	return out
}

func typeConstraintOf(t *typeName) *Node {
	n := newNode("TypeConstraintAst", t.ext)
	n.prop("TypeName", t.fullName())
	return n
}

func (p *Parser) classDefinitionRule(customAttributes []*Node, classToken *Token) *Node {
	p.skipNewlines()
	name, classNameToken := p.simpleNameRuleTok()
	if name == nil {
		p.reportIncomplete(after(tokExt(classToken)), "MissingNameAfterKeyword")
		return newErrorStmt(tokExt(classToken))
	}
	classNameToken.Flags &^= tfMemberName
	classNameToken.Flags |= tfTypeName
	p.skipNewlines()
	oldMode := p.tz.mode
	defer p.setTokenizerMode(oldMode)
	var superClasses []*Node
	p.setTokenizerMode(modeSignature)
	colonToken := p.peekToken()
	if colonToken.Kind == TkColon {
		p.skipToken()
		p.skipNewlines()
		var commaToken *Token
		for {
			superClass, _ := p.typeNameRule(false)
			if superClass == nil {
				var e extent
				if commaToken != nil {
					e = tokExt(commaToken)
				} else {
					e = tokExt(colonToken)
				}
				p.reportIncomplete(after(e), "TypeNameExpected")
				break
			}
			superClasses = append(superClasses, typeConstraintOf(superClass))
			p.skipNewlines()
			commaToken = p.peekToken()
			if commaToken.Kind == TkComma {
				p.skipToken()
				p.skipNewlines()
			} else {
				break
			}
		}
	}
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		lastElement := name.ext()
		if len(superClasses) > 0 {
			lastElement = superClasses[len(superClasses)-1].ext()
		}
		p.reportIncomplete(after(lastElement), "MissingTypeBody")
		return newErrorStmt(extentOf(tokExt(classToken), lastElement), superClasses...)
	}
	lastExtent := tokExt(lCurly)
	var nested []*Node
	var members []*Node
	classNameText := name.Str
	for {
		member, astsOnError := p.classMemberRule(classNameText)
		if member == nil && astsOnError == nil {
			break
		}
		if member != nil {
			members = append(members, member)
			lastExtent = member.ext()
		}
		if len(astsOnError) > 0 {
			nested = append(nested, astsOnError...)
			lastExtent = astsOnError[len(astsOnError)-1].ext()
		}
	}
	rCurly := p.nextToken()
	if rCurly.Kind != TkRCurly {
		p.ungetToken(rCurly)
		p.reportIncompleteAt(after(tokExt(lCurly)), tokExt(rCurly), "MissingEndCurlyBrace")
	} else {
		lastExtent = tokExt(rCurly)
	}
	startExtent := tokExt(classToken)
	if len(customAttributes) > 0 {
		startExtent = customAttributes[0].ext()
	}
	e := extentOf(startExtent, lastExtent)
	classDefn := newNode("TypeDefinitionAst", e)
	classDefn.Kids = append(classDefn.Kids, attributeAsts(customAttributes)...)
	classDefn.Kids = append(classDefn.Kids, superClasses...)
	classDefn.Kids = append(classDefn.Kids, members...)
	if tcs := nestedTypeConstraints(customAttributes); len(tcs) > 0 {
		nested = append(nested, tcs...)
		nested = append(nested, classDefn)
	}
	if len(nested) > 0 {
		return newErrorStmt(e, nested...)
	}
	return classDefn
}

func (p *Parser) classMemberRule(className string) (member *Node, astsOnError []*Node) {
	startExtent := emptyExtent
	var attributeList []*Node
	var typeConstraint *Node
	scanning := true
	var staticToken, hiddenToken, token *Token
	lastAttr := emptyExtent
	for scanning {
		p.skipNewlines()
		attribute := p.attributeRule()
		if attribute != nil {
			lastAttr = attribute.ext()
			if startExtent.empty() {
				startExtent = attribute.ext()
			}
			if attribute.Type == "AttributeAst" {
				attributeList = append(attributeList, attribute)
			} else if typeConstraint == nil {
				typeConstraint = attribute
			} else {
				p.reportError(attribute.ext(), "TooManyTypes")
			}
			continue
		}
		token = p.peekToken()
		if startExtent.empty() {
			startExtent = tokExt(token)
		}
		switch token.Kind {
		case TkHidden:
			if hiddenToken != nil {
				p.reportError(tokExt(token), "DuplicateQualifier")
			}
			hiddenToken = token
			lastAttr = tokExt(token)
			p.skipToken()
		case TkStatic:
			if staticToken != nil {
				p.reportError(tokExt(token), "DuplicateQualifier")
			}
			staticToken = token
			lastAttr = tokExt(token)
			p.skipToken()
		default:
			scanning = false
		}
	}
	recordErrors := func() {
		astsOnError = append(astsOnError, attributeList...)
		if typeConstraint != nil {
			astsOnError = append(astsOnError, typeConstraint)
		}
	}
	if token.Kind == TkVariable {
		p.skipToken()
		var initial *Node
		assignToken := p.peekToken()
		if assignToken.Kind == TkEquals {
			p.skipToken()
			p.skipNewlines()
			initial = p.expressionRule()
		}
		endExtent := tokExt(token)
		if initial != nil {
			endExtent = initial.ext()
		}
		terminator := p.peekToken()
		if terminator.Kind != TkNewLine && terminator.Kind != TkSemi && terminator.Kind != TkRCurly {
			p.reportIncomplete(after(endExtent), "MissingPropertyTerminator")
		}
		p.skipNewlinesAndSemicolons()
		if terminator.Kind == TkSemi {
			endExtent = tokExt(terminator)
		}
		if token.Path != nil && token.Path.UserPath != "" {
			return newPropertyMember(extentOf(startExtent, endExtent), token.Path.UserPath, typeConstraint, attributeList, initial), nil
		}
		recordErrors()
		if initial != nil {
			astsOnError = append(astsOnError, initial)
		}
		return nil, astsOnError
	}
	if token.Kind == TkIdentifier || token.Kind == TkDynamicKeyword || token.Flags&tfKeyword != 0 {
		token.Flags = 0
		p.skipToken()
		functionDefinition := p.methodDeclarationRule(token, className, staticToken != nil)
		if functionDefinition == nil || functionDefinition.Type != "FunctionDefinitionAst" {
			p.syncOnError(false, TkRCurly)
			recordErrors()
			return nil, astsOnError
		}
		n := newNode("FunctionMemberAst", extentOf(startExtent, functionDefinition.ext()))
		n.Kids = append(n.Kids, attributeList...)
		if typeConstraint != nil {
			n.Kids = append(n.Kids, typeConstraint)
		}
		n.Kids = append(n.Kids, functionDefinition)
		return n, nil
	}
	if !lastAttr.empty() {
		p.reportIncomplete(after(lastAttr), "IncompleteMemberDefinition")
		recordErrors()
	}
	return nil, astsOnError
}

// newPropertyMember builds a PropertyMemberAst (visit order: type constraint, attributes, initial value).
func newPropertyMember(e extent, name string, typeConstraint *Node, attrs []*Node, initial *Node) *Node {
	n := newNode("PropertyMemberAst", e)
	if typeConstraint != nil {
		n.Kids = append(n.Kids, typeConstraint)
	}
	n.Kids = append(n.Kids, attrs...)
	if initial != nil {
		n.Kids = append(n.Kids, initial)
	}
	return n
}

func (p *Parser) methodDeclarationRule(functionNameToken *Token, className string, isStatic bool) *Node {
	functionName := p.tokText(functionNameToken)
	var parameters []*Node
	lParen := p.peekToken()
	endErrorStatement := emptyExtent
	var rParen *Token
	if lParen.Kind == TkLParen {
		parameters, endErrorStatement, rParen = p.functionParameterDeclarationRule()
	} else {
		p.reportIncomplete(after(tokExt(functionNameToken)), "MissingMethodParameterList")
	}
	isCtor := strings.EqualFold(functionName, className)
	var baseCtorCallParams []*Node
	var baseToken *Token
	baseCallLastExtent := emptyExtent
	if isCtor && !isStatic {
		p.skipNewlines()
		oldMode := p.tz.mode
		p.setTokenizerMode(modeSignature)
		colonToken := p.peekToken()
		if colonToken.Kind == TkColon {
			p.skipToken()
			p.skipNewlines()
			baseToken = p.peekToken()
			if baseToken.Kind == TkBase {
				p.skipToken()
				p.skipNewlines()
				lParen = p.peekToken()
				if lParen.Kind == TkLParen {
					p.skipToken()
					baseCtorCallParams, baseCallLastExtent = p.invokeParamParenListRule(lParen)
					p.skipNewlines()
				} else {
					endErrorStatement = tokExt(baseToken)
					p.reportIncomplete(after(tokExt(baseToken)), "MissingMethodParameterList")
				}
			} else {
				endErrorStatement = tokExt(colonToken)
				p.reportIncomplete(after(tokExt(colonToken)), "MissingBaseCtorCall")
			}
		}
		p.setTokenizerMode(oldMode)
	}
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		if endErrorStatement.empty() {
			endErrorStatement = firstOf(tx(rParen), tokExt(functionNameToken))
			p.reportIncomplete(after(endErrorStatement), "MissingFunctionBody")
		}
	}
	if !endErrorStatement.empty() {
		return newErrorStmt(extentOf(tokExt(functionNameToken), endErrorStatement), parameters...)
	}
	var baseCtorCallStatement *Node
	if isCtor && !isStatic {
		callExtent := extent{0, 0}
		keywordExtent := extent{0, 0}
		if baseToken != nil {
			callExtent = extentOf(tokExt(baseToken), baseCallLastExtent)
			keywordExtent = tokExt(baseToken)
		}
		inv := newNode("BaseCtorInvokeMemberExpressionAst", callExtent,
			newVariableNode(keywordExtent, "this", false),
			newStringConst(keywordExtent, ".ctor", "BareWord"))
		inv.Kids = append(inv.Kids, baseCtorCallParams...)
		inv.prop("Static", "false").prop("NullConditional", "false")
		baseCtorCallStatement = newNode("CommandExpressionAst", inv.ext(), inv)
	}
	oldMode := p.tz.mode
	p.setTokenizerMode(modeCommand)
	scriptBlock := p.scriptBlockRule(lCurly, false, baseCtorCallStatement)
	p.setTokenizerMode(oldMode)
	name := functionName
	n := newNode("FunctionDefinitionAst", extentOf(tokExt(functionNameToken), scriptBlock.ext()))
	n.prop("Name", name).prop("IsFilter", "false").prop("IsWorkflow", "false")
	n.Kids = append(n.Kids, parameters...)
	n.Kids = append(n.Kids, scriptBlock)
	return n
}

func (p *Parser) enumDefinitionRule(customAttributes []*Node, enumToken *Token) *Node {
	p.skipNewlines()
	name := p.simpleNameRule()
	if name == nil {
		p.reportIncomplete(after(tokExt(enumToken)), "MissingNameAfterKeyword")
		return newErrorStmt(tokExt(enumToken))
	}
	oldMode := p.tz.mode
	defer p.setTokenizerMode(oldMode)
	var underlying *Node
	p.setTokenizerMode(modeSignature)
	colonToken := p.peekToken()
	if colonToken.Kind == TkColon {
		p.skipToken()
		p.skipNewlines()
		underlyingType, _ := p.typeNameRule(false)
		if underlyingType == nil {
			p.reportIncomplete(after(tokExt(colonToken)), "TypeNameExpected")
		} else {
			if !validEnumUnderlyingType(underlyingType.fullName()) {
				p.reportError(underlyingType.ext, "InvalidUnderlyingType")
			}
			underlying = typeConstraintOf(underlyingType)
		}
	}
	p.skipNewlines()
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		p.reportIncomplete(after(name.ext()), "MissingTypeBody")
		return newErrorStmt(extentOf(tokExt(enumToken), name.ext()))
	}
	var members []*Node
	for {
		m := p.enumMemberRule()
		if m == nil {
			break
		}
		members = append(members, m)
	}
	rCurly := p.nextToken()
	if rCurly.Kind != TkRCurly {
		p.ungetToken(rCurly)
		p.reportIncompleteAt(after(tokExt(lCurly)), tokExt(rCurly), "MissingEndCurlyBrace")
	}
	startExtent := tokExt(enumToken)
	if len(customAttributes) > 0 {
		startExtent = customAttributes[0].ext()
	}
	e := extentOf(startExtent, tokExt(rCurly))
	enumDefn := newNode("TypeDefinitionAst", e)
	enumDefn.Kids = append(enumDefn.Kids, attributeAsts(customAttributes)...)
	if underlying != nil {
		enumDefn.Kids = append(enumDefn.Kids, underlying)
	}
	enumDefn.Kids = append(enumDefn.Kids, members...)
	if tcs := nestedTypeConstraints(customAttributes); len(tcs) > 0 {
		nested := append(append([]*Node{}, tcs...), enumDefn)
		return newErrorStmt(startExtent, nested...)
	}
	return enumDefn
}

// validEnumUnderlyingType mirrors the TypeCode check of EnumDefinitionRule by type name.
func validEnumUnderlyingType(name string) bool {
	switch strings.ToLower(strings.TrimPrefix(strings.ToLower(name), "system.")) {
	case "byte", "int16", "int32", "int64", "sbyte", "uint16", "uint32", "uint64",
		"short", "int", "long", "ushort", "uint", "ulong":
		return true
	}
	return false
}

func (p *Parser) enumMemberRule() *Node {
	p.skipNewlines()
	enumeratorName := p.simpleNameRule()
	if enumeratorName == nil {
		return nil
	}
	endExtent := enumeratorName.ext()
	var initial *Node
	missingInitializer := false
	oldMode := p.tz.mode
	p.setTokenizerMode(modeExpression)
	assignToken := p.peekToken()
	if assignToken.Kind == TkEquals {
		p.skipToken()
		initial = p.expressionRule()
		if initial == nil {
			p.reportError(after(tokExt(assignToken)), "ExpectedValueExpression")
			endExtent = tokExt(assignToken)
			missingInitializer = true
		} else {
			endExtent = initial.ext()
		}
	}
	p.setTokenizerMode(oldMode)
	terminator := p.peekToken()
	if terminator.Kind != TkNewLine && terminator.Kind != TkSemi && terminator.Kind != TkRCurly && !missingInitializer {
		p.reportIncomplete(after(endExtent), "MissingPropertyTerminator")
	}
	p.skipNewlinesAndSemicolons()
	if terminator.Kind == TkSemi {
		endExtent = tokExt(terminator)
	}
	return newPropertyMember(extentOf(enumeratorName.ext(), endExtent), enumeratorName.Str, nil, nil, initial)
}
