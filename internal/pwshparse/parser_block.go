// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

// Script blocks, param blocks, attributes and type names (Parser.cs ScriptBlockRule .. CompleteArrayTypeName).

func (p *Parser) tokText(t *Token) string { return p.textOf(tokExt(t)) }

// column is the 1-based column of a UTF-16 offset (PositionUtilities).
func (p *Parser) column(off int) int {
	if off > len(p.src) {
		off = len(p.src)
	}
	i := off
	for i > 0 && p.src[i-1] != '\n' && p.src[i-1] != '\r' {
		i--
	}
	return off - i + 1
}

func (p *Parser) scriptBlockRule(lCurly *Token, isFilter bool, predefined *Node) *Node {
	p.skipNewlines()
	var usings []*Node
	if lCurly == nil {
		usings = p.usingStatementsRule()
	}
	restore := p.tz.getRestorePoint()
	paramBlock := p.paramBlockRule()
	if paramBlock == nil {
		p.resync(restore)
	}
	p.skipNewlinesAndSemicolons()
	return p.scriptBlockBodyRule(lCurly, usings, paramBlock, isFilter, predefined)
}

func (p *Parser) usingStatementsRule() []*Node {
	var result []*Node
	for {
		token := p.peekToken()
		if token.Kind == TkUsing {
			p.skipToken()
			st := p.usingStatementRule(token)
			p.skipNewlinesAndSemicolons()
			if st != nil && st.Type == "UsingStatementAst" {
				result = append(result, st)
			}
			continue
		}
		p.resyncToken(token)
		break
	}
	return result
}

func (p *Parser) paramBlockRule() *Node {
	p.skipNewlines()
	candidates := p.attributeListRule(false)
	p.skipNewlines()
	paramToken := p.peekToken()
	if paramToken.Kind != TkParam {
		return nil
	}
	p.skipToken()
	p.skipNewlines()
	lparen := p.nextToken()
	if lparen.Kind != TkLParen {
		p.ungetToken(lparen)
		return nil
	}
	parameters := p.parameterListRule()
	p.skipNewlines()
	rParen := p.nextToken()
	endExtent := tokExt(rParen)
	if rParen.Kind != TkRParen {
		p.ungetToken(rParen)
		endExtent = before(tokExt(rParen))
		var at extent
		if len(parameters) > 0 {
			at = after(parameters[len(parameters)-1].ext())
		} else {
			at = after(tokExt(lparen))
		}
		p.reportIncomplete(at, "MissingEndParenthesisInFunctionParameterList")
	}
	var attrs []*Node
	for _, a := range candidates {
		if a.Type == "AttributeAst" {
			attrs = append(attrs, a)
		} else {
			p.reportError(a.ext(), "TypeNotAllowedBeforeParam")
		}
	}
	n := newNode("ParamBlockAst", extentOf(tokExt(paramToken), endExtent))
	n.Kids = append(n.Kids, attrs...)
	n.Kids = append(n.Kids, parameters...)
	return n
}

func (p *Parser) parameterListRule() []*Node {
	var parameters []*Node
	var commaToken *Token
	for {
		parameter := p.parameterRule()
		if parameter == nil {
			if commaToken != nil {
				p.reportIncomplete(after(tokExt(commaToken)), "MissingExpressionAfterToken")
			}
			break
		}
		parameters = append(parameters, parameter)
		p.skipNewlines()
		commaToken = p.peekToken()
		if commaToken.Kind != TkComma {
			break
		}
		p.skipToken()
	}
	return parameters
}

func (p *Parser) parameterRule() *Node {
	oldDisable := p.disableComma
	oldMode := p.tz.mode
	defer func() {
		p.disableComma = oldDisable
		p.setTokenizerMode(oldMode)
	}()
	p.disableComma = true
	p.setTokenizerMode(modeExpression)
	p.skipNewlines()
	attributes := p.attributeListRule(false)
	p.skipNewlines()
	token := p.nextToken()
	if token.Kind != TkVariable && token.Kind != TkSplattedVariable {
		p.ungetToken(token)
		if attributes != nil {
			p.reportIncomplete(after(attributes[len(attributes)-1].ext()), "InvalidFunctionParameter")
			p.syncOnError(true, TkRParen)
			e := extentOf(attributes[0].ext(), attributes[len(attributes)-1].ext())
			n := newNode("ParameterAst", e)
			n.Kids = append(n.Kids, attributes...)
			n.Kids = append(n.Kids, newVariableNode(e, "__error__", false))
			return n
		}
		return nil
	}
	variableToken := token
	p.skipNewlines()
	var defaultValue *Node
	equalsToken := p.peekToken()
	if equalsToken.Kind == TkEquals {
		p.skipToken()
		p.skipNewlines()
		defaultValue = p.expressionRule()
		if defaultValue == nil {
			p.reportIncomplete(after(tokExt(equalsToken)), "MissingExpressionAfterToken")
		}
	}
	startExtent := tokExt(variableToken)
	if attributes != nil {
		startExtent = attributes[0].ext()
	}
	endExtent := tokExt(variableToken)
	if defaultValue != nil {
		endExtent = defaultValue.ext()
	}
	n := newNode("ParameterAst", extentOf(startExtent, endExtent))
	n.Kids = append(n.Kids, attributes...)
	n.Kids = append(n.Kids, p.variableFromToken(variableToken))
	if defaultValue != nil {
		n.Kids = append(n.Kids, defaultValue)
	}
	return n
}

// variableFromToken is new VariableExpressionAst(VariableToken).
func (p *Parser) variableFromToken(t *Token) *Node {
	return newVariableNode(tokExt(t), t.Path.UserPath, t.Kind == TkSplattedVariable)
}

func (p *Parser) attributeListRule(inExpressionMode bool) []*Node {
	var attributes []*Node
	attribute := p.attributeRule()
	for attribute != nil {
		attributes = append(attributes, attribute)
		if !inExpressionMode || attribute.Type == "AttributeAst" {
			p.skipNewlines()
		}
		attribute = p.attributeRule()
	}
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func (p *Parser) attributeRule() *Node {
	lBracket := p.nextLBracket()
	if lBracket == nil {
		return nil
	}
	p.skipNewlines()
	typeName, firstTypeNameToken := p.typeNameRule(true)
	if typeName == nil {
		p.resyncToken(lBracket)
		p.reportIncomplete(after(tokExt(lBracket)), "MissingTypename")
		return nil
	}
	lParenOrRBracket := p.nextToken()
	if lParenOrRBracket.Kind == TkLParen {
		p.skipNewlines()
		var positional, named []*Node
		lastItemExtent := tokExt(lParenOrRBracket)
		oldMode := p.tz.mode
		p.setTokenizerMode(modeExpression)
		p.attributeArgumentsRule(&positional, &named, &lastItemExtent)
		p.setTokenizerMode(oldMode)
		p.skipNewlines()
		rParen := p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			rParen = nil
			p.reportIncomplete(after(lastItemExtent), "MissingEndParenthesisInExpression")
		}
		p.skipNewlines()
		rBracket := p.nextToken()
		if rBracket.Kind != TkRBracket {
			p.ungetToken(rBracket)
			rBracket = nil
			if rParen != nil {
				p.reportIncomplete(after(tokExt(rParen)), "EndSquareBracketExpectedAtEndOfAttribute")
			}
		}
		firstTypeNameToken.Flags |= tfAttributeName
		n := newNode("AttributeAst", extentOf(tokExt(lBracket), firstOf(tx(rBracket), tx(rParen), lastItemExtent)))
		n.prop("TypeName", typeName.fullName())
		n.Kids = append(n.Kids, positional...)
		n.Kids = append(n.Kids, named...)
		return n
	}
	if lParenOrRBracket.Kind != TkRBracket {
		p.ungetToken(lParenOrRBracket)
		p.reportError(before(tokExt(lParenOrRBracket)), "EndSquareBracketExpectedAtEndOfAttribute")
		lParenOrRBracket = nil
	}
	n := newNode("TypeConstraintAst", extentOf(tokExt(lBracket), firstOf(tx(lParenOrRBracket), typeName.ext)))
	n.prop("TypeName", typeName.fullName())
	return n
}

func (p *Parser) attributeArgumentsRule(positional, named *[]*Node, lastItemExtent *extent) {
	oldDisable := p.disableComma
	defer func() { p.disableComma = oldDisable }()
	var commaToken *Token
	keysSeen := map[string]bool{}
	p.disableComma = true
	for {
		p.skipNewlines()
		name := p.simpleNameRule()
		var expr *Node
		expressionOmitted := false
		if name != nil {
			token := p.peekToken()
			if token.Kind == TkEquals {
				token = p.nextToken()
				p.skipNewlines()
				expr = p.expressionRule()
				if expr == nil {
					errPos := after(tokExt(token))
					p.reportIncomplete(errPos, "MissingExpressionInNamedArgument")
					expr = newErrorExpr(errPos)
					p.syncOnError(true, TkComma, TkRParen, TkRBracket, TkNewLine)
				}
				*lastItemExtent = expr.ext()
			} else {
				expr = newConstBool(name.ext(), true)
				expressionOmitted = true
			}
		} else {
			expr = p.expressionRule()
		}
		if name != nil {
			if keysSeen[name.Str] {
				p.reportError(name.ext(), "DuplicateNamedArgument")
			} else {
				keysSeen[name.Str] = true
				n := newNode("NamedAttributeArgumentAst", extentOf(name.ext(), expr.ext()), expr)
				n.prop("ArgumentName", name.Str).prop("ExpressionOmitted", boolStr(expressionOmitted))
				*named = append(*named, n)
			}
		} else if expr != nil {
			*positional = append(*positional, expr)
			*lastItemExtent = expr.ext()
		} else if commaToken != nil {
			errorExtent := after(tokExt(commaToken))
			p.reportIncomplete(errorExtent, "MissingExpressionAfterToken")
			*positional = append(*positional, newErrorExpr(errorExtent))
			*lastItemExtent = errorExtent
		}
		p.skipNewlines()
		commaToken = p.peekToken()
		if commaToken.Kind != TkComma {
			break
		}
		*lastItemExtent = tokExt(commaToken)
		p.skipToken()
	}
}

// typeNameRule parses a type name; the second result is its first identifier token.
func (p *Parser) typeNameRule(allowAssemblyQualified bool) (*typeName, *Token) {
	oldMode := p.tz.mode
	defer p.setTokenizerMode(oldMode)
	p.setTokenizerMode(modeTypeName)
	tn := p.nextToken()
	if tn.Kind != TkIdentifier {
		p.ungetToken(tn)
		return nil, nil
	}
	return p.finishTypeNameRule(tn, false, allowAssemblyQualified), tn
}

func (p *Parser) finishTypeNameRule(tn *Token, unBracketedGenericArg, allowAssemblyQualified bool) *typeName {
	token := p.peekToken()
	if token.Kind == TkLBracket {
		lbracket := token
		p.skipToken()
		p.skipNewlines()
		token = p.nextToken()
		switch token.Kind {
		case TkRBracket, TkComma:
			elem := newTypeName(tokExt(tn), p.tokText(tn))
			return p.completeArrayTypeName(elem, elem, token, unBracketedGenericArg)
		case TkLBracket, TkIdentifier:
			return p.genericTypeNameRule(tn, token, unBracketedGenericArg)
		default:
			if token.Kind != TkEndOfInput {
				p.reportError(tokExt(token), "UnexpectedToken")
				p.syncOnError(true, TkRBracket)
			} else {
				p.ungetToken(token)
				p.reportIncomplete(after(tokExt(lbracket)), "MissingTypename")
			}
			return newTypeName(tokExt(tn), p.tokText(tn))
		}
	}
	if token.Kind == TkComma && allowAssemblyQualified && !unBracketedGenericArg {
		p.skipToken()
		spec := p.tz.getAssemblyNameSpec()
		if isNullOrWhiteSpace(spec) {
			p.reportError(after(tokExt(token)), "MissingAssemblyNameSpecification")
			return newTypeName(tokExt(tn), p.tokText(tn))
		}
		return newTypeNameAsm(extentOf(tokExt(tn), p.tz.currentExtent()), p.tokText(tn), spec)
	}
	return newTypeName(tokExt(tn), p.tokText(tn))
}

func isNullOrWhiteSpace(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' && r != '\v' && r != '\f' && r != 0x85 && r != 0xa0 && (r < 0x2000 || r > 0x200a) && r != 0x1680 && r != 0x2028 && r != 0x2029 && r != 0x202f && r != 0x205f && r != 0x3000 {
			return false
		}
	}
	return true
}

func (p *Parser) getSingleGenericArgument(first *Token) *typeName {
	if first.Kind == TkIdentifier {
		return p.finishTypeNameRule(first, true, true)
	}
	token := p.nextToken()
	if token.Kind != TkIdentifier {
		p.ungetToken(token)
		p.reportIncomplete(after(tokExt(token)), "MissingTypename")
		return newTypeName(tokExt(first), ":ErrorTypeName:")
	}
	tn := p.finishTypeNameRule(token, false, true)
	if tn != nil {
		rBracket := p.nextToken()
		if rBracket.Kind != TkRBracket {
			p.ungetToken(rBracket)
			p.reportIncomplete(before(tokExt(rBracket)), "EndSquareBracketExpectedAtEndOfType")
		}
	}
	return tn
}

func (p *Parser) genericTypeArgumentsRule(first *Token) ([]*typeName, *Token) {
	var args []*typeName
	args = append(args, p.getSingleGenericArgument(first))
	var last *Token
	for {
		p.skipNewlines()
		last = p.nextToken()
		if last.Kind != TkComma {
			break
		}
		p.skipNewlines()
		token := p.peekToken()
		var tn *typeName
		if token.Kind == TkIdentifier || token.Kind == TkLBracket {
			p.skipToken()
			tn = p.getSingleGenericArgument(token)
		} else {
			p.reportIncomplete(after(tokExt(last)), "MissingTypename")
			tn = newTypeName(tokExt(last), ":ErrorTypeName:")
		}
		args = append(args, tn)
	}
	return args, last
}

func (p *Parser) genericTypeNameRule(generic, first *Token, unbracketed bool) *typeName {
	args, rBracket := p.genericTypeArgumentsRule(first)
	if rBracket.Kind != TkRBracket {
		p.ungetToken(rBracket)
		p.reportIncomplete(before(tokExt(rBracket)), "EndSquareBracketExpectedAtEndOfAttribute")
		rBracket = nil
	}
	open := newTypeName(tokExt(generic), p.tokText(generic))
	open.count = len(args)
	var lastArgExt extent
	if len(args) > 0 {
		lastArgExt = args[len(args)-1].ext
	} else {
		lastArgExt = emptyExtent
	}
	result := &typeName{
		ext:  extentOf(tokExt(generic), firstOf(tx(rBracket), lastArgExt, tokExt(first))),
		kind: 1, open: open, args: args,
	}
	token := p.peekToken()
	if token.Kind == TkLBracket {
		p.skipToken()
		return p.completeArrayTypeName(result, open, p.nextToken(), unbracketed)
	}
	if token.Kind == TkComma && !unbracketed {
		p.skipToken()
		spec := p.tz.getAssemblyNameSpec()
		if spec == "" {
			p.reportError(after(tokExt(token)), "MissingAssemblyNameSpecification")
		} else {
			open.asm = spec
		}
	}
	return result
}

func (p *Parser) completeArrayTypeName(elem, forAssembly *typeName, first *Token, unBracketed bool) *typeName {
	for {
		var token *Token
		switch first.Kind {
		case TkComma:
			dim := 1
			token = first
			var lastComma *Token
			for {
				lastComma = token
				dim++
				token = p.nextToken()
				if token.Kind != TkComma {
					break
				}
			}
			if dim > 32 {
				if token.Kind != TkRBracket {
					p.ungetToken(token)
				}
				p.reportError(extentOf(tokExt(first), tokExt(lastComma)), "ArrayHasTooManyDimensions")
				break
			}
			if token.Kind != TkRBracket {
				p.ungetToken(token)
				p.reportError(after(tokExt(lastComma)), "EndSquareBracketExpectedAtEndOfAttribute")
			}
			elem = &typeName{ext: extentOf(elem.ext, tokExt(token)), kind: 2, elem: elem, rank: dim}
		case TkRBracket:
			elem = &typeName{ext: extentOf(elem.ext, tokExt(first)), kind: 2, elem: elem, rank: 1}
		case TkEndOfInput:
			p.ungetToken(first)
			p.reportError(before(tokExt(first)), "EndSquareBracketExpectedAtEndOfAttribute")
		default:
			p.reportError(tokExt(first), "UnexpectedToken")
			p.syncOnError(true, TkRBracket)
		}
		token = p.peekToken()
		if !unBracketed && token.Kind == TkComma {
			p.skipToken()
			asm := p.tz.getAssemblyNameSpec()
			if asm == "" {
				p.reportError(after(tokExt(token)), "MissingAssemblyNameSpecification")
			} else {
				forAssembly.setAssemblyName(asm)
			}
			break
		}
		if token.Kind != TkLBracket {
			break
		}
		p.skipToken()
		first = p.nextToken()
	}
	return elem
}

// completeScriptBlockBody finishes a script block; bodyExtent is read and may be set.
func (p *Parser) completeScriptBlockBody(lCurly *Token, bodyExtent *extent) (extent, bool) {
	var full extent
	if lCurly != nil {
		rCurly := p.nextToken()
		var endScriptBlock extent
		if rCurly.Kind != TkRCurly {
			p.ungetToken(rCurly)
			if !bodyExtent.empty() {
				endScriptBlock = *bodyExtent
			} else {
				endScriptBlock = tokExt(lCurly)
			}
			p.reportIncompleteAt(tokExt(lCurly), tokExt(rCurly), "MissingEndCurlyBrace")
		} else {
			endScriptBlock = tokExt(rCurly)
			if bodyExtent.empty() && p.column(lCurly.End) != p.column(rCurly.Start) {
				*bodyExtent = extentOf(after(tokExt(lCurly)), before(tokExt(rCurly)))
			}
		}
		full = extentOf(tokExt(lCurly), endScriptBlock)
	} else {
		full = p.tz.scriptExtent()
		token := p.nextToken()
		if token.Kind != TkEndOfInput {
			p.reportError(tokExt(token), "UnexpectedToken")
			return full, false
		}
	}
	return full, true
}

func (p *Parser) scriptBlockBodyRule(lCurly *Token, usings []*Node, paramBlock *Node, isFilter bool, predefined *Node) *Node {
	token := p.peekToken()
	if token.Flags&tfScriptBlockBlockName == tfScriptBlockBlockName {
		return p.namedBlockListRule(lCurly, usings, paramBlock)
	}
	var traps, statements []*Node
	if predefined != nil {
		statements = append(statements, predefined)
	}
	stmtListExt := emptyExtent
	if paramBlock != nil {
		stmtListExt = paramBlock.ext()
	}
	var scriptBlockExt extent
	for {
		e := p.statementListRule(&statements, &traps)
		if stmtListExt.empty() {
			stmtListExt = e
		} else if !e.empty() {
			stmtListExt = extentOf(stmtListExt, e)
		}
		var ok bool
		scriptBlockExt, ok = p.completeScriptBlockBody(lCurly, &stmtListExt)
		if ok {
			break
		}
	}
	se := stmtListExt
	if se.empty() {
		se = extent{0, 0}
	}
	sb := stmtBlock(se, statements, traps)
	return scriptBlockOfStatements(scriptBlockExt, usings, nil, paramBlock, sb, isFilter)
}

func (p *Parser) namedBlockListRule(lCurly *Token, usings []*Node, paramBlock *Node) *Node {
	var dyn, begin, process, end, clean *Node
	startExtent := emptyExtent
	if lCurly != nil {
		startExtent = tokExt(lCurly)
	} else if paramBlock != nil {
		startExtent = paramBlock.ext()
	}
	endExtent := emptyExtent
	var ext, scriptBlockExt extent
loop:
	for {
		blockNameToken := p.nextToken()
		switch blockNameToken.Kind {
		case TkRCurly, TkEndOfInput:
			p.ungetToken(blockNameToken)
			ext = extentOf(startExtent, endExtent)
			p.completeScriptBlockBodyIgnore(lCurly, &ext, &scriptBlockExt)
			break loop
		case TkDynamicparam, TkBegin, TkProcess, TkEnd, TkClean:
		default:
			if lCurly != nil {
				p.ungetToken(blockNameToken)
				scriptBlockExt = extentOf(startExtent, endExtent)
			} else {
				scriptBlockExt = p.tz.scriptExtent()
			}
			p.reportError(tokExt(blockNameToken), "MissingNamedBlocks")
			break loop
		}
		if startExtent.empty() {
			startExtent = tokExt(blockNameToken)
		}
		endExtent = tokExt(blockNameToken)
		sb := p.statementBlockRule()
		if sb == nil {
			p.reportIncomplete(after(tokExt(blockNameToken)), "MissingNamedStatementBlock")
			sb = stmtBlock(tokExt(blockNameToken), nil, nil)
		} else {
			endExtent = sb.ext()
		}
		ext = extentOf(tokExt(blockNameToken), endExtent)
		switch {
		case blockNameToken.Kind == TkBegin && begin == nil:
			begin = namedBlock(ext, TkBegin, sb, false)
		case blockNameToken.Kind == TkProcess && process == nil:
			process = namedBlock(ext, TkProcess, sb, false)
		case blockNameToken.Kind == TkEnd && end == nil:
			end = namedBlock(ext, TkEnd, sb, false)
		case blockNameToken.Kind == TkClean && clean == nil:
			clean = namedBlock(ext, TkClean, sb, false)
		case blockNameToken.Kind == TkDynamicparam && dyn == nil:
			dyn = namedBlock(ext, TkDynamicparam, sb, false)
		default:
			p.reportError(ext, "DuplicateScriptCommandClause")
		}
		p.skipNewlinesAndSemicolons()
	}
	return scriptBlockAst(scriptBlockExt, usings, nil, paramBlock, begin, process, end, clean, dyn)
}

func (p *Parser) completeScriptBlockBodyIgnore(lCurly *Token, ext *extent, out *extent) {
	full, _ := p.completeScriptBlockBody(lCurly, ext)
	*out = full
}

func (p *Parser) statementBlockRule() *Node {
	p.skipNewlines()
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		return nil
	}
	var traps, statements []*Node
	listExt := p.statementListRule(&statements, &traps)
	rCurly := p.nextToken()
	var endBlock extent
	if rCurly.Kind != TkRCurly {
		p.ungetToken(rCurly)
		if !listExt.empty() {
			endBlock = listExt
		} else {
			endBlock = tokExt(lCurly)
		}
		p.reportIncompleteAt(tokExt(lCurly), tokExt(rCurly), "MissingEndCurlyBrace")
	} else {
		endBlock = tokExt(rCurly)
	}
	return stmtBlock(extentOf(tokExt(lCurly), endBlock), statements, traps)
}

func (p *Parser) statementListRule(statements, traps *[]*Node) extent {
	var first, last *Node
	p.skipNewlinesAndSemicolons()
	for {
		st := p.statementRule()
		if st == nil {
			break
		}
		if st.Type == "TrapStatementAst" {
			*traps = append(*traps, st)
		} else {
			*statements = append(*statements, st)
		}
		if first == nil {
			first = st
		}
		last = st
		p.skipNewlinesAndSemicolons()
		token := p.peekToken()
		if token.Kind == TkRParen || token.Kind == TkRCurly {
			break
		}
	}
	if first == nil {
		return emptyExtent
	}
	return extentOf(first.ext(), last.ext())
}
