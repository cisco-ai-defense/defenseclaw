// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// Expressions (Parser.cs ExpressionRule .. ElementAccessRule).

func (p *Parser) expressionRule() *Node { return p.expressionRuleEx(false) }

func (p *Parser) expressionRuleEx(endNumberOnTernaryOpChars bool) *Node {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.tooDeep()
		return nil
	}
	old := p.tz.mode
	defer p.setTokenizerMode(old)
	p.setTokenizerMode(modeExpression)
	condition := p.binaryExpressionRule(endNumberOnTernaryOpChars)
	if condition == nil {
		return nil
	}
	token := p.peekToken()
	if token.Kind != TkQuestionMark {
		return condition
	}
	p.skipToken()
	p.skipNewlines()
	ifTrue := p.expressionRuleEx(true)
	if ifTrue == nil {
		e := after(tokExt(token))
		p.reportIncomplete(e, "ExpectedValueExpression")
		ifTrue = newErrorExpr(e)
	}
	p.skipNewlines()
	token = p.nextToken()
	if token.Kind != TkColon {
		comps := []*Node{condition}
		p.ungetToken(token)
		if ifTrue.Type != "ErrorExpressionAst" {
			comps = append(comps, ifTrue)
			p.reportIncomplete(tokExt(token), "MissingColonInTernaryExpression")
		}
		return newErrorExpr(extentOf(condition.ext(), before(tokExt(token))), comps...)
	}
	p.skipNewlines()
	ifFalse := p.expressionRuleEx(true)
	if ifFalse == nil {
		e := after(tokExt(token))
		p.reportIncomplete(e, "ExpectedValueExpression")
		ifFalse = newErrorExpr(e)
	}
	return newNode("TernaryExpressionAst", extentOf(condition.ext(), ifFalse.ext()), condition, ifTrue, ifFalse)
}

func newBinary(lhs *Node, op TokenKind, rhs *Node) *Node {
	n := newNode("BinaryExpressionAst", extentOf(lhs.ext(), rhs.ext()), lhs, rhs)
	n.prop("Operator", op.String())
	return n
}

func (p *Parser) binaryExpressionRule(endNumberOnTernaryOpChars bool) *Node {
	old := p.tz.mode
	defer p.setTokenizerMode(old)
	p.setTokenizerMode(modeExpression)
	expr := p.arrayLiteralRule(endNumberOnTernaryOpChars)
	if expr == nil {
		return nil
	}
	var paramToken *Token
	token := p.peekToken()
	if !token.Kind.hasTrait(tfBinaryOperator) {
		if token.class == tcParameter {
			return p.errorRecoveryParameterInExpression(token, expr)
		}
		return expr
	} else if token.Kind == TkAndAnd || token.Kind == TkOrOr {
		return expr
	}
	p.skipToken()
	operands := []*Node{expr}
	operators := []*Token{token}
	precedence := token.Kind.binaryPrecedence()
	for {
		p.skipNewlines()
		expr = p.arrayLiteralRule(true)
		if expr == nil {
			e := after(tokExt(token))
			p.reportIncomplete(e, "ExpectedValueExpression")
			expr = newErrorExpr(e)
		}
		operands = append(operands, expr)
		token = p.nextToken()
		if !token.Kind.hasTrait(tfBinaryOperator) {
			if token.class == tcParameter {
				paramToken = token
			}
			p.ungetToken(token)
			break
		}
		newPrecedence := token.Kind.binaryPrecedence()
		for newPrecedence <= precedence {
			rhs := operands[len(operands)-1]
			lhs := operands[len(operands)-2]
			operands = operands[:len(operands)-2]
			op := operators[len(operators)-1]
			operators = operators[:len(operators)-1]
			operands = append(operands, newBinary(lhs, op.Kind, rhs))
			if len(operators) == 0 {
				break
			}
			precedence = operators[len(operators)-1].Kind.binaryPrecedence()
		}
		operators = append(operators, token)
		precedence = newPrecedence
	}
	rhs := operands[len(operands)-1]
	operands = operands[:len(operands)-1]
	for len(operands) > 0 {
		lhs := operands[len(operands)-1]
		operands = operands[:len(operands)-1]
		token = operators[len(operators)-1]
		operators = operators[:len(operators)-1]
		rhs = newBinary(lhs, token.Kind, rhs)
	}
	if paramToken != nil {
		return p.errorRecoveryParameterInExpression(paramToken, rhs)
	}
	return rhs
}

func (p *Parser) errorRecoveryParameterInExpression(paramToken *Token, expr *Node) *Node {
	p.reportError(tokExt(paramToken), "UnexpectedToken")
	p.skipToken()
	return newErrorExpr(extentOf(expr.ext(), tokExt(paramToken)), expr, newCommandParameter(tokExt(paramToken), paramToken.Value, nil))
}

func (p *Parser) arrayLiteralRule(endNumberOnTernaryOpChars bool) *Node {
	lastExpr := p.unaryExpressionRuleEx(endNumberOnTernaryOpChars)
	if lastExpr == nil {
		return nil
	}
	firstExpr := lastExpr
	commaToken := p.peekToken()
	if commaToken.Kind != TkComma || p.disableComma {
		return lastExpr
	}
	values := []*Node{lastExpr}
	for commaToken.Kind == TkComma {
		p.skipToken()
		p.skipNewlines()
		lastExpr = p.unaryExpressionRuleEx(true)
		if lastExpr == nil {
			p.reportIncomplete(after(tokExt(commaToken)), "MissingExpressionAfterToken")
			lastExpr = newErrorExpr(tokExt(commaToken))
			values = append(values, lastExpr)
			break
		}
		values = append(values, lastExpr)
		commaToken = p.peekToken()
	}
	return newNode("ArrayLiteralAst", extentOf(firstExpr.ext(), lastExpr.ext()), values...)
}

func (p *Parser) unaryExpressionRule() *Node { return p.unaryExpressionRuleEx(false) }

func newTypeExpr(e extent, typeFull string) *Node {
	n := newNode("TypeExpressionAst", e)
	n.prop("TypeName", typeFull)
	return n
}

func (p *Parser) unaryExpressionRuleEx(endNumberOnTernaryOpChars bool) *Node {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.tooDeep()
		return nil
	}
	var expr *Node
	var token *Token
	func() {
		oldSigned := p.tz.allowSignedNumbers
		oldForce := p.tz.forceEndNumberOnTernOp
		defer func() {
			p.tz.allowSignedNumbers = oldSigned
			p.tz.forceEndNumberOnTernOp = oldForce
		}()
		p.tz.allowSignedNumbers = true
		p.tz.forceEndNumberOnTernOp = endNumberOnTernaryOpChars
		if p.ungot != nil {
			needResync := p.ungot.Kind == TkMinus
			if !needResync {
				needResync = endNumberOnTernaryOpChars && p.ungot.Kind == TkGeneric
			}
			if needResync {
				p.resyncToken(p.ungot)
			}
		}
		token = p.peekToken()
	}()
	var child *Node
	if token.Kind.hasTrait(tfUnaryOperator) {
		if p.disableComma && token.Kind == TkComma {
			return nil
		}
		p.skipToken()
		p.skipNewlines()
		child = p.unaryExpressionRuleEx(true)
		if child != nil {
			if token.Kind == TkComma {
				expr = newNode("ArrayLiteralAst", extentOf(tokExt(token), child.ext()), child)
			} else {
				expr = newNode("UnaryExpressionAst", extentOf(tokExt(token), child.ext()), child)
				expr.prop("TokenKind", token.Kind.String())
			}
		} else {
			p.reportIncomplete(after(tokExt(token)), "MissingExpressionAfterOperator")
			return newErrorExpr(tokExt(token))
		}
	} else if token.Kind == TkLBracket {
		attributes := p.attributeListRule(true)
		if attributes == nil {
			return nil
		}
		lastAttribute := attributes[len(attributes)-1]
		if lastAttribute.Type == "AttributeAst" {
			p.skipNewlines()
			child = p.unaryExpressionRuleEx(true)
			if child == nil {
				p.reportIncomplete(lastAttribute.ext(), "UnexpectedAttribute")
				return newErrorExpr(extentOf(tokExt(token), lastAttribute.ext()), attributes...)
			}
			expr = newNode("AttributedExpressionAst", extentOf(lastAttribute.ext(), child.ext()), lastAttribute, child)
		} else {
			var memberAccess *Token
			if p.ungot == nil {
				memberAccess = p.nextMemberAccessToken(false)
			}
			if memberAccess != nil {
				expr = p.checkPostPrimaryExpressionOperators(memberAccess, newTypeExpr(lastAttribute.ext(), lastAttribute.propv("TypeName")))
			} else {
				token = p.peekToken()
				if token.Kind != TkNewLine && token.Kind != TkComma {
					child = p.unaryExpressionRuleEx(true)
					if child != nil {
						expr = newConvert(extentOf(lastAttribute.ext(), child.ext()), lastAttribute, child)
					}
				}
			}
			if expr == nil {
				expr = newTypeExpr(lastAttribute.ext(), lastAttribute.propv("TypeName"))
			}
		}
		for i := len(attributes) - 2; i >= 0; i-- {
			a := attributes[i]
			if a.Type == "TypeConstraintAst" {
				expr = newConvert(extentOf(a.ext(), expr.ext()), a, expr)
			} else {
				expr = newNode("AttributedExpressionAst", extentOf(a.ext(), expr.ext()), a, expr)
			}
		}
	} else {
		expr = p.primaryExpressionRule(true)
	}
	if expr != nil {
		token = p.peekToken()
		op := TkUnknown
		switch token.Kind {
		case TkPlusPlus:
			op = TkPostfixPlusPlus
		case TkMinusMinus:
			op = TkPostfixMinusMinus
		}
		if op != TkUnknown {
			p.skipToken()
			n := newNode("UnaryExpressionAst", extentOf(expr.ext(), tokExt(token)), expr)
			n.prop("TokenKind", op.String())
			expr = n
		}
	}
	return expr
}

// newConvert builds a ConvertExpressionAst; its StaticType needs .NET type resolution and is not modelled.
func newConvert(e extent, tc, child *Node) *Node {
	n := newNode("ConvertExpressionAst", e, tc, child)
	n.prop("StaticType", propNull)
	return n
}

func (p *Parser) primaryExpressionRule(withMemberAccess bool) *Node {
	var expr *Node
	token := p.nextToken()
	switch token.Kind {
	case TkSplattedVariable, TkVariable:
		expr = p.checkUsingVariable(token, withMemberAccess)
	case TkNumber:
		expr = newNumberConst(token)
	case TkHereStringExpandable, TkStringExpandable:
		expr = p.expandableStringRule(token)
	case TkHereStringLiteral, TkStringLiteral:
		expr = newStringConst(tokExt(token), token.Value, stringConstTypeOf(token.Kind))
	case TkLParen:
		expr = p.parenthesizedExpressionRule(token)
	case TkAtParen, TkDollarParen:
		expr = p.subExpressionRule(token)
	case TkAtCurly:
		expr = p.hashExpressionRule(token)
	case TkLCurly:
		expr = p.scriptBlockExpressionRule(token)
	default:
		p.ungetToken(token)
		return nil
	}
	if !withMemberAccess {
		return expr
	}
	return p.checkPostPrimaryExpressionOperators(p.nextMemberAccessToken(true), expr)
}

func stringConstTypeOf(k TokenKind) string {
	switch k {
	case TkStringExpandable:
		return "DoubleQuoted"
	case TkHereStringLiteral:
		return "SingleQuotedHereString"
	case TkHereStringExpandable:
		return "DoubleQuotedHereString"
	case TkStringLiteral:
		return "SingleQuoted"
	}
	return "BareWord"
}

func newNumberConst(t *Token) *Node {
	n := newNode("ConstantExpressionAst", tokExt(t))
	if t.Num == nil {
		// BadNumericConstant: the reference keeps a null value (static type System.Object).
		n.prop("StaticType", "System.Object").prop("Value", propNull)
		return n
	}
	n.Num = t.Num
	ty := t.Num.Type
	if ty == "BigInteger" {
		ty = "Numerics.BigInteger"
	}
	n.prop("StaticType", "System."+ty).prop("Value", t.Num.Text)
	return n
}

func (p *Parser) newExpandableString(t *Token, nested []*Node) *Node {
	n := newNode("ExpandableStringExpressionAst", tokExt(t), nested...)
	n.Str = t.Value
	n.prop("StringConstantType", stringConstTypeOf(t.Kind)).prop("Value", t.Value)
	return n
}

func (p *Parser) checkUsingVariable(t *Token, withMemberAccess bool) *Node {
	path := t.Path.UserPath
	if len(path) > 6 && strings.EqualFold(path[:6], "using:") {
		real := path[6:]
		child := newVariableNode(tokExt(t), real, t.Kind == TkSplattedVariable)
		if withMemberAccess {
			child = p.checkPostPrimaryExpressionOperators(p.nextMemberAccessToken(true), child)
		}
		return newNode("UsingExpressionAst", child.ext(), child)
	}
	return p.variableFromToken(t)
}

func (p *Parser) checkPostPrimaryExpressionOperators(token *Token, expr *Node) *Node {
	for token != nil {
		p.skipNewlines()
		switch token.Kind {
		case TkDot, TkColonColon, TkQuestionDot:
			expr = p.memberAccessRule(expr, token)
		case TkLBracket, TkQuestionLBracket:
			expr = p.elementAccessRule(expr, token)
		}
		token = p.nextMemberAccessToken(true)
	}
	return expr
}

func (p *Parser) hashExpressionRule(atCurly *Token) *Node {
	p.skipNewlines()
	var kids []*Node
	for {
		k, v := p.getKeyValuePair()
		if k == nil {
			break
		}
		kids = append(kids, k, v)
		token := p.peekToken()
		if token.Kind != TkNewLine && token.Kind != TkSemi {
			break
		}
		p.skipNewlinesAndSemicolons()
	}
	var endExtent extent
	rCurly := p.nextToken()
	if rCurly.Kind != TkRCurly {
		p.ungetToken(rCurly)
		p.reportIncompleteAt(after(tokExt(atCurly)), tokExt(rCurly), "MissingEndCurlyBrace")
		endExtent = before(tokExt(rCurly))
	} else {
		endExtent = tokExt(rCurly)
	}
	return newNode("HashtableAst", extentOf(tokExt(atCurly), endExtent), kids...)
}

func (p *Parser) getKeyValuePair() (key, value *Node) {
	var equals *Token
	old := p.tz.mode
	defer p.setTokenizerMode(old)
	p.setTokenizerMode(modeExpression)
	key = p.labelOrKeyRule()
	if key == nil {
		return nil, nil
	}
	equals = p.nextToken()
	if equals.Kind != TkEquals {
		p.ungetToken(equals)
		errorExtent := after(key.ext())
		p.reportError(errorExtent, "MissingEqualsInHashLiteral")
		p.syncOnError(false, TkRCurly, TkSemi, TkNewLine)
		return key, newErrorStmt(errorExtent)
	}
	p.setTokenizerMode(modeCommand)
	p.skipNewlines()
	statement := p.statementRule()
	if statement == nil {
		errorExtent := after(tokExt(equals))
		p.reportIncomplete(errorExtent, "MissingStatementInHashLiteral")
		statement = newErrorStmt(errorExtent)
	}
	return key, statement
}

func (p *Parser) scriptBlockExpressionRule(lCurly *Token) *Node {
	oldDisable := p.disableComma
	old := p.tz.mode
	defer func() {
		p.disableComma = oldDisable
		p.setTokenizerMode(old)
	}()
	p.disableComma = false
	p.setTokenizerMode(modeCommand)
	p.skipNewlines()
	sb := p.scriptBlockRule(lCurly, false, nil)
	return newNode("ScriptBlockExpressionAst", sb.ext(), sb)
}

func (p *Parser) subExpressionRule(first *Token) *Node {
	var statements, traps []*Node
	var rParen *Token
	var listExt extent
	func() {
		oldDisable := p.disableComma
		old := p.tz.mode
		defer func() {
			p.disableComma = oldDisable
			p.setTokenizerMode(old)
		}()
		p.disableComma = false
		p.setTokenizerMode(modeCommand)
		p.skipNewlines()
		listExt = p.statementListRule(&statements, &traps)
		p.skipNewlines()
		rParen = p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			p.reportIncomplete(tokExt(rParen), "MissingEndParenthesisInSubexpression")
		}
	}()
	var endE extent
	if rParen.Kind == TkRParen {
		endE = tokExt(rParen)
	} else {
		endE = firstOf(listExt, tokExt(first))
	}
	e := extentOf(tokExt(first), endE)
	le := listExt
	if le.empty() {
		le = extent{0, 0}
	}
	sb := stmtBlock(le, statements, traps)
	if first.Kind == TkDollarParen {
		return newNode("SubExpressionAst", e, sb)
	}
	return newNode("ArrayExpressionAst", e, sb)
}

func (p *Parser) parenthesizedExpressionRule(lParen *Token) *Node {
	var rParen *Token
	var pipeline *Node
	func() {
		old := p.tz.mode
		oldDisable := p.disableComma
		defer func() {
			p.disableComma = oldDisable
			p.setTokenizerMode(old)
		}()
		p.setTokenizerMode(modeCommand)
		p.disableComma = false
		p.skipNewlines()
		pipeline = p.pipelineChainRule()
		if pipeline == nil {
			errPos := after(tokExt(lParen))
			p.reportIncomplete(errPos, "ExpectedExpression")
			pipeline = newErrorStmt(errPos)
		}
		p.skipNewlines()
		rParen = p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			p.reportIncomplete(after(pipeline.ext()), "MissingEndParenthesisInExpression")
			rParen = nil
		}
	}()
	return newNode("ParenExpressionAst", extentOf(tokExt(lParen), firstOf(tx(rParen), pipeline.ext())), pipeline)
}

func (p *Parser) parseNestedExpressions(t *Token) []*Node {
	var nested []*Node
	for _, tok := range t.nested() {
		var expr *Node
		if tok.class == tcVariable {
			expr = p.checkUsingVariable(tok, false)
		} else {
			ts := p.tz.startNestedScan(tok)
			expr = p.primaryExpressionRule(true)
			p.ungot = nil
			p.tz.finishNestedScan(ts)
		}
		nested = append(nested, expr)
	}
	return nested
}

func (p *Parser) expandableStringRule(t *Token) *Node {
	if len(t.nested()) > 0 {
		nested := p.parseNestedExpressions(t)
		return p.newExpandableString(t, nested)
	}
	return newStringConst(tokExt(t), t.Value, stringConstTypeOf(t.Kind))
}

func (p *Parser) memberNameRule() *Node {
	if simple := p.simpleNameRule(); simple != nil {
		return simple
	}
	token := p.peekToken()
	if token.Kind.hasTrait(tfUnaryOperator) || token.Kind == TkLBracket {
		return p.unaryExpressionRule()
	}
	return p.primaryExpressionRule(false)
}

func (p *Parser) memberAccessRule(target *Node, operatorToken *Token) *Node {
	member := p.memberNameRule()
	if member == nil {
		p.reportIncomplete(after(tokExt(operatorToken)), "MissingPropertyName")
		member = p.getSingleCommandArgument(argCommandArgument)
		if member == nil {
			member = newErrorExpr(extentOf(target.ext(), tokExt(operatorToken)))
		}
	} else if p.ungot == nil {
		resyncIndex := p.tz.getRestorePoint()
		_, rBracket := p.genericMethodArgumentsRule(resyncIndex)
		lParen := p.nextInvokeMemberToken()
		if lParen != nil {
			return p.memberInvokeRule(target, lParen, operatorToken, member)
		} else if rBracket != nil {
			p.resync(resyncIndex)
		}
	}
	static := operatorToken.Kind == TkColonColon
	nullc := operatorToken.Kind == TkQuestionDot
	n := newNode("MemberExpressionAst", extentOf(target.ext(), member.ext()), target, member)
	n.prop("Static", boolStr(static)).prop("NullConditional", boolStr(nullc))
	return n
}

func (p *Parser) genericMethodArgumentsRule(resyncIndex int) ([]*typeName, *Token) {
	var genericTypes []*typeName
	var rBracket *Token
	lBracket := p.nextToken()
	if lBracket.Kind != TkLBracket {
		p.resync(resyncIndex)
		return nil, nil
	}
	old := p.tz.mode
	defer func() {
		p.setTokenizerMode(old)
		if resyncIndex > 0 {
			p.resync(resyncIndex)
		}
	}()
	p.setTokenizerMode(modeTypeName)
	p.skipNewlines()
	first := p.nextToken()
	if first.Kind == TkIdentifier {
		resyncIndex = -1
		genericTypes, rBracket = p.genericTypeArgumentsRule(first)
		if rBracket.Kind != TkRBracket {
			p.ungetToken(rBracket)
			p.reportIncomplete(before(tokExt(rBracket)), "EndSquareBracketExpectedAtEndOfType")
			rBracket = nil
		}
	}
	return genericTypes, rBracket
}

func (p *Parser) memberInvokeRule(target *Node, lBracket, operatorToken *Token, member *Node) *Node {
	var lastExtent extent
	var args []*Node
	if lBracket.Kind == TkLParen {
		args, lastExtent = p.invokeParamParenListRule(lBracket)
	} else {
		p.skipNewlines()
		arg := p.scriptBlockExpressionRule(lBracket)
		args = []*Node{arg}
		lastExtent = arg.ext()
	}
	n := newNode("InvokeMemberExpressionAst", extentOf(target.ext(), lastExtent), target, member)
	n.Kids = append(n.Kids, args...)
	n.prop("Static", boolStr(operatorToken.Kind == TkColonColon)).prop("NullConditional", boolStr(operatorToken.Kind == TkQuestionDot))
	return n
}

func (p *Parser) invokeParamParenListRule(lParen *Token) ([]*Node, extent) {
	var args []*Node
	var comma, rParen *Token
	oldDisable := p.disableComma
	defer func() { p.disableComma = oldDisable }()
	reported := false
	p.disableComma = true
	for {
		p.skipNewlines()
		arg := p.expressionRule()
		if arg == nil {
			if comma != nil {
				p.reportIncomplete(after(tokExt(comma)), "MissingExpressionAfterToken")
				reported = true
			}
			break
		}
		args = append(args, arg)
		p.skipNewlines()
		comma = p.nextToken()
		if comma.Kind != TkComma {
			p.ungetToken(comma)
			comma = nil
			break
		}
	}
	p.skipNewlines()
	rParen = p.nextToken()
	if rParen.Kind != TkRParen {
		p.ungetToken(rParen)
		if !reported {
			if len(args) > 0 {
				p.reportIncomplete(after(args[len(args)-1].ext()), "MissingEndParenthesisInMethodCall")
			} else {
				p.reportIncomplete(after(tokExt(lParen)), "MissingEndParenthesisInMethodCall")
			}
		}
		rParen = nil
	}
	last := emptyExtent
	if len(args) > 0 {
		last = args[len(args)-1].ext()
	}
	return args, firstOf(tx(rParen), tx(comma), last, tokExt(lParen))
}

func (p *Parser) elementAccessRule(primary *Node, lBracket *Token) *Node {
	p.skipNewlines()
	oldDisable := p.disableComma
	p.disableComma = false
	indexExpr := p.expressionRule()
	p.disableComma = oldDisable
	if indexExpr == nil {
		p.reportIncomplete(after(tokExt(lBracket)), "MissingArrayIndexExpression")
		indexExpr = newErrorExpr(tokExt(lBracket))
	}
	p.skipNewlines()
	rBracket := p.nextToken()
	if rBracket.Kind != TkRBracket {
		p.ungetToken(rBracket)
		if indexExpr.Type != "ErrorExpressionAst" {
			p.reportIncomplete(after(indexExpr.ext()), "MissingEndSquareBracket")
		}
		rBracket = nil
	}
	return newNode("IndexExpressionAst", extentOf(primary.ext(), firstOf(tx(rBracket), indexExpr.ext())), primary, indexExpr)
}
