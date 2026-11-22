// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

// do/while, using, function, trap, try/catch and data statements (Parser.cs).

func (p *Parser) doWhileStatementRule(labelToken, doToken *Token) *Node {
	startTok := doToken
	if labelToken != nil {
		startTok = labelToken
	}
	startExtent := tokExt(startTok)
	endErrorStatement := emptyExtent
	var rParen, whileOrUntil *Token
	var condition *Node
	body := p.statementBlockRule()
	if body == nil {
		endErrorStatement = tokExt(doToken)
		p.reportIncomplete(after(endErrorStatement), "MissingLoopStatement")
	} else {
		p.skipNewlines()
		whileOrUntil = p.nextToken()
		if whileOrUntil.Kind != TkWhile && whileOrUntil.Kind != TkUntil {
			p.ungetToken(whileOrUntil)
			endErrorStatement = body.ext()
			p.reportIncomplete(after(endErrorStatement), "MissingWhileOrUntilInDoWhile")
		} else {
			p.skipNewlines()
			lParen := p.nextToken()
			if lParen.Kind != TkLParen {
				p.ungetToken(lParen)
				endErrorStatement = tokExt(whileOrUntil)
				p.reportIncomplete(after(endErrorStatement), "MissingOpenParenthesisAfterKeyword")
			} else {
				p.skipNewlines()
				condition = p.pipelineChainRule()
				if condition == nil {
					endErrorStatement = tokExt(lParen)
					p.reportIncomplete(after(endErrorStatement), "MissingExpressionAfterKeyword")
				}
				p.skipNewlines()
				rParen = p.nextToken()
				if rParen.Kind != TkRParen {
					p.ungetToken(rParen)
					if condition != nil {
						endErrorStatement = condition.ext()
						p.reportIncomplete(after(endErrorStatement), "MissingEndParenthesisAfterStatement")
					}
				}
			}
		}
	}
	if !endErrorStatement.empty() {
		return newErrorStmt(extentOf(startExtent, endErrorStatement), body, condition)
	}
	e := extentOf(startExtent, tokExt(rParen))
	typ := "DoWhileStatementAst"
	if whileOrUntil.Kind == TkUntil {
		typ = "DoUntilStatementAst"
	}
	return newNode(typ, e, condition, body)
}

func (p *Parser) usingStatementRule(usingToken *Token) *Node {
	directive := p.nextToken()
	var kind string
	aliasAllowed, aliasRequired := false, false
	switch directive.Kind {
	case TkNamespace:
		kind, aliasAllowed = "Namespace", true
	case TkType:
		kind, aliasRequired = "Type", true
	case TkModule:
		kind, aliasAllowed = "Module", true
	case TkCommand:
		kind, aliasRequired = "Command", true
	case TkAssembly:
		kind = "Assembly"
	default:
		p.ungetToken(directive)
		p.reportIncomplete(after(tokExt(usingToken)), "MissingUsingStatementDirective")
		return newErrorStmt(tokExt(usingToken))
	}
	item := p.nextToken()
	switch item.Kind {
	case TkEndOfInput, TkNewLine, TkComma, TkSemi:
		p.reportIncomplete(after(tokExt(directive)), "MissingUsingItemName")
		return newErrorStmt(extentOf(tokExt(usingToken), tokExt(directive)))
	}
	itemAst := p.getCommandArgument(argCommandArgument, item)
	if itemAst == nil {
		p.reportError(tokExt(item), "InvalidValueForUsingItemName")
		p.syncOnError(true, TkSemi, TkNewLine)
		return newErrorStmt(extentOf(tokExt(usingToken), tokExt(item)))
	}
	if !itemAst.isStringConst() && (kind != "Module" || itemAst.Type != "HashtableAst") {
		ee := firstOf(itemAst.ext(), tokExt(item))
		p.reportError(ee, "InvalidValueForUsingItemName")
		return newErrorStmt(extentOf(tokExt(usingToken), ee))
	}
	var ht *Node
	switch kind {
	case "Module":
		if itemAst.Type == "HashtableAst" {
			ht = itemAst
		}
	}
	mk := func(e extent, name, htab, alias *Node) *Node {
		n := newNode("UsingStatementAst", e, name, htab, alias)
		n.prop("UsingStatementKind", kind)
		return n
	}
	if (aliasAllowed || aliasRequired) && ht == nil {
		equals := p.peekToken()
		if equals.Kind == TkEquals {
			p.skipToken()
			aliasToken := p.nextToken()
			if aliasToken.Kind == TkEndOfInput || aliasToken.Kind == TkNewLine || aliasToken.Kind == TkSemi {
				p.ungetToken(aliasToken)
				p.reportIncomplete(after(tokExt(equals)), "MissingNamespaceAlias")
				return newErrorStmt(extentOf(tokExt(usingToken), tokExt(equals)))
			}
			if aliasToken.Kind == TkComma {
				p.reportError(tokExt(aliasToken), "UnexpectedUnaryOperator")
				return newErrorStmt(extentOf(tokExt(usingToken), tokExt(aliasToken)))
			}
			aliasAst := p.getCommandArgument(argCommandArgument, aliasToken)
			if kind == "Module" && aliasAst != nil && aliasAst.Type == "HashtableAst" {
				ht = aliasAst
			} else if aliasAst == nil || !aliasAst.isStringConst() {
				errorExtent := firstOf(nx(aliasAst), tokExt(aliasToken))
				p.reportError(errorExtent, "InvalidValueForUsingItemName")
				return newErrorStmt(extentOf(tokExt(usingToken), errorExtent), itemAst, aliasAst)
			}
			p.requireStatementTerminator()
			if ht == nil {
				return mk(extentOf(tokExt(usingToken), tokExt(aliasToken)), itemAst, nil, aliasAst)
			}
			return mk(extentOf(tokExt(usingToken), tokExt(aliasToken)), itemAst, ht, nil)
		}
		if aliasRequired {
			p.reportIncomplete(after(tokExt(item)), "MissingEqualsInUsingAlias")
			return newErrorStmt(extentOf(tokExt(usingToken), itemAst.ext()), itemAst)
		}
	}
	p.requireStatementTerminator()
	if ht == nil {
		return mk(extentOf(tokExt(usingToken), itemAst.ext()), itemAst, nil, nil)
	}
	return mk(extentOf(tokExt(usingToken), itemAst.ext()), nil, ht, nil)
}

func (p *Parser) functionDeclarationRule(functionToken *Token) *Node {
	p.skipNewlines()
	nameTok := p.nextToken()
	switch nameTok.Kind {
	case TkPipe, TkLParen, TkLCurly, TkAtParen, TkAtCurly, TkRCurly, TkRParen, TkEndOfInput, TkSemi,
		TkRedirection, TkRedirectInStd, TkAndAnd, TkOrOr, TkAmpersand, TkVariable, TkSplattedVariable,
		TkHereStringExpandable, TkHereStringLiteral, TkStringLiteral, TkStringExpandable:
		p.ungetToken(nameTok)
		p.reportIncomplete(after(tokExt(functionToken)), "MissingNameAfterKeyword")
		return newErrorStmt(tokExt(functionToken))
	}
	nameTok.Flags &^= tfKeyword
	parameters, endErrorStatement, rParen := p.functionParameterDeclarationRule()
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		if endErrorStatement.empty() {
			endErrorStatement = firstOf(tx(rParen), tokExt(nameTok))
			p.reportIncomplete(after(endErrorStatement), "MissingFunctionBody")
		}
	}
	if !endErrorStatement.empty() {
		return newErrorStmt(extentOf(tokExt(functionToken), endErrorStatement), parameters...)
	}
	isFilter := functionToken.Kind == TkFilter
	isWorkflow := functionToken.Kind == TkWorkflow
	old := p.tz.inWorkflowContext
	p.tz.inWorkflowContext = isWorkflow
	scriptBlock := p.scriptBlockRule(lCurly, isFilter, nil)
	p.tz.inWorkflowContext = old
	name := p.tokText(nameTok)
	if nameTok.Kind == TkGeneric {
		name = nameTok.Value
	}
	n := newNode("FunctionDefinitionAst", extentOf(tokExt(functionToken), scriptBlock.ext()))
	n.prop("Name", name).prop("IsFilter", boolStr(isFilter)).prop("IsWorkflow", boolStr(isWorkflow))
	n.Kids = append(n.Kids, parameters...)
	n.Kids = append(n.Kids, scriptBlock)
	return n
}

func (p *Parser) functionParameterDeclarationRule() (parameters []*Node, endErr extent, rParen *Token) {
	endErr = emptyExtent
	p.skipNewlines()
	lParen := p.peekToken()
	if lParen.Kind == TkLParen {
		p.skipToken()
		parameters = p.parameterListRule()
		p.skipNewlines()
		rParen = p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			if len(parameters) > 0 {
				endErr = parameters[len(parameters)-1].ext()
			} else {
				endErr = tokExt(lParen)
			}
			p.reportIncomplete(after(endErr), "MissingEndParenthesisInFunctionParameterList")
		}
		p.skipNewlines()
	}
	return
}

func (p *Parser) trapStatementRule(trapToken *Token) *Node {
	restore := p.tz.getRestorePoint()
	p.skipNewlines()
	typ := p.attributeRule()
	var tc *Node
	if typ != nil {
		if typ.Type == "TypeConstraintAst" {
			tc = typ
		} else {
			p.resync(restore)
		}
	}
	body := p.statementBlockRule()
	if body == nil {
		end := firstOf(nx(tc), tokExt(trapToken))
		p.reportIncomplete(after(end), "MissingTrapStatement")
		return newErrorStmt(extentOf(tokExt(trapToken), end), tc)
	}
	return newNode("TrapStatementAst", extentOf(tokExt(trapToken), body.ext()), tc, body)
}

func (p *Parser) catchBlockRule(endErr *extent, errorAsts *[]*Node) *Node {
	p.skipNewlines()
	catchToken := p.nextToken()
	if catchToken.Kind != TkCatch {
		p.ungetToken(catchToken)
		return nil
	}
	var types []*Node
	var commaToken *Token
	for {
		restore := p.tz.getRestorePoint()
		p.skipNewlines()
		typ := p.attributeRule()
		if typ == nil {
			if commaToken != nil {
				*endErr = tokExt(commaToken)
				p.reportIncomplete(after(*endErr), "MissingTypeLiteralToken")
			}
			break
		}
		if typ.Type != "TypeConstraintAst" {
			p.resync(restore)
			break
		}
		types = append(types, typ)
		p.skipNewlines()
		commaToken = p.peekToken()
		if commaToken.Kind != TkComma {
			break
		}
		p.skipToken()
	}
	handler := p.statementBlockRule()
	if handler == nil {
		if commaToken == nil || *endErr != tokExt(commaToken) {
			if len(types) > 0 {
				*endErr = types[len(types)-1].ext()
			} else {
				*endErr = tokExt(catchToken)
			}
			p.reportIncomplete(after(*endErr), "MissingCatchHandlerBlock")
		}
		*errorAsts = append(*errorAsts, types...)
		return nil
	}
	n := newNode("CatchClauseAst", extentOf(tokExt(catchToken), handler.ext()))
	n.Kids = append(n.Kids, types...)
	n.Kids = append(n.Kids, handler)
	n.prop("IsCatchAll", boolStr(len(types) == 0))
	return n
}

func (p *Parser) tryStatementRule(tryToken *Token) *Node {
	p.skipNewlines()
	body := p.statementBlockRule()
	if body == nil {
		p.reportIncomplete(after(tokExt(tryToken)), "MissingTryStatementBlock")
		return newErrorStmt(tokExt(tryToken))
	}
	endErr := emptyExtent
	var catches, errorAsts []*Node
	for {
		c := p.catchBlockRule(&endErr, &errorAsts)
		if c == nil {
			break
		}
		catches = append(catches, c)
	}
	p.skipNewlines()
	finallyToken := p.peekToken()
	var finallyBlock *Node
	if finallyToken.Kind == TkFinally {
		p.skipToken()
		finallyBlock = p.statementBlockRule()
		if finallyBlock == nil {
			endErr = tokExt(finallyToken)
			p.reportIncomplete(after(endErr), "MissingFinallyStatementBlock")
		}
	}
	if len(catches) == 0 && finallyBlock == nil && endErr.empty() {
		endErr = body.ext()
		p.reportIncomplete(after(endErr), "MissingCatchOrFinally")
	}
	if !endErr.empty() {
		kids := []*Node{body}
		kids = append(kids, catches...)
		kids = append(kids, errorAsts...)
		return newErrorStmt(extentOf(tokExt(tryToken), endErr), kids...)
	}
	end := catches
	var last extent
	if finallyBlock != nil {
		last = finallyBlock.ext()
	} else {
		last = end[len(end)-1].ext()
	}
	n := newNode("TryStatementAst", extentOf(tokExt(tryToken), last), body)
	n.Kids = append(n.Kids, catches...)
	if finallyBlock != nil {
		n.Kids = append(n.Kids, finallyBlock)
	}
	return n
}

func (p *Parser) dataStatementRule(dataToken *Token) *Node {
	endErr := emptyExtent
	p.skipNewlines()
	nameAst := p.simpleNameRule()
	varName := ""
	hasVar := false
	if nameAst != nil {
		varName = nameAst.Str
		hasVar = true
	}
	p.skipNewlines()
	supportedCmd := p.peekToken()
	var commands []*Node
	if supportedCmd.Kind == TkParameter {
		p.skipToken()
		if !isSpecificParameter(supportedCmd, "SupportedCommand") {
			endErr = tokExt(supportedCmd)
			p.reportError(endErr, "InvalidParameterForDataSectionStatement")
		}
		var commaToken *Token
		for {
			p.skipNewlines()
			ast := p.getSingleCommandArgument(argCommandName)
			if ast == nil {
				if endErr.empty() {
					at := supportedCmd
					if commaToken != nil {
						at = commaToken
					}
					p.reportIncomplete(after(tokExt(at)), "MissingValueForSupportedCommandInDataSectionStatement")
				}
				if commaToken != nil {
					endErr = tokExt(commaToken)
				} else {
					endErr = tokExt(supportedCmd)
				}
				break
			}
			commands = append(commands, ast)
			commaToken = p.peekToken()
			if commaToken.Kind == TkComma {
				p.skipToken()
				continue
			}
			break
		}
	}
	var body *Node
	if endErr.empty() {
		body = p.statementBlockRule()
		if body == nil {
			if len(commands) > 0 {
				endErr = commands[len(commands)-1].ext()
			} else {
				endErr = firstOf(nx(nameAst), tokExt(dataToken))
			}
			p.reportIncomplete(after(endErr), "MissingStatementBlockForDataSection")
		}
	}
	if !endErr.empty() {
		return newErrorStmt(extentOf(tokExt(dataToken), endErr), commands...)
	}
	n := newNode("DataStatementAst", extentOf(tokExt(dataToken), body.ext()), body)
	if hasVar {
		n.prop("Variable", varName)
	} else {
		n.prop("Variable", propNull)
	}
	return n
}
