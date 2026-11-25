// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// Statements (Parser.cs StatementRule .. WhileStatementRule).

func (p *Parser) statementRule() *Node {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.tooDeep()
		return nil
	}
	restorePoint := 0
	var statement *Node
	token := p.nextToken()
	var attributes []*Node
	if token.Kind == TkGeneric && p.src[token.Start] == '[' {
		restorePoint = token.Start
		p.resyncToken(token)
		attributes = p.attributeListRule(false)
		token = p.nextToken()
		if len(attributes) > 0 {
			if token.Flags&tfStatementDoesntSupportAttributes != 0 {
				hasTC := false
				for _, a := range attributes {
					if a.Type == "TypeConstraintAst" {
						hasTC = true
						break
					}
				}
				if hasTC {
					p.resync(restorePoint)
					token = p.nextToken()
				} else {
					p.reportError(attributes[0].ext(), "UnexpectedAttribute")
				}
			} else if token.Flags&tfKeyword != 0 {
				for _, a := range attributes {
					if a.Type != "AttributeAst" {
						p.reportError(a.ext(), "TypeNotAllowedBeforeStatement")
						break
					}
				}
			} else {
				p.resync(restorePoint)
				token = p.nextToken()
			}
		}
	}
	switch token.Kind {
	case TkIf:
		statement = p.ifStatementRule(token)
	case TkSwitch:
		statement = p.switchStatementRule(nil, token)
	case TkForeach:
		statement = p.foreachStatementRule(nil, token)
	case TkFor:
		statement = p.forStatementRule(nil, token)
	case TkWhile:
		statement = p.whileStatementRule(nil, token)
	case TkDo:
		statement = p.doWhileStatementRule(nil, token)
	case TkFunction, TkFilter, TkWorkflow:
		statement = p.functionDeclarationRule(token)
	case TkReturn:
		statement = p.pipelineKeywordStatement("ReturnStatementAst", token)
	case TkThrow:
		statement = p.pipelineKeywordStatement("ThrowStatementAst", token)
	case TkExit:
		statement = p.pipelineKeywordStatement("ExitStatementAst", token)
	case TkBreak:
		statement = p.labelKeywordStatement("BreakStatementAst", token)
	case TkContinue:
		statement = p.labelKeywordStatement("ContinueStatementAst", token)
	case TkTrap:
		statement = p.trapStatementRule(token)
	case TkTry:
		statement = p.tryStatementRule(token)
	case TkData:
		statement = p.dataStatementRule(token)
	case TkParallel, TkSequence:
		statement = p.blockStatementRule(token)
	case TkConfiguration:
		statement = p.unsupportedStatement(token)
	case TkFrom, TkDefine, TkVar:
		p.reportError(tokExt(token), "ReservedKeywordNotAllowed")
		statement = newErrorStmt(tokExt(token))
	case TkLabel:
		p.skipNewlines()
		statement = p.labeledStatementRule(token)
	case TkEndOfInput:
		if attributes != nil {
			p.resync(restorePoint)
			statement = p.pipelineChainRule()
		} else {
			p.ungetToken(token)
			statement = nil
		}
	case TkElse, TkElseIf, TkCatch, TkUntil:
		if len(p.errors) > 0 {
			p.skipNewlines()
			return p.statementRule()
		}
		statement = p.statementDefault(token, attributes, restorePoint)
	case TkClass:
		statement = p.classDefinitionRule(attributes, token)
	case TkEnum:
		statement = p.enumDefinitionRule(attributes, token)
	case TkDynamicKeyword:
		statement = p.unsupportedStatement(token)
	case TkUsing:
		statement = p.usingStatementRule(token)
		p.reportError(statement.ext(), "UsingMustBeAtStartOfScript")
	default:
		statement = p.statementDefault(token, attributes, restorePoint)
	}
	return statement
}

func (p *Parser) statementDefault(token *Token, attributes []*Node, restorePoint int) *Node {
	if attributes != nil {
		p.resync(restorePoint)
	} else {
		p.ungetToken(token)
	}
	return p.pipelineChainRule()
}

// unsupportedStatement is used for the tier-2 constructs that are not ported (configuration, dynamic keywords):
// the port does not parse them, flags the result and recovers as the reference does on a bad statement.
func (p *Parser) unsupportedStatement(token *Token) *Node {
	p.markUnsupported()
	p.reportError(tokExt(token), "UnsupportedByPort")
	p.syncOnError(true, TkRCurly)
	return newErrorStmt(tokExt(token))
}

func (p *Parser) simpleNameRule() *Node {
	n, _ := p.simpleNameRuleTok()
	return n
}

func (p *Parser) simpleNameRuleTok() (*Node, *Token) {
	p.tz.wantSimpleName = true
	token := p.peekToken()
	p.tz.wantSimpleName = false
	if token.Kind == TkIdentifier {
		token.Flags |= tfMemberName
		p.skipToken()
		return newStringConst(tokExt(token), p.tokText(token), "BareWord"), token
	}
	return nil, token
}

func (p *Parser) labelOrKeyRule() *Node {
	if simple := p.simpleNameRule(); simple != nil {
		return simple
	}
	token := p.peekToken()
	if token.Kind != TkNewLine && token.Kind != TkSemi {
		old := p.disableComma
		p.disableComma = true
		labelExpr := p.unaryExpressionRule()
		p.disableComma = old
		if labelExpr != nil {
			return labelExpr
		}
	}
	return nil
}

func (p *Parser) labelKeywordStatement(typ string, kw *Token) *Node {
	label := p.labelOrKeyRule()
	e := tokExt(kw)
	if label != nil {
		e = extentOf(tokExt(kw), label.ext())
	}
	return newNode(typ, e, label)
}

func (p *Parser) pipelineKeywordStatement(typ string, kw *Token) *Node {
	pl := p.pipelineChainRule()
	e := tokExt(kw)
	if pl != nil {
		e = extentOf(tokExt(kw), pl.ext())
	}
	return newNode(typ, e, pl)
}

func (p *Parser) labeledStatementRule(label *Token) *Node {
	token := p.nextToken()
	switch token.Kind {
	case TkSwitch:
		return p.switchStatementRule(label, token)
	case TkForeach:
		return p.foreachStatementRule(label, token)
	case TkFor:
		return p.forStatementRule(label, token)
	case TkWhile:
		return p.whileStatementRule(label, token)
	case TkDo:
		return p.doWhileStatementRule(label, token)
	}
	p.resyncToken(label)
	return p.pipelineChainRule()
}

func (p *Parser) blockStatementRule(kind *Token) *Node {
	body := p.statementBlockRule()
	if body == nil {
		p.reportIncomplete(after(tokExt(kind)), "MissingStatementAfterKeyword")
		return newErrorStmt(extentOf(tokExt(kind), tokExt(kind)))
	}
	return newNode("BlockStatementAst", extentOf(tokExt(kind), body.ext()), body)
}

func (p *Parser) inlineScriptRule(tok *Token, elements *[]*Node) bool {
	name := newStringConst(tokExt(tok), p.tokText(tok), "BareWord")
	tok.Flags |= tfCommandName
	*elements = append(*elements, name)
	p.skipNewlines()
	lCurly := p.nextToken()
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		p.reportIncomplete(after(tokExt(tok)), "MissingStatementAfterKeyword")
		return false
	}
	*elements = append(*elements, p.scriptBlockExpressionRule(lCurly))
	return true
}

func (p *Parser) ifStatementRule(ifToken *Token) *Node {
	var componentAsts []*Node
	var kids []*Node
	var elseClause *Node
	var lastBody *Node
	keyword := ifToken
	for {
		p.skipNewlines()
		lParen := p.nextToken()
		if lParen.Kind != TkLParen {
			p.ungetToken(lParen)
			p.reportIncomplete(after(tokExt(keyword)), "MissingOpenParenthesisInIfStatement")
			return newErrorStmt(extentOf(tokExt(ifToken), tokExt(keyword)), componentAsts...)
		}
		p.skipNewlines()
		condition := p.pipelineChainRule()
		if condition == nil {
			errPos := after(tokExt(lParen))
			p.reportIncomplete(errPos, "IfStatementMissingCondition")
			condition = newErrorStmt(errPos)
		} else {
			componentAsts = append(componentAsts, condition)
		}
		p.skipNewlines()
		rParen := p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			if condition.Type != "ErrorStatementAst" {
				p.reportIncomplete(tokExt(rParen), "MissingEndParenthesisAfterStatement")
			}
			return newErrorStmt(extentOf(tokExt(ifToken), before(tokExt(rParen))), componentAsts...)
		}
		p.skipNewlines()
		body := p.statementBlockRule()
		if body == nil {
			p.reportIncomplete(tokExt(rParen), "MissingStatementBlock")
			return newErrorStmt(extentOf(tokExt(ifToken), tokExt(rParen)), componentAsts...)
		}
		componentAsts = append(componentAsts, body)
		kids = append(kids, condition, body)
		lastBody = body
		var restorePoint int
		if p.ungot == nil {
			restorePoint = p.tz.getRestorePoint()
		} else {
			restorePoint = p.ungot.Start
		}
		p.skipNewlines()
		keyword = p.peekToken()
		if keyword.Kind == TkElseIf {
			p.skipToken()
			continue
		} else if keyword.Kind == TkElse {
			p.skipToken()
			p.skipNewlines()
			elseClause = p.statementBlockRule()
			if elseClause == nil {
				p.reportIncomplete(after(tokExt(keyword)), "MissingStatementBlockAfterElse")
				return newErrorStmt(extentOf(tokExt(ifToken), tokExt(keyword)), componentAsts...)
			}
		} else {
			p.resync(restorePoint)
		}
		break
	}
	end := lastBody.ext()
	if elseClause != nil {
		end = elseClause.ext()
	}
	n := newNode("IfStatementAst", extentOf(tokExt(ifToken), end))
	n.Kids = append(n.Kids, kids...)
	if elseClause != nil {
		n.Kids = append(n.Kids, elseClause)
	}
	return n
}

const (
	swFile          = 0x01
	swRegex         = 0x02
	swWildcard      = 0x04
	swExact         = 0x08
	swCaseSensitive = 0x10
	swParallel      = 0x20
)

func switchFlagsString(f int) string {
	if f == 0 {
		return "None"
	}
	names := []struct {
		v int
		n string
	}{{swFile, "File"}, {swRegex, "Regex"}, {swWildcard, "Wildcard"}, {swExact, "Exact"}, {swCaseSensitive, "CaseSensitive"}, {swParallel, "Parallel"}}
	var out []string
	for _, e := range names {
		if f&e.v != 0 {
			out = append(out, e.n)
		}
	}
	return strings.Join(out, ", ")
}

func (p *Parser) switchStatementRule(labelToken, switchToken *Token) *Node {
	startTok := switchToken
	if labelToken != nil {
		startTok = labelToken
	}
	startExtent := tokExt(startTok)
	endErrorStatement := startExtent
	isError := false
	isIncompleteError := false
	p.skipNewlines()
	needErrorCondition := false
	var condition *Node
	var flagAsts []*Node
	switchParameterToken := p.peekToken()
	flags := 0
	for switchParameterToken.Kind == TkParameter {
		p.skipToken()
		endErrorStatement = tokExt(switchParameterToken)
		switch {
		case isSpecificParameter(switchParameterToken, "regex"):
			flags |= swRegex
			flags &^= swWildcard
		case isSpecificParameter(switchParameterToken, "wildcard"):
			flags |= swWildcard
			flags &^= swRegex
		case isSpecificParameter(switchParameterToken, "exact"):
			flags &^= swRegex
			flags &^= swWildcard
		case isSpecificParameter(switchParameterToken, "casesensitive"):
			flags |= swCaseSensitive
		case isSpecificParameter(switchParameterToken, "parallel"):
			flags |= swParallel
		case isSpecificParameter(switchParameterToken, "file"):
			flags |= swFile
			p.skipNewlines()
			fileNameExpr := p.getSingleCommandArgument(argFileName)
			if fileNameExpr == nil {
				isError = true
				isIncompleteError = p.reportIncomplete(after(tokExt(switchParameterToken)), "MissingFilenameOption")
			} else {
				endErrorStatement = fileNameExpr.ext()
				ce := newNode("CommandExpressionAst", fileNameExpr.ext(), fileNameExpr)
				condition = newNode("PipelineAst", fileNameExpr.ext(), ce)
				condition.prop("Background", "false")
				flagAsts = append(flagAsts, condition)
			}
		default:
			isError = true
			p.reportError(tokExt(switchParameterToken), "InvalidSwitchFlag")
		}
		switchParameterToken = p.peekToken()
	}
	lParen := p.peekToken()
	if lParen.Kind == TkLParen {
		endErrorStatement = tokExt(lParen)
		p.skipToken()
		if flags&swFile == swFile {
			isError = true
			p.reportError(tokExt(lParen), "PipelineValueRequired")
		}
		needErrorCondition = true
		p.skipNewlines()
		condition = p.pipelineChainRule()
		if condition == nil {
			isError = true
			isIncompleteError = p.reportIncomplete(after(tokExt(lParen)), "PipelineValueRequired")
		} else {
			endErrorStatement = condition.ext()
		}
		p.skipNewlines()
		rParen := p.nextToken()
		if rParen.Kind != TkRParen {
			p.ungetToken(rParen)
			if !isIncompleteError {
				isError = true
				isIncompleteError = p.reportIncomplete(after(endErrorStatement), "MissingEndParenthesisInSwitchStatement")
			}
		} else {
			endErrorStatement = tokExt(rParen)
		}
	} else if condition == nil {
		if flags&swFile == 0 {
			isError = true
			isIncompleteError = p.reportIncomplete(after(endErrorStatement), "PipelineValueRequired")
		}
	}
	p.skipNewlines()
	lCurly := p.nextToken()
	var def *Node
	var clauseKids []*Node
	var errorAsts []*Node
	var rCurly *Token
	if lCurly.Kind != TkLCurly {
		p.ungetToken(lCurly)
		if !isIncompleteError {
			isError = true
			p.reportIncomplete(after(endErrorStatement), "MissingCurlyBraceInSwitchStatement")
		}
	} else {
		endErrorStatement = tokExt(lCurly)
		p.skipNewlines()
		for {
			token := p.peekToken()
			isDefaultClause := token.Kind == TkDefault
			var clauseCondition *Node
			if isDefaultClause {
				p.skipToken()
				clauseCondition = newStringConst(tokExt(token), p.tokText(token), "BareWord")
			} else {
				clauseCondition = p.getSingleCommandArgument(argSwitchCondition)
				if clauseCondition == nil {
					isError = true
					p.reportIncomplete(after(endErrorStatement), "MissingSwitchConditionExpression")
					if p.peekToken().Kind == TkRCurly {
						p.skipToken()
					}
					break
				}
			}
			errorAsts = append(errorAsts, clauseCondition)
			endErrorStatement = clauseCondition.ext()
			clauseBody := p.statementBlockRule()
			if clauseBody == nil {
				isError = true
				isIncompleteError = p.reportIncomplete(after(endErrorStatement), "MissingSwitchStatementClause")
			} else {
				errorAsts = append(errorAsts, clauseBody)
				endErrorStatement = clauseBody.ext()
				if isDefaultClause {
					if def != nil {
						isError = true
						p.reportError(clauseCondition.ext(), "MultipleSwitchDefaultClauses")
					}
					def = clauseBody
				} else {
					clauseKids = append(clauseKids, clauseCondition, clauseBody)
				}
			}
			p.skipNewlinesAndSemicolons()
			token = p.peekToken()
			if token.Kind == TkRCurly {
				rCurly = token
				p.skipToken()
				break
			}
			if token.Kind == TkEndOfInput {
				if !isIncompleteError {
					isError = true
					p.reportIncompleteAt(tokExt(lCurly), tokExt(token), "MissingEndCurlyBrace")
				}
				break
			}
		}
	}
	if isError {
		var kids []*Node
		kids = append(kids, flagAsts...)
		if needErrorCondition && condition != nil {
			kids = append(kids, condition)
		}
		kids = append(kids, errorAsts...)
		return newErrorStmt(extentOf(startExtent, endErrorStatement), kids...)
	}
	n := newNode("SwitchStatementAst", extentOf(tokExt(startTok), tx(rCurly)), condition)
	n.prop("Flags", switchFlagsString(flags))
	n.Kids = append(n.Kids, clauseKids...)
	if def != nil {
		n.Kids = append(n.Kids, def)
	}
	return n
}

func (p *Parser) foreachStatementRule(labelToken, forEachToken *Token) *Node {
	startTok := forEachToken
	if labelToken != nil {
		startTok = labelToken
	}
	startOfStatement := tokExt(startTok)
	endErrorStatement := emptyExtent
	p.skipNewlines()
	foreachParameterToken := p.peekToken()
	flags := "None"
	for foreachParameterToken.Kind == TkParameter {
		p.skipToken()
		if isSpecificParameter(foreachParameterToken, "parallel") {
			flags = "Parallel"
		} else if isSpecificParameter(foreachParameterToken, "throttlelimit") {
			p.skipNewlines()
			throttle := p.getSingleCommandArgument(argCommandArgument)
			if throttle == nil {
				p.reportIncomplete(after(tokExt(foreachParameterToken)), "MissingThrottleLimit")
			}
		} else {
			endErrorStatement = tokExt(foreachParameterToken)
			p.reportError(tokExt(foreachParameterToken), "InvalidForeachFlag")
		}
		p.skipNewlines()
		foreachParameterToken = p.peekToken()
	}
	lParen := p.nextToken()
	if lParen.Kind != TkLParen {
		p.ungetToken(lParen)
		endErrorStatement = tokExt(forEachToken)
		p.reportIncomplete(after(endErrorStatement), "MissingOpenParenthesisAfterKeyword")
		return newErrorStmt(extentOf(startOfStatement, endErrorStatement))
	}
	p.skipNewlines()
	token := p.nextToken()
	if token.Kind != TkVariable && token.Kind != TkSplattedVariable {
		p.ungetToken(token)
		endErrorStatement = tokExt(lParen)
		p.reportIncomplete(after(endErrorStatement), "MissingVariableNameAfterForeach")
		return newErrorStmt(extentOf(startOfStatement, endErrorStatement))
	}
	variableAst := p.variableFromToken(token)
	p.skipNewlines()
	var pipeline, body *Node
	inToken := p.nextToken()
	if inToken.Kind != TkIn {
		p.ungetToken(inToken)
		endErrorStatement = variableAst.ext()
		p.reportIncomplete(after(endErrorStatement), "MissingInInForeach")
	} else {
		p.skipNewlines()
		pipeline = p.pipelineChainRule()
		if pipeline == nil {
			endErrorStatement = tokExt(inToken)
			p.reportIncomplete(after(endErrorStatement), "MissingForeachExpression")
		} else {
			p.skipNewlines()
			rParen := p.nextToken()
			if rParen.Kind != TkRParen {
				p.ungetToken(rParen)
				endErrorStatement = pipeline.ext()
				p.reportIncomplete(after(endErrorStatement), "MissingEndParenthesisAfterForeach")
			} else {
				body = p.statementBlockRule()
				if body == nil {
					endErrorStatement = tokExt(rParen)
					p.reportIncomplete(after(endErrorStatement), "MissingForeachStatement")
				}
			}
		}
	}
	if !endErrorStatement.empty() {
		return newErrorStmt(extentOf(startOfStatement, endErrorStatement), variableAst, pipeline, body)
	}
	n := newNode("ForEachStatementAst", extentOf(startOfStatement, body.ext()), variableAst, pipeline, body)
	n.prop("Flags", flags)
	return n
}

func (p *Parser) forStatementRule(labelToken, forToken *Token) *Node {
	startTok := forToken
	if labelToken != nil {
		startTok = labelToken
	}
	endErrorStatement := emptyExtent
	p.skipNewlines()
	lParen := p.nextToken()
	if lParen.Kind != TkLParen {
		p.ungetToken(lParen)
		endErrorStatement = tokExt(forToken)
		p.reportIncomplete(after(endErrorStatement), "MissingOpenParenthesisAfterKeyword")
		return newErrorStmt(extentOf(tokExt(startTok), endErrorStatement))
	}
	p.skipNewlines()
	initializer := p.pipelineChainRule()
	if initializer != nil {
		endErrorStatement = initializer.ext()
	}
	if p.peekToken().Kind == TkSemi {
		endErrorStatement = tokExt(p.nextToken())
	}
	p.skipNewlines()
	condition := p.pipelineChainRule()
	if condition != nil {
		endErrorStatement = condition.ext()
	}
	if p.peekToken().Kind == TkSemi {
		endErrorStatement = tokExt(p.nextToken())
	}
	p.skipNewlines()
	iterator := p.pipelineChainRule()
	if iterator != nil {
		endErrorStatement = iterator.ext()
	}
	p.skipNewlines()
	rParen := p.nextToken()
	var body *Node
	if rParen.Kind != TkRParen {
		p.ungetToken(rParen)
		if endErrorStatement.empty() {
			endErrorStatement = tokExt(lParen)
		}
		p.reportIncomplete(after(endErrorStatement), "MissingEndParenthesisAfterStatement")
	} else {
		body = p.statementBlockRule()
		if body == nil {
			endErrorStatement = tokExt(rParen)
			p.reportIncomplete(after(endErrorStatement), "MissingLoopStatement")
		}
	}
	if body == nil {
		return newErrorStmt(extentOf(tokExt(startTok), endErrorStatement), initializer, condition, iterator)
	}
	return newNode("ForStatementAst", extentOf(tokExt(startTok), body.ext()), initializer, condition, iterator, body)
}

func (p *Parser) whileStatementRule(labelToken, whileToken *Token) *Node {
	startTok := whileToken
	if labelToken != nil {
		startTok = labelToken
	}
	p.skipNewlines()
	lParen := p.nextToken()
	if lParen.Kind != TkLParen {
		p.ungetToken(lParen)
		p.reportIncomplete(after(tokExt(whileToken)), "MissingOpenParenthesisAfterKeyword")
		return newErrorStmt(extentOf(tokExt(startTok), tokExt(whileToken)))
	}
	p.skipNewlines()
	condition := p.pipelineChainRule()
	var errorCondition *Node
	if condition == nil {
		errPos := after(tokExt(lParen))
		p.reportIncomplete(errPos, "MissingExpressionAfterKeyword")
		condition = newErrorStmt(errPos)
	} else {
		errorCondition = condition
	}
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.Kind != TkRParen {
		p.ungetToken(rParen)
		if condition.Type != "ErrorStatementAst" {
			p.reportIncomplete(after(condition.ext()), "MissingEndParenthesisAfterStatement")
		}
		return newErrorStmt(extentOf(tokExt(startTok), condition.ext()), errorCondition)
	}
	p.skipNewlines()
	body := p.statementBlockRule()
	if body == nil {
		p.reportIncomplete(after(tokExt(rParen)), "MissingLoopStatement")
		return newErrorStmt(extentOf(tokExt(startTok), tokExt(rParen)), errorCondition)
	}
	return newNode("WhileStatementAst", extentOf(tokExt(startTok), body.ext()), condition, body)
}
