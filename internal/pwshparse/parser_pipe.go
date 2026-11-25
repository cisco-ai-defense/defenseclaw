// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// Pipelines, commands, redirections and command arguments (Parser.cs PipelineChainRule .. CommandRule).

const (
	argCommandName                      = 0x01
	argCommandNameAfterInvocationOperat = 0x03
	argFileName                         = 0x04
	argCommandArgument                  = 0x08
	argSwitchCondition                  = 0x10

	maxRedirections = 7
)

func (p *Parser) pipelineChainRule() *Node {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.tooDeep()
		return nil
	}
	var assignToken *Token
	var expr *Node
	func() {
		old := p.tz.mode
		defer p.setTokenizerMode(old)
		p.setTokenizerMode(modeExpression)
		expr = p.expressionRule()
		if expr != nil {
			token := p.peekToken()
			if token.Kind.hasTrait(tfAssignmentOperator) {
				p.skipToken()
				assignToken = token
			}
		}
	}()
	if expr != nil && assignToken != nil {
		p.skipNewlines()
		statement := p.statementRule()
		if statement == nil {
			errorExtent := after(tokExt(assignToken))
			p.reportIncomplete(errorExtent, "ExpectedValueExpression")
			statement = newErrorStmt(errorExtent)
		}
		// AssignmentStatementAst's constructor unwraps a foreground single-element
		// pipeline whose element is a CommandExpressionAst (ast.cs 3647).
		if statement.Type == "PipelineAst" && statement.propv("Background") != "true" &&
			len(statement.Kids) == 1 && statement.Kids[0].Type == "CommandExpressionAst" {
			statement = statement.Kids[0]
		}
		n := newNode("AssignmentStatementAst", extentOf(expr.ext(), statement.ext()), expr, statement)
		n.prop("Operator", assignToken.Kind.String())
		return n
	}
	startExpression := expr
	var currentChain *Node
	var currentOp *Token
	background := false
	for {
		var nextPipeline *Node
		var firstPipelineToken *Token
		if startExpression != nil {
			nextPipeline = p.pipelineRule(startExpression, false)
			startExpression = nil
		} else {
			firstPipelineToken = p.peekToken()
			nextPipeline = p.pipelineRule(nil, false)
		}
		if nextPipeline == nil {
			if currentOp == nil {
				return nil
			}
			switch firstPipelineToken.Kind {
			case TkEndOfInput:
				p.reportIncomplete(after(tokExt(currentOp)), "EmptyPipelineChainElement")
			case TkDot, TkAmpersand:
			default:
				p.reportError(extentOf(tokExt(currentOp), tokExt(firstPipelineToken)), "EmptyPipelineChainElement")
			}
			return newErrorStmt(extentOf(nx(currentChain), tokExt(currentOp)), currentChain)
		}
		nextToken := p.peekToken()
		stop := false
		switch nextToken.Kind {
		case TkAndAnd, TkOrOr:
			p.skipToken()
			p.skipNewlines()
		case TkAmpersand:
			p.skipToken()
			nextToken = p.peekToken()
			if nextToken.Kind == TkAndAnd || nextToken.Kind == TkOrOr {
				p.skipToken()
				p.reportError(tokExt(nextToken), "BackgroundOperatorInPipelineChain")
				if currentChain != nil {
					return newErrorStmt(extentOf(currentChain.ext(), tokExt(nextToken)))
				}
				return newErrorStmt(extentOf(nextPipeline.ext(), tokExt(nextToken)))
			}
			background = true
			stop = true
		default:
			stop = true
		}
		if stop {
			if currentChain == nil {
				if background {
					nextPipeline.prop("Background", "true")
				}
				return nextPipeline
			}
			return newChainNode(extentOf(currentChain.ext(), nextPipeline.ext()), currentChain, nextPipeline, currentOp.Kind, background)
		}
		if currentChain == nil {
			currentChain = nextPipeline
		} else {
			currentChain = newChainNode(extentOf(currentChain.ext(), nextPipeline.ext()), currentChain, nextPipeline, currentOp.Kind, false)
		}
		currentOp = nextToken
		if p.peekToken().Kind == TkEndOfInput {
			p.reportIncomplete(after(tokExt(nextToken)), "EmptyPipelineChainElement")
			return currentChain
		}
	}
}

func newChainNode(e extent, lhs, rhs *Node, op TokenKind, background bool) *Node {
	n := newNode("PipelineChainAst", e, lhs, rhs)
	n.prop("Operator", op.String()).prop("IsBackground", boolStr(background))
	return n
}

func (p *Parser) pipelineRule(startExpression *Node, allowBackground bool) *Node {
	var elements []*Node
	startExtent := emptyExtent
	var nextToken *Token
	scanning := true
	background := false
	expr := startExpression
	for scanning {
		var commandAst *Node
		if expr == nil {
			func() {
				old := p.tz.mode
				defer p.setTokenizerMode(old)
				p.setTokenizerMode(modeExpression)
				expr = p.expressionRule()
			}()
		}
		if expr != nil {
			if len(elements) > 0 {
				p.reportError(expr.ext(), "ExpressionsMustBeFirstInPipeline")
			}
			var redirections [maxRedirections]*Node
			var lastRedirection *Node
			for {
				rt := p.peekToken()
				if rt.redir() == 0 {
					break
				}
				p.skipToken()
				var unused extent
				lastRedirection, _ = p.redirectionRule(rt, &redirections, &unused)
			}
			exprExtent := expr.ext()
			if lastRedirection != nil {
				exprExtent = extentOf(expr.ext(), lastRedirection.ext())
			}
			commandAst = newNode("CommandExpressionAst", exprExtent, expr)
			for _, r := range redirections {
				if r != nil {
					commandAst.Kids = append(commandAst.Kids, r)
				}
			}
		} else {
			commandAst = p.commandRule()
		}
		if commandAst != nil {
			if startExtent.empty() {
				startExtent = commandAst.ext()
			}
			elements = append(elements, commandAst)
		} else if len(elements) > 0 || p.peekToken().Kind == TkPipe {
			var errPos extent
			if nextToken != nil {
				errPos = after(tokExt(nextToken))
			} else {
				errPos = tokExt(p.peekToken())
			}
			p.reportIncomplete(errPos, "EmptyPipeElement")
		}
		expr = nil
		nextToken = p.peekToken()
		if nextToken.Kind == TkNewLine && p.tz.isPipeContinuation(tokExt(nextToken)) {
			p.skipNewlines()
			nextToken = p.peekToken()
		}
		switch nextToken.Kind {
		case TkSemi, TkNewLine, TkRParen, TkRCurly, TkEndOfInput:
			scanning = false
		case TkAndAnd, TkOrOr:
			scanning = false
		case TkAmpersand:
			if !allowBackground {
				scanning = false
				continue
			}
			p.skipToken()
			scanning = false
			background = true
		case TkPipe:
			p.skipToken()
			p.skipNewlines()
			if p.peekToken().Kind == TkEndOfInput {
				scanning = false
				p.reportIncomplete(after(tokExt(nextToken)), "EmptyPipeElement")
			}
		default:
			p.reportError(tokExt(nextToken), "UnexpectedToken")
			scanning = false
		}
	}
	if len(elements) == 0 {
		return nil
	}
	n := newNode("PipelineAst", extentOf(startExtent, elements[len(elements)-1].ext()))
	n.Kids = elements
	n.prop("Background", boolStr(background))
	return n
}

// redirectionRule parses a redirection; the second result is the FromStream index.
func (p *Parser) redirectionRule(rt *Token, redirections *[maxRedirections]*Node, ext *extent) (*Node, int) {
	var result *Node
	var from int
	if rt.redir() == 3 || rt.redir() == 1 {
		filename := p.getSingleCommandArgument(argFileName)
		if filename == nil {
			p.reportError(after(tokExt(rt)), "MissingFileSpecification")
			filename = newErrorExpr(tokExt(rt))
		}
		if rt.redir() != 3 {
			p.reportError(tokExt(rt), "RedirectionNotSupported")
			*ext = extentOf(tokExt(rt), filename.ext())
			return nil, 0
		}
		result = newNode("FileRedirectionAst", extentOf(tokExt(rt), filename.ext()), filename)
		result.prop("FromStream", rt.fromStream().String()).prop("Append", boolStr(rt.appendMode()))
		from = int(rt.fromStream())
	} else {
		fromStream := rt.fromStream()
		toStream := rt.toStream()
		if toStream != StreamOutput {
			p.reportError(tokExt(rt), "RedirectionNotSupported")
			toStream = StreamOutput
		} else if fromStream == toStream {
			p.reportError(tokExt(rt), "RedirectionNotSupported")
		}
		result = newNode("MergingRedirectionAst", tokExt(rt))
		result.prop("FromStream", fromStream.String()).prop("ToStream", toStream.String())
		from = int(fromStream)
	}
	if redirections[from] == nil {
		redirections[from] = result
	} else {
		p.reportError(result.ext(), "StreamAlreadyRedirected")
		p.rejected = append(p.rejected, result)
	}
	*ext = result.ext()
	return result, from
}

func (p *Parser) getSingleCommandArgument(ctx int) *Node {
	if p.peekToken().Kind == TkComma || p.peekToken().Kind == TkEndOfInput {
		return nil
	}
	old := p.tz.mode
	defer p.setTokenizerMode(old)
	p.setTokenizerMode(modeCommand)
	return p.getCommandArgument(ctx, p.nextToken())
}

func (t *Token) setIsCommandArgument() {
	if t.Kind != TkIdentifier {
		t.Kind = TkGeneric
	}
}

func (p *Parser) getCommandArgument(ctx int, token *Token) *Node {
	var exprAst *Node
	var commandArgs []*Node
	var commaToken *Token
	foundVerbatim := false
	for {
		switch token.Kind {
		case TkPipe, TkRCurly, TkRParen, TkEndOfInput, TkNewLine, TkSemi, TkRedirection, TkRedirectInStd,
			TkAndAnd, TkOrOr, TkAmpersand, TkMinusMinus, TkComma:
			p.ungetToken(token)
			if commaToken == nil {
				return nil
			}
			p.reportIncomplete(after(tokExt(commaToken)), "MissingExpression")
			return newErrorExpr(extentOf(commandArgs[0].ext(), tokExt(commaToken)), commandArgs...)
		case TkSplattedVariable, TkVariable, TkNumber, TkHereStringExpandable, TkStringExpandable, TkHereStringLiteral,
			TkStringLiteral, TkLParen, TkDollarParen, TkAtParen, TkAtCurly, TkLCurly:
			p.ungetToken(token)
			exprAst = p.primaryExpressionRule(true)
		case TkGeneric:
			if ctx&argCommandName != 0 {
				token.Flags |= tfCommandName
			}
			if len(token.nested()) > 0 && ctx != argCommandName {
				nested := p.parseNestedExpressions(token)
				exprAst = p.newExpandableString(token, nested)
			} else {
				exprAst = newStringConst(tokExt(token), token.Value, "BareWord")
				if strings.EqualFold(token.Value, verbatimArgument) {
					foundVerbatim = true
				}
			}
		default:
			exprAst = newStringConst(tokExt(token), p.tokText(token), "BareWord")
			token.Flags &^= tfKeyword
			switch ctx {
			case argCommandName, argCommandNameAfterInvocationOperat:
				token.Flags |= tfCommandName
			case argFileName, argCommandArgument, argSwitchCondition:
				token.setIsCommandArgument()
			}
		}
		if ctx != argCommandArgument {
			break
		}
		if foundVerbatim {
			break
		}
		token = p.peekToken()
		if token.Kind != TkComma {
			break
		}
		commaToken = token
		commandArgs = append(commandArgs, exprAst)
		p.skipToken()
		p.skipNewlines()
		token = p.nextToken()
	}
	if commandArgs != nil {
		commandArgs = append(commandArgs, exprAst)
		return newNode("ArrayLiteralAst", extentOf(commandArgs[0].ext(), commandArgs[len(commandArgs)-1].ext()), commandArgs...)
	}
	return exprAst
}

func (p *Parser) commandRule() *Node {
	var redirections [maxRedirections]*Node
	hasRedirs := false
	sawDashDash := false
	foundVerbatim := false
	elements := make([]*Node, 0, 4)
	var firstToken *Token
	var endExtent extent
	dotSource, ampersand := false, false
	func() {
		old := p.tz.mode
		defer p.setTokenizerMode(old)
		p.setTokenizerMode(modeCommand)
		token := p.nextToken()
		firstToken = token
		endExtent = tokExt(token)
		var ctx int
		switch token.Kind {
		case TkDot:
			dotSource = true
			token = p.nextToken()
			ctx = argCommandNameAfterInvocationOperat
		case TkAmpersand:
			ampersand = true
			token = p.nextToken()
			ctx = argCommandNameAfterInvocationOperat
		default:
			ctx = argCommandName
		}
		scanning := true
		for scanning {
			switch token.Kind {
			case TkPipe, TkRCurly, TkRParen, TkEndOfInput, TkNewLine, TkSemi, TkAndAnd, TkOrOr, TkAmpersand:
				p.ungetToken(token)
				scanning = false
				continue
			case TkMinusMinus:
				endExtent = tokExt(token)
				if sawDashDash {
					elements = append(elements, newStringConst(tokExt(token), p.tokText(token), "BareWord"))
				} else {
					elements = append(elements, newCommandParameter(tokExt(token), "-", nil))
				}
				sawDashDash = true
			case TkComma:
				endExtent = tokExt(token)
				p.reportError(tokExt(token), "MissingArgument")
				p.skipNewlines()
			case TkParameter:
				if ctx&argCommandName != 0 || sawDashDash {
					endExtent = tokExt(token)
					token.Flags |= tfCommandName
					elements = append(elements, newStringConst(tokExt(token), p.tokText(token), "BareWord"))
					break
				}
				var parameterArgs *Node
				var ext extent
				if token.UsedColon && p.peekToken().Kind != TkComma {
					parameterArgs = p.getCommandArgument(argCommandArgument, p.nextToken())
					if parameterArgs == nil {
						ext = tokExt(token)
						p.reportError(after(ext), "ParameterRequiresArgument")
					} else {
						ext = extentOf(tokExt(token), parameterArgs.ext())
					}
				} else {
					ext = tokExt(token)
				}
				endExtent = ext
				elements = append(elements, newCommandParameter(ext, token.Value, parameterArgs))
			case TkRedirection, TkRedirectInStd:
				if ctx&argCommandName == 0 {
					hasRedirs = true
					p.redirectionRule(token, &redirections, &endExtent)
				} else {
					endExtent = tokExt(token)
					elements = append(elements, newStringConst(tokExt(token), p.tokText(token), "BareWord"))
				}
			default:
				if token.Kind == TkInlineScript && ctx == argCommandName {
					scanning = p.inlineScriptRule(token, &elements)
					endExtent = elements[len(elements)-1].ext()
					if !scanning {
						continue
					}
				} else {
					ast := p.getCommandArgument(ctx, token)
					if token.isStringToken() && strings.EqualFold(token.Value, verbatimArgument) {
						elements = append(elements, ast)
						endExtent = ast.ext()
						vt := p.getVerbatimCommandArgumentToken()
						if vt != nil {
							foundVerbatim = true
							scanning = false
							ast = newStringConst(tokExt(vt), vt.Value, "BareWord")
							elements = append(elements, ast)
							endExtent = ast.ext()
						}
						break
					}
					endExtent = ast.ext()
					elements = append(elements, ast)
				}
			}
			if !foundVerbatim {
				ctx = argCommandArgument
				token = p.nextToken()
			}
		}
	}()
	if len(elements) == 0 {
		if dotSource || ampersand {
			p.reportError(tokExt(firstToken), "MissingExpression")
		}
		return nil
	}
	n := newNode("CommandAst", extentOf(tokExt(firstToken), endExtent))
	n.Kids = elements
	if hasRedirs {
		for _, r := range redirections {
			if r != nil {
				n.Kids = append(n.Kids, r)
			}
		}
	}
	op := "Unknown"
	if dotSource || ampersand {
		op = firstToken.Kind.String()
	}
	n.prop("InvocationOperator", op).prop("DefiningKeyword", propNull)
	return n
}

func newCommandParameter(e extent, name string, arg *Node) *Node {
	n := newNode("CommandParameterAst", e, arg)
	n.prop("ParameterName", name)
	return n
}
