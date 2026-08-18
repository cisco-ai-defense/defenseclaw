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

package actionfacts

import (
	"math"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxInlineInterpreterTokens     = 512
	maxInlineInterpreterStatements = 64
	maxInlineInterpreterSymbols    = 32
	maxInlineInterpreterDepth      = 16
	maxInlineInterpreterCollection = 64
)

type inlineInvocationState uint8

const (
	inlineInvocationAbsent inlineInvocationState = iota
	inlineInvocationInvalid
	inlineInvocationLimited
	inlineInvocationValid
)

type inlineInvocation struct {
	program string
	body    string
}

type inlineIR struct {
	operations []OperationKind
	paths      []inlinePathFact
	network    []inlineNetworkFact
	flows      []inlineFlowFact
	children   []inlineChildSpec
	opaque     bool
	forkBomb   bool
}

type inlinePathFact struct {
	access PathAccess
	value  string
}

type inlineNetworkFact struct {
	host string
	port int64
}

type inlineFlowFact struct {
	from DataKind
	to   DataKind
}

type inlineChildSpec struct {
	argv   []string
	source string
	exec   bool
}

// expandBoundedInlineInterpreters replaces the opaque Perl/Ruby -e boundary
// only when both the complete invocation and complete inline program match a
// closed grammar. Parsing first produces a private IR; no positive fact is
// committed unless that parse succeeds in full.
func expandBoundedInlineInterpreters(out *parseOutput, wrapperDepth int) {
	if out == nil || out.status == StatusLimitExceeded {
		return
	}
	owners := cloneCommands(out.commands)
	for _, owner := range owners {
		if owner.Program != "perl" && owner.Program != "ruby" ||
			owner.Dialect != DialectPOSIX || owner.Effect != EffectExecute ||
			!owner.ArgvComplete {
			continue
		}
		if !inlineWrapperProgramIdentityExact(owner.Wrappers) {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		invocation, state := parseInlineInterpreterInvocation(owner.Argv, owner.Program)
		switch state {
		case inlineInvocationAbsent:
			continue
		case inlineInvocationLimited:
			out.markLimit(IssueInputLimit)
			return
		case inlineInvocationInvalid:
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}

		ir, ok := parseBoundedInlineProgram(invocation)
		if !ok {
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		effectiveDepth := wrapperDepth + len(owner.Wrappers)
		if len(ir.children) > 0 && effectiveDepth >= maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return
		}
		children, ok := prepareInlineChildren(out, owner, ir.children, effectiveDepth)
		if !ok || !preflightInlineCommit(out, ir, children) {
			out.markLimit(IssueFactLimit)
			return
		}
		commitInlineIR(out, owner, ir, children)
		if ir.opaque {
			out.markPartial(IssueOpaqueArtifact)
		}
	}
}

func prepareInlineChildren(
	out *parseOutput,
	owner CommandFact,
	specs []inlineChildSpec,
	wrapperDepth int,
) ([]parseOutput, bool) {
	children := make([]parseOutput, 0, len(specs))
	nextID := out.nextID
	for _, spec := range specs {
		var child parseOutput
		if spec.source != "" {
			child = parsePOSIX(spec.source, nextID, wrapperDepth+1)
		} else if len(spec.argv) > 0 {
			child = analyzeStructuredArgv(spec.argv, nextID, wrapperDepth+1, DialectPOSIX)
		} else {
			return nil, false
		}
		if !inlineChildProgramIdentityExact(child) {
			child.markPartial(IssueUnknownOperandGrammar)
		}
		expandBoundedInlineInterpreters(&child, wrapperDepth+1)
		for index := range child.commands {
			if child.commands[index].ParentCommandID == 0 {
				child.commands[index].ParentCommandID = owner.ID
			}
			wrappers := cloneWrapperFacts(owner.Wrappers)
			wrappers = append(wrappers, WrapperFact{
				Executable: owner.Executable,
				Argv:       cloneSlice(owner.Argv),
			})
			child.commands[index].Wrappers = append(
				wrappers,
				child.commands[index].Wrappers...,
			)
		}
		children = append(children, child)
		nextID = child.nextID
	}
	return children, true
}

func inlineChildProgramIdentityExact(child parseOutput) bool {
	for _, command := range child.commands {
		if command.Dialect != DialectPOSIX || command.Executable == "" || command.Program == "" {
			continue
		}
		if !exactPOSIXProgramIdentity(command.Executable, command.Program) {
			return false
		}
	}
	return true
}

func inlineWrapperProgramIdentityExact(wrappers []WrapperFact) bool {
	for _, wrapper := range wrappers {
		if len(wrapper.Argv) == 0 || wrapper.Argv[0] != wrapper.Executable ||
			!exactPOSIXProgramIdentity(wrapper.Executable, commandProgram(wrapper.Executable)) {
			return false
		}
	}
	return true
}

func exactPOSIXProgramIdentity(executable, program string) bool {
	return program != "" && strings.TrimSpace(executable) == executable &&
		executable != "" && !strings.Contains(executable, `\`) &&
		(!strings.Contains(executable, "/") || trustedPOSIXExecutablePath(executable)) &&
		path.Base(executable) == program
}

func trustedPOSIXExecutablePath(executable string) bool {
	if executable == "" || path.Clean(executable) != executable {
		return false
	}
	for _, prefix := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"} {
		if strings.HasPrefix(executable, prefix) && len(executable) > len(prefix) {
			return true
		}
	}
	return false
}

func cloneWrapperFacts(input []WrapperFact) []WrapperFact {
	if len(input) == 0 {
		return nil
	}
	cloned := make([]WrapperFact, len(input))
	for index, wrapper := range input {
		cloned[index] = WrapperFact{
			Executable: wrapper.Executable,
			Argv:       cloneSlice(wrapper.Argv),
		}
	}
	return cloned
}

func preflightInlineCommit(out *parseOutput, ir inlineIR, children []parseOutput) bool {
	commands := len(out.commands)
	paths := len(out.paths) + len(ir.paths)
	network := len(out.network) + len(ir.network)
	flows := len(out.dataFlows) + len(ir.flows)
	for _, child := range children {
		commands += len(child.commands)
		paths += len(child.paths)
		network += len(child.network)
		flows += len(child.dataFlows)
	}
	return commands <= maxCommands && paths <= maxPathFacts &&
		network <= maxNetworkFacts && flows <= maxDataFlowFacts
}

func commitInlineIR(
	out *parseOutput,
	owner CommandFact,
	ir inlineIR,
	children []parseOutput,
) {
	ownerIndex := -1
	for index := range out.commands {
		if out.commands[index].ID == owner.ID {
			ownerIndex = index
			break
		}
	}
	if ownerIndex < 0 {
		out.markAmbiguous(IssueConflictingSources)
		return
	}
	addOperation(&out.commands[ownerIndex], OperationExecute)
	for _, operation := range ir.operations {
		addOperation(&out.commands[ownerIndex], operation)
	}
	for _, fact := range ir.paths {
		appendPath(out, owner.ID, fact.access, fact.value)
	}
	for _, fact := range ir.network {
		out.appendNetwork(NetworkFact{
			CommandID: owner.ID,
			Action:    NetworkConnect,
			Scheme:    "tcp",
			Host:      fact.host,
			Port:      fact.port,
		})
	}
	for _, fact := range ir.flows {
		flow := DataFlowFact{From: fact.from, To: fact.to}
		if fact.from != DataNetwork {
			flow.FromCommandID = owner.ID
		}
		if fact.to != DataNetwork {
			flow.ToCommandID = owner.ID
		}
		out.appendDataFlow(flow)
	}
	for _, child := range children {
		out.mergeNested(child)
	}
}

// RecognizesPOSIXPerlInlineBody reports that the visible Perl -e body is fully
// consumed by the bounded grammar. Like the rest of ActionFacts, this proof is
// scoped to visible action input; callers must separately require authoritative
// facts before using it to suppress a conservative fallback.
func RecognizesPOSIXPerlInlineBody(command CommandFact) bool {
	_, ok := recognizesBoundedInlineOwner(command, "perl")
	return ok
}

// RecognizesPOSIXRubyInlineBody reports that the visible Ruby -e body is fully
// consumed by the bounded grammar. Like the rest of ActionFacts, this proof is
// scoped to visible action input; callers must separately require authoritative
// facts before using it to suppress a conservative fallback.
func RecognizesPOSIXRubyInlineBody(command CommandFact) bool {
	_, ok := recognizesBoundedInlineOwner(command, "ruby")
	return ok
}

func recognizesBoundedInlineOwner(command CommandFact, program string) (inlineInvocation, bool) {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		!command.ArgvComplete || command.Program != program ||
		!inlineWrapperProgramIdentityExact(command.Wrappers) {
		return inlineInvocation{}, false
	}
	invocation, state := parseInlineInterpreterInvocation(command.Argv, program)
	if state != inlineInvocationValid {
		return inlineInvocation{}, false
	}
	_, ok := parseBoundedInlineProgram(invocation)
	return invocation, ok
}

// ProvesPOSIXInlineInterpreterShellExec reports whether a fully parsed inline
// owner contains one exact exec child which is the matching interactive POSIX
// shell. A system child cannot satisfy this replacement proof. This is a
// positive detection ingredient only; it must not establish whole-action
// authority or suppress a conservative fallback by itself.
func ProvesPOSIXInlineInterpreterShellExec(facts Facts, ownerID int64) bool {
	var owner CommandFact
	for _, command := range facts.Commands {
		if command.ID == ownerID {
			owner = command
			break
		}
	}
	if !RecognizesPOSIXPerlInlineBody(owner) && !RecognizesPOSIXRubyInlineBody(owner) {
		return false
	}
	invocation, state := parseInlineInterpreterInvocation(owner.Argv, owner.Program)
	if state != inlineInvocationValid {
		return false
	}
	ir, ok := parseBoundedInlineProgram(invocation)
	if !ok {
		return false
	}
	var expected []string
	for _, child := range ir.children {
		if !child.exec || len(child.argv) == 0 || child.source != "" {
			continue
		}
		if expected != nil {
			return false
		}
		expected = child.argv
	}
	if expected == nil {
		return false
	}
	matches := 0
	for _, command := range facts.Commands {
		if command.ParentCommandID == ownerID && equalStrings(command.Argv, expected) &&
			exactPOSIXInteractiveShellExecutable(command.Executable) &&
			ProvesPOSIXInteractiveShell(command) {
			matches++
		}
	}
	return matches == 1
}

func exactPOSIXInteractiveShellExecutable(executable string) bool {
	if strings.TrimSpace(executable) != executable || executable == "" ||
		strings.Contains(executable, `\`) ||
		strings.Contains(executable, "/") && !trustedPOSIXExecutablePath(executable) {
		return false
	}
	switch path.Base(executable) {
	case "bash", "sh", "zsh", "dash", "ksh", "mksh":
		return true
	default:
		return false
	}
}

// ProvesPOSIXInlineInterpreterForkBomb recognizes only the two complete,
// closed syntax forms accepted by the parser. Inert string contents cannot
// satisfy it. This positive proof does not establish whole-action authority.
func ProvesPOSIXInlineInterpreterForkBomb(command CommandFact) bool {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		!command.ArgvComplete || !inlineWrapperProgramIdentityExact(command.Wrappers) {
		return false
	}
	invocation, state := parseInlineInterpreterInvocation(command.Argv, command.Program)
	if state != inlineInvocationValid {
		return false
	}
	ir, ok := parseBoundedInlineProgram(invocation)
	return ok && ir.forkBomb
}

func parseInlineInterpreterInvocation(argv []string, program string) (inlineInvocation, inlineInvocationState) {
	if len(argv) < 2 || (program != "perl" && program != "ruby") ||
		!exactPOSIXInlineExecutable(argv[0], program) {
		return inlineInvocation{}, inlineInvocationAbsent
	}
	fragments := make([]string, 0, 2)
	seenCode := false
	seenRubyDisableGems := false
	seenPerlNoSiteCustomize := false
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if program == "ruby" && argument == "--disable=gems,rubyopt" &&
			!seenCode && !seenRubyDisableGems {
			seenRubyDisableGems = true
			continue
		}
		if program == "ruby" && argument == "--disable-gems" && !seenCode && !seenRubyDisableGems {
			seenRubyDisableGems = true
			continue
		}
		if program == "perl" && argument == "-T" && index == 1 {
			continue
		}
		if program == "perl" && argument == "-f" && !seenCode && !seenPerlNoSiteCustomize {
			seenPerlNoSiteCustomize = true
			continue
		}
		if program == "perl" && !seenCode && (argument == "-w" || argument == "-W") {
			continue
		}
		if argument == "-e" {
			if index+1 >= len(argv) {
				return inlineInvocation{}, inlineInvocationInvalid
			}
			index++
			fragments = append(fragments, argv[index])
			seenCode = true
			continue
		}
		if strings.HasPrefix(argument, "-e") && len(argument) > 2 {
			fragments = append(fragments, argument[2:])
			seenCode = true
			continue
		}
		if program == "perl" && !seenCode && strings.HasPrefix(argument, "-") &&
			!strings.HasPrefix(argument, "--") {
			bundle := argument[1:]
			position := strings.IndexByte(bundle, 'e')
			if position >= 0 && inlinePerlBundlePrefix(bundle[:position]) {
				code := bundle[position+1:]
				if code == "" {
					if index+1 >= len(argv) {
						return inlineInvocation{}, inlineInvocationInvalid
					}
					index++
					code = argv[index]
				}
				fragments = append(fragments, code)
				seenCode = true
				continue
			}
		}
		state := inlineInvocationInvalid
		if !seenCode && !inlineArgumentLooksLikeCodeOption(argument, program) {
			state = inlineInvocationAbsent
		}
		return inlineInvocation{}, state
	}
	if !seenCode || len(fragments) == 0 {
		return inlineInvocation{}, inlineInvocationAbsent
	}
	body := strings.Join(fragments, "\n")
	if body == "" {
		return inlineInvocation{}, inlineInvocationInvalid
	}
	if len(body) > maxInlineInterpreterBytes {
		return inlineInvocation{}, inlineInvocationLimited
	}
	if !utf8.ValidString(body) || strings.IndexByte(body, 0) >= 0 {
		return inlineInvocation{}, inlineInvocationInvalid
	}
	return inlineInvocation{program: program, body: body}, inlineInvocationValid
}

func exactPOSIXInlineExecutable(executable, program string) bool {
	return exactPOSIXProgramIdentity(executable, program)
}

func inlinePerlBundlePrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	for _, char := range prefix {
		if char != 'w' && char != 'W' {
			return false
		}
	}
	return true
}

func inlineArgumentLooksLikeCodeOption(argument, program string) bool {
	if argument == "-e" || strings.HasPrefix(argument, "-e") {
		return true
	}
	return program == "perl" && strings.HasPrefix(argument, "-") &&
		strings.ContainsRune(argument[1:], 'e')
}

type inlineTokenKind uint8

const (
	inlineTokenEOF inlineTokenKind = iota
	inlineTokenIdent
	inlineTokenVariable
	inlineTokenNumber
	inlineTokenString
	inlineTokenSymbol
)

type inlineToken struct {
	kind inlineTokenKind
	text string
}

func lexInlineProgram(source, program string) ([]inlineToken, bool) {
	tokens := make([]inlineToken, 0, 64)
	for index := 0; index < len(source); {
		char := source[index]
		if char < utf8.RuneSelf && unicode.IsSpace(rune(char)) {
			// Ruby line breaks are statement boundaries unless the surrounding
			// syntax proves continuation. The bounded grammar deliberately does
			// not model that full layout rule, so reject visible newlines instead
			// of joining a zero-argument call to a following parenthesized value.
			if program == "ruby" && (char == '\n' || char == '\r') {
				return nil, false
			}
			index++
			continue
		}
		if char >= utf8.RuneSelf {
			return nil, false
		}
		if isInlineIdentStart(char) {
			start := index
			index++
			for index < len(source) {
				if isInlineIdentContinue(source[index]) {
					index++
					continue
				}
				if index+2 < len(source) && source[index] == ':' && source[index+1] == ':' &&
					isInlineIdentStart(source[index+2]) {
					index += 2
					continue
				}
				break
			}
			tokens = append(tokens, inlineToken{kind: inlineTokenIdent, text: source[start:index]})
		} else if char == '$' {
			start := index
			index++
			if index >= len(source) || !isInlineIdentStart(source[index]) {
				return nil, false
			}
			for index < len(source) && isInlineIdentContinue(source[index]) {
				index++
			}
			tokens = append(tokens, inlineToken{kind: inlineTokenVariable, text: source[start:index]})
		} else if char >= '0' && char <= '9' {
			start := index
			for index < len(source) && source[index] >= '0' && source[index] <= '9' {
				index++
			}
			tokens = append(tokens, inlineToken{kind: inlineTokenNumber, text: source[start:index]})
		} else if char == '\'' || char == '"' {
			value, next, ok := lexInlineString(source, index, program)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, inlineToken{kind: inlineTokenString, text: value})
			index = next
		} else {
			symbol := string(char)
			if index+1 < len(source) {
				pair := source[index : index+2]
				if program == "perl" && (pair == "++" || pair == "--") {
					return nil, false
				}
				switch pair {
				case "=>", "->", ">>", "<&", ">&", "==", "!=", "<=", ">=", "&&", "||":
					symbol = pair
					index++
				}
			}
			if !strings.Contains("()[]{},;.=+-*/<>", string(symbol[0])) {
				return nil, false
			}
			tokens = append(tokens, inlineToken{kind: inlineTokenSymbol, text: symbol})
			index++
		}
		if len(tokens) > maxInlineInterpreterTokens {
			return nil, false
		}
	}
	tokens = append(tokens, inlineToken{kind: inlineTokenEOF})
	return tokens, true
}

func lexInlineString(source string, start int, program string) (string, int, bool) {
	quote := source[start]
	var value strings.Builder
	for index := start + 1; index < len(source); index++ {
		char := source[index]
		if char == quote {
			return value.String(), index + 1, true
		}
		if quote == '"' {
			if char == '$' || program == "perl" && char == '@' ||
				program == "ruby" && char == '#' && index+1 < len(source) &&
					(source[index+1] == '{' || source[index+1] == '@' || source[index+1] == '$') {
				return "", 0, false
			}
		}
		if char == '\\' {
			index++
			if index >= len(source) {
				return "", 0, false
			}
			escaped := source[index]
			if quote == '\'' {
				if escaped != '\\' && escaped != '\'' {
					return "", 0, false
				}
				value.WriteByte(escaped)
				continue
			}
			switch escaped {
			case '\\', '"':
				value.WriteByte(escaped)
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			default:
				return "", 0, false
			}
			continue
		}
		if char < 0x20 && char != '\t' {
			return "", 0, false
		}
		value.WriteByte(char)
	}
	return "", 0, false
}

func isInlineIdentStart(char byte) bool {
	return char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

func isInlineIdentContinue(char byte) bool {
	return isInlineIdentStart(char) || char >= '0' && char <= '9'
}

type inlineValueKind uint8

const (
	inlineValueInvalid inlineValueKind = iota
	inlineValueString
	inlineValueInteger
	inlineValueArray
	inlineValueHandle
	inlineValueSocket
)

type inlineValue struct {
	kind  inlineValueKind
	text  string
	num   int64
	items []inlineValue
}

type inlineParser struct {
	program          string
	tokens           []inlineToken
	position         int
	depth            int
	statements       int
	symbols          map[string]inlineValue
	seenSocketImport bool
	ir               inlineIR
}

func parseBoundedInlineProgram(invocation inlineInvocation) (inlineIR, bool) {
	tokens, ok := lexInlineProgram(invocation.body, invocation.program)
	if !ok {
		return inlineIR{}, false
	}
	parser := inlineParser{
		program: invocation.program,
		tokens:  tokens,
		symbols: make(map[string]inlineValue),
	}
	if parser.parseExactForkBomb() {
		parser.ir.forkBomb = true
		return parser.ir, true
	}
	for !parser.atEOF() {
		if parser.statements >= maxInlineInterpreterStatements {
			return inlineIR{}, false
		}
		parser.statements++
		terminal, ok := parser.parseStatement()
		if !ok {
			return inlineIR{}, false
		}
		separators := 0
		for parser.consumeSymbol(";") {
			separators++
		}
		if terminal && !parser.atEOF() || !parser.atEOF() && separators == 0 {
			return inlineIR{}, false
		}
	}
	if parser.statements == 0 {
		return inlineIR{}, false
	}
	return parser.ir, true
}

func (parser *inlineParser) parseExactForkBomb() bool {
	end := len(parser.tokens) - 1
	if end > 0 && parser.tokens[end-1].kind == inlineTokenSymbol &&
		parser.tokens[end-1].text == ";" {
		end--
	}
	if parser.program == "perl" && end == 3 &&
		parser.tokens[0].kind == inlineTokenIdent && parser.tokens[0].text == "fork" &&
		parser.tokens[1].kind == inlineTokenIdent && parser.tokens[1].text == "while" &&
		parser.tokens[2].kind == inlineTokenIdent && parser.tokens[2].text == "fork" {
		parser.position = len(parser.tokens) - 1
		return true
	}
	if parser.program == "ruby" && end == 4 &&
		parser.tokens[0].kind == inlineTokenIdent && parser.tokens[0].text == "loop" &&
		parser.tokens[1].kind == inlineTokenSymbol && parser.tokens[1].text == "{" &&
		parser.tokens[2].kind == inlineTokenIdent && parser.tokens[2].text == "fork" &&
		parser.tokens[3].kind == inlineTokenSymbol && parser.tokens[3].text == "}" {
		parser.position = len(parser.tokens) - 1
		return true
	}
	return false
}

func (parser *inlineParser) parseStatement() (bool, bool) {
	if parser.peek().kind != inlineTokenIdent {
		return false, false
	}
	if parser.program == "perl" {
		return parser.parsePerlStatement()
	}
	return parser.parseRubyStatement()
}

func (parser *inlineParser) parsePerlStatement() (bool, bool) {
	switch parser.peekText() {
	case "my":
		return false, parser.parsePerlAssignment()
	case "print", "warn":
		return false, parser.parseDiagnostic()
	case "open":
		return false, parser.parsePerlOpen()
	case "use":
		return false, parser.parsePerlImport()
	case "system":
		return false, parser.parseChildCall(false)
	case "exec":
		return true, parser.parseChildCall(true)
	default:
		return false, false
	}
}

func (parser *inlineParser) parseRubyStatement() (bool, bool) {
	switch parser.peekText() {
	case "require":
		return false, parser.parseRubyImport()
	case "puts", "print", "p", "warn":
		return false, parser.parseDiagnostic()
	case "File":
		return false, parser.parseRubyFileCall()
	case "STDIN", "STDOUT":
		return false, parser.parseRubyReopen()
	case "system":
		return false, parser.parseChildCall(false)
	case "exec":
		return true, parser.parseChildCall(true)
	default:
		if parser.peek().kind == inlineTokenIdent && parser.peekN(1).text == "=" {
			return false, parser.parseRubyAssignment()
		}
		return false, false
	}
}

func (parser *inlineParser) parsePerlAssignment() bool {
	if !parser.consumeIdent("my") || parser.peek().kind != inlineTokenVariable {
		return false
	}
	name := parser.take().text
	if !parser.consumeSymbol("=") || parser.symbolDefined(name) {
		return false
	}
	if parser.peekText() == "IO::Socket::INET" {
		value, ok := parser.parsePerlSocket()
		if !ok {
			return false
		}
		return parser.defineSymbol(name, value)
	}
	value, ok := parser.parseExpression()
	return ok && value.kind != inlineValueSocket && value.kind != inlineValueHandle &&
		parser.defineSymbol(name, value)
}

func (parser *inlineParser) parseRubyAssignment() bool {
	name := parser.take().text
	if !validInlineRubyLocal(name) ||
		!parser.consumeSymbol("=") || parser.symbolDefined(name) {
		return false
	}
	if parser.peekText() == "TCPSocket" {
		value, ok := parser.parseRubySocket()
		if !ok {
			return false
		}
		return parser.defineSymbol(name, value)
	}
	value, ok := parser.parseExpression()
	return ok && value.kind != inlineValueSocket && value.kind != inlineValueHandle &&
		parser.defineSymbol(name, value)
}

func validInlineRubyLocal(name string) bool {
	if name == "" || strings.Contains(name, "::") ||
		name[0] != '_' && (name[0] < 'a' || name[0] > 'z') ||
		len(name) == 2 && name[0] == '_' && name[1] >= '1' && name[1] <= '9' {
		return false
	}
	switch name {
	case "BEGIN", "END", "__ENCODING__", "__FILE__", "__LINE__",
		"alias", "and", "begin", "break", "case", "class",
		"def", "defined", "do", "else", "elsif", "end", "ensure", "false",
		"for", "if", "in", "module", "next", "nil", "not", "or", "redo",
		"rescue", "retry", "return", "self", "super", "then", "true", "undef",
		"unless", "until", "when", "while", "yield":
		return false
	default:
		return true
	}
}

func (parser *inlineParser) parseDiagnostic() bool {
	parser.take()
	parenthesized := parser.consumeSymbol("(")
	count := 0
	for {
		if parenthesized && parser.peekText() == ")" {
			break
		}
		if !parenthesized && (parser.peekText() == ";" || parser.atEOF()) {
			break
		}
		value, ok := parser.parseExpression()
		if !ok || value.kind == inlineValueSocket || value.kind == inlineValueHandle {
			return false
		}
		count++
		if !parser.consumeSymbol(",") {
			break
		}
		if parser.program == "ruby" && !parenthesized &&
			(parser.peekText() == ";" || parser.atEOF()) {
			return false
		}
	}
	if count == 0 {
		return false
	}
	return !parenthesized || parser.consumeSymbol(")")
}

func (parser *inlineParser) parsePerlImport() bool {
	if !parser.consumeIdent("use") || !parser.consumeIdent("IO::Socket::INET") ||
		parser.seenSocketImport {
		return false
	}
	parser.seenSocketImport = true
	parser.ir.opaque = true
	return true
}

func (parser *inlineParser) parseRubyImport() bool {
	if !parser.consumeIdent("require") || parser.peek().kind != inlineTokenString ||
		parser.peek().text != "socket" || parser.seenSocketImport {
		return false
	}
	parser.take()
	parser.seenSocketImport = true
	parser.ir.opaque = true
	return true
}

func (parser *inlineParser) parsePerlSocket() (inlineValue, bool) {
	if !parser.seenSocketImport || !parser.consumeIdent("IO::Socket::INET") ||
		!parser.consumeSymbol("->") || !parser.consumeIdent("new") ||
		!parser.consumeSymbol("(") {
		return inlineValue{}, false
	}
	values := make(map[string]inlineValue, 3)
	for {
		if parser.peek().kind != inlineTokenIdent {
			return inlineValue{}, false
		}
		key := parser.take().text
		if _, exists := values[key]; exists || !parser.consumeSymbol("=>") {
			return inlineValue{}, false
		}
		value, ok := parser.parseExpression()
		if !ok {
			return inlineValue{}, false
		}
		values[key] = value
		if !parser.consumeSymbol(",") {
			break
		}
	}
	if !parser.consumeSymbol(")") || len(values) != 3 ||
		values["PeerAddr"].kind != inlineValueString ||
		values["PeerPort"].kind != inlineValueInteger ||
		values["Proto"].kind != inlineValueString || values["Proto"].text != "tcp" {
		return inlineValue{}, false
	}
	if address, err := netip.ParseAddr(values["PeerAddr"].text); err == nil && address.Is6() {
		// IO::Socket::INET is an AF_INET interface. IPv6 literals require a
		// different module whose semantics are outside this bounded grammar.
		return inlineValue{}, false
	}
	if !parser.addNetwork(values["PeerAddr"].text, values["PeerPort"].num) {
		return inlineValue{}, false
	}
	return inlineValue{kind: inlineValueSocket}, true
}

func (parser *inlineParser) parseRubySocket() (inlineValue, bool) {
	if !parser.seenSocketImport || !parser.consumeIdent("TCPSocket") ||
		!parser.consumeSymbol(".") || !parser.consumeIdent("new") ||
		!parser.consumeSymbol("(") {
		return inlineValue{}, false
	}
	host, hostOK := parser.parseExpression()
	if !hostOK || !parser.consumeSymbol(",") {
		return inlineValue{}, false
	}
	port, portOK := parser.parseExpression()
	if !portOK || !parser.consumeSymbol(")") || host.kind != inlineValueString ||
		port.kind != inlineValueInteger || !parser.addNetwork(host.text, port.num) {
		return inlineValue{}, false
	}
	return inlineValue{kind: inlineValueSocket}, true
}

func (parser *inlineParser) addNetwork(host string, port int64) bool {
	if !validNetworkHost(host) || port < 1 || port > 65535 {
		return false
	}
	parser.addOperation(OperationConnect)
	parser.ir.network = append(parser.ir.network, inlineNetworkFact{host: host, port: port})
	return true
}

func (parser *inlineParser) parsePerlOpen() bool {
	if !parser.consumeIdent("open") || !parser.consumeSymbol("(") {
		return false
	}
	if parser.consumeIdent("my") {
		if parser.peek().kind != inlineTokenVariable {
			return false
		}
		handle := parser.take().text
		if parser.symbolDefined(handle) || !parser.consumeSymbol(",") {
			return false
		}
		mode, modeOK := parser.parseExpression()
		if !modeOK || mode.kind != inlineValueString || !parser.consumeSymbol(",") {
			return false
		}
		pathValue, pathOK := parser.parseExpression()
		if !pathOK || pathValue.kind != inlineValueString || !parser.consumeSymbol(")") ||
			!validInlinePOSIXPath(pathValue.text) {
			return false
		}
		var operation OperationKind
		var access PathAccess
		switch mode.text {
		case "<":
			operation, access = OperationRead, PathAccessRead
		case ">":
			operation, access = OperationWrite, PathAccessWrite
		case ">>":
			operation, access = OperationAppend, PathAccessAppend
		default:
			return false
		}
		parser.addOperation(operation)
		parser.ir.paths = append(parser.ir.paths, inlinePathFact{access: access, value: pathValue.text})
		return parser.defineSymbol(handle, inlineValue{kind: inlineValueHandle})
	}
	if parser.peek().kind != inlineTokenIdent {
		return false
	}
	descriptor := parser.take().text
	if descriptor != "STDIN" && descriptor != "STDOUT" || !parser.consumeSymbol(",") {
		return false
	}
	mode, modeOK := parser.parseExpression()
	if !modeOK || mode.kind != inlineValueString || !parser.consumeSymbol(",") ||
		parser.peek().kind != inlineTokenVariable {
		return false
	}
	socket := parser.take().text
	if !parser.consumeSymbol(")") || parser.symbols[socket].kind != inlineValueSocket {
		return false
	}
	if descriptor == "STDIN" && mode.text == "<&" {
		parser.ir.flows = append(parser.ir.flows, inlineFlowFact{from: DataNetwork, to: DataStdin})
		return true
	}
	if descriptor == "STDOUT" && mode.text == ">&" {
		parser.ir.flows = append(parser.ir.flows, inlineFlowFact{from: DataStdout, to: DataNetwork})
		return true
	}
	return false
}

func (parser *inlineParser) parseRubyFileCall() bool {
	if !parser.consumeIdent("File") || !parser.consumeSymbol(".") ||
		parser.peek().kind != inlineTokenIdent {
		return false
	}
	method := parser.take().text
	if !parser.consumeSymbol("(") {
		return false
	}
	pathValue, ok := parser.parseExpression()
	if !ok || pathValue.kind != inlineValueString || !validInlinePOSIXPath(pathValue.text) {
		return false
	}
	var operation OperationKind
	var access PathAccess
	switch method {
	case "read":
		operation, access = OperationRead, PathAccessRead
	case "write":
		if !parser.consumeSymbol(",") {
			return false
		}
		value, valueOK := parser.parseExpression()
		if !valueOK || value.kind != inlineValueString {
			return false
		}
		operation, access = OperationWrite, PathAccessWrite
	case "delete", "unlink":
		operation, access = OperationDelete, PathAccessDelete
	default:
		return false
	}
	if !parser.consumeSymbol(")") {
		return false
	}
	parser.addOperation(operation)
	parser.ir.paths = append(parser.ir.paths, inlinePathFact{access: access, value: pathValue.text})
	return true
}

func (parser *inlineParser) parseRubyReopen() bool {
	descriptor := parser.take().text
	if !parser.consumeSymbol(".") || !parser.consumeIdent("reopen") ||
		!parser.consumeSymbol("(") || parser.peek().kind != inlineTokenIdent {
		return false
	}
	socket := parser.take().text
	if !parser.consumeSymbol(")") || parser.symbols[socket].kind != inlineValueSocket {
		return false
	}
	if descriptor == "STDIN" {
		parser.ir.flows = append(parser.ir.flows, inlineFlowFact{from: DataNetwork, to: DataStdin})
	} else {
		parser.ir.flows = append(parser.ir.flows, inlineFlowFact{from: DataStdout, to: DataNetwork})
	}
	return true
}

func (parser *inlineParser) parseChildCall(exec bool) bool {
	name := parser.take().text
	if name != "system" && name != "exec" || !parser.consumeSymbol("(") {
		return false
	}
	arguments := make([]string, 0, 4)
	for {
		value, ok := parser.parseExpression()
		if !ok || value.kind != inlineValueString {
			return false
		}
		arguments = append(arguments, value.text)
		if !parser.consumeSymbol(",") {
			break
		}
	}
	if !parser.consumeSymbol(")") || len(arguments) == 0 {
		return false
	}
	if exec && len(arguments) == 1 {
		// Scalar exec uses language-specific command-line/shell semantics;
		// only explicit argv-list replacement is modeled here.
		return false
	}
	child := inlineChildSpec{exec: exec}
	if !exec && parser.program == "ruby" && len(arguments) == 1 {
		if strings.TrimSpace(arguments[0]) == "" || len(arguments[0]) > maxScalarBytes {
			return false
		}
		child.source = arguments[0]
	} else {
		if !exec && parser.program == "perl" && len(arguments) < 2 {
			return false
		}
		child.argv = cloneSlice(arguments)
	}
	parser.ir.children = append(parser.ir.children, child)
	return true
}

func validInlinePOSIXPath(value string) bool {
	return value != "" && len(value) <= maxScalarBytes && path.IsAbs(value) &&
		path.Clean(value) == value && !strings.ContainsAny(value, `$~*?[]{}\\`)
}

func (parser *inlineParser) parseExpression() (inlineValue, bool) {
	return parser.parseAdditive()
}

func (parser *inlineParser) parseAdditive() (inlineValue, bool) {
	left, ok := parser.parseMultiplicative()
	if !ok {
		return inlineValue{}, false
	}
	for parser.peek().kind == inlineTokenSymbol &&
		(parser.peekText() == "+" || parser.peekText() == "-") {
		operator := parser.take().text
		right, rightOK := parser.parseMultiplicative()
		if !rightOK || left.kind != inlineValueInteger || right.kind != inlineValueInteger {
			return inlineValue{}, false
		}
		if operator == "+" {
			if right.num > 0 && left.num > math.MaxInt64-right.num ||
				right.num < 0 && left.num < math.MinInt64-right.num {
				return inlineValue{}, false
			}
			left.num += right.num
		} else {
			if right.num == math.MinInt64 || right.num > 0 && left.num < math.MinInt64+right.num ||
				right.num < 0 && left.num > math.MaxInt64+right.num {
				return inlineValue{}, false
			}
			left.num -= right.num
		}
	}
	return left, true
}

func (parser *inlineParser) parseMultiplicative() (inlineValue, bool) {
	left, ok := parser.parseUnary()
	if !ok {
		return inlineValue{}, false
	}
	for parser.peek().kind == inlineTokenSymbol && parser.peekText() == "*" {
		parser.take()
		right, rightOK := parser.parseUnary()
		if !rightOK || left.kind != inlineValueInteger || right.kind != inlineValueInteger {
			return inlineValue{}, false
		}
		if left.num != 0 && (left.num == math.MinInt64 && right.num == -1 ||
			right.num != 0 && left.num*right.num/right.num != left.num) {
			return inlineValue{}, false
		}
		left.num *= right.num
	}
	return left, true
}

func (parser *inlineParser) parseUnary() (inlineValue, bool) {
	if parser.consumeSymbol("+") {
		if parser.program == "perl" && (parser.peekText() == "+" || parser.peekText() == "-") {
			return inlineValue{}, false
		}
		value, ok := parser.parseUnary()
		if !ok || value.kind != inlineValueInteger {
			return inlineValue{}, false
		}
		return value, true
	}
	if parser.consumeSymbol("-") {
		if parser.program == "perl" && (parser.peekText() == "+" || parser.peekText() == "-") {
			return inlineValue{}, false
		}
		value, ok := parser.parseUnary()
		if !ok || value.kind != inlineValueInteger || value.num == math.MinInt64 {
			return inlineValue{}, false
		}
		value.num = -value.num
		return value, true
	}
	return parser.parsePrimary()
}

func (parser *inlineParser) parsePrimary() (inlineValue, bool) {
	if parser.depth >= maxInlineInterpreterDepth {
		return inlineValue{}, false
	}
	parser.depth++
	defer func() { parser.depth-- }()
	token := parser.peek()
	var value inlineValue
	switch token.kind {
	case inlineTokenString:
		parser.take()
		value = inlineValue{kind: inlineValueString, text: token.text}
	case inlineTokenNumber:
		parser.take()
		if len(token.text) > 1 && token.text[0] == '0' {
			return inlineValue{}, false
		}
		number, err := strconv.ParseInt(token.text, 10, 64)
		if err != nil {
			return inlineValue{}, false
		}
		value = inlineValue{kind: inlineValueInteger, num: number}
	case inlineTokenVariable, inlineTokenIdent:
		parser.take()
		known, exists := parser.symbols[token.text]
		if !exists || known.kind == inlineValueSocket || known.kind == inlineValueHandle {
			return inlineValue{}, false
		}
		value = known
	case inlineTokenSymbol:
		if token.text == "(" {
			parser.take()
			inner, ok := parser.parseExpression()
			if !ok || !parser.consumeSymbol(")") {
				return inlineValue{}, false
			}
			value = inner
		} else if token.text == "[" {
			parser.take()
			items := make([]inlineValue, 0, 4)
			if !parser.consumeSymbol("]") {
				for {
					item, ok := parser.parseExpression()
					if !ok || item.kind == inlineValueSocket || item.kind == inlineValueHandle ||
						len(items) >= maxInlineInterpreterCollection {
						return inlineValue{}, false
					}
					items = append(items, item)
					if parser.consumeSymbol("]") {
						break
					}
					if !parser.consumeSymbol(",") {
						return inlineValue{}, false
					}
				}
			}
			value = inlineValue{kind: inlineValueArray, items: items}
		} else {
			return inlineValue{}, false
		}
	default:
		return inlineValue{}, false
	}
	for parser.program == "ruby" && parser.consumeSymbol(".") {
		if !parser.consumeIdent("join") || value.kind != inlineValueArray ||
			!parser.consumeSymbol("(") {
			return inlineValue{}, false
		}
		separator, ok := parser.parseExpression()
		if !ok || separator.kind != inlineValueString || !parser.consumeSymbol(")") {
			return inlineValue{}, false
		}
		parts := make([]string, len(value.items))
		joinedBytes := 0
		for index, item := range value.items {
			switch item.kind {
			case inlineValueString:
				parts[index] = item.text
			case inlineValueInteger:
				parts[index] = strconv.FormatInt(item.num, 10)
			default:
				return inlineValue{}, false
			}
			if len(parts[index]) > maxScalarBytes-joinedBytes {
				return inlineValue{}, false
			}
			joinedBytes += len(parts[index])
			if index > 0 {
				if len(separator.text) > maxScalarBytes-joinedBytes {
					return inlineValue{}, false
				}
				joinedBytes += len(separator.text)
			}
		}
		value = inlineValue{kind: inlineValueString, text: strings.Join(parts, separator.text)}
	}
	return value, true
}

func (parser *inlineParser) addOperation(operation OperationKind) {
	for _, existing := range parser.ir.operations {
		if existing == operation {
			return
		}
	}
	parser.ir.operations = append(parser.ir.operations, operation)
}

func (parser *inlineParser) symbolDefined(name string) bool {
	_, exists := parser.symbols[name]
	return exists
}

func (parser *inlineParser) defineSymbol(name string, value inlineValue) bool {
	if name == "" || parser.symbolDefined(name) || len(parser.symbols) >= maxInlineInterpreterSymbols {
		return false
	}
	parser.symbols[name] = value
	return true
}

func (parser *inlineParser) atEOF() bool {
	return parser.peek().kind == inlineTokenEOF
}

func (parser *inlineParser) peek() inlineToken {
	return parser.peekN(0)
}

func (parser *inlineParser) peekN(offset int) inlineToken {
	index := parser.position + offset
	if index < 0 || index >= len(parser.tokens) {
		return inlineToken{kind: inlineTokenEOF}
	}
	return parser.tokens[index]
}

func (parser *inlineParser) peekText() string {
	return parser.peek().text
}

func (parser *inlineParser) take() inlineToken {
	token := parser.peek()
	if parser.position < len(parser.tokens) {
		parser.position++
	}
	return token
}

func (parser *inlineParser) consumeIdent(value string) bool {
	if parser.peek().kind != inlineTokenIdent || parser.peek().text != value {
		return false
	}
	parser.position++
	return true
}

func (parser *inlineParser) consumeSymbol(value string) bool {
	if parser.peek().kind != inlineTokenSymbol || parser.peek().text != value {
		return false
	}
	parser.position++
	return true
}
