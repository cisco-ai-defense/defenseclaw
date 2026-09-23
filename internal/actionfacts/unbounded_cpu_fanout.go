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
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// MinimumExactPOSIXUnboundedCPUFanout is the smallest statically proven
// worker count emitted by ExtractExactPOSIXUnboundedCPUFanout. Keeping this
// threshold conservative prevents ordinary small local concurrency from
// becoming a resource-exhaustion fact.
const MinimumExactPOSIXUnboundedCPUFanout uint64 = 64

// UnboundedCPUFanoutFact is a value-safe proof that one complete POSIX action
// unconditionally launches FanoutCount background workers and that every
// worker executes an infinite busy loop. The proof retains no command text,
// loop variable, arguments, paths, or other source-controlled values.
type UnboundedCPUFanoutFact struct {
	FanoutCount uint64
}

// ExtractExactPOSIXUnboundedCPUFanout recognizes one deliberately small POSIX
// grammar:
//
//	for worker in $(seq 1 N); do
//	  (while true; do :; done) &
//	done
//
// The condition and busy-loop body may independently use either the POSIX
// no-op builtin ':' or the constant-success utility 'true'. N must be a
// canonical decimal literal at or above MinimumExactPOSIXUnboundedCPUFanout.
//
// Every other shape fails closed. In particular, the extractor rejects shell
// expansions other than the exact seq substitution, finite or conditional
// work, foreground workers, wrappers, redirections, pipelines, sleep/wait,
// timeout and resource-limit launchers, additional statements, Bash-only
// brace expansion, and malformed or unsupported syntax. Enforcement is
// intentionally left to callers in a later change.
func ExtractExactPOSIXUnboundedCPUFanout(source string) (UnboundedCPUFanoutFact, bool) {
	if len(source) == 0 || len(source) > maxCommandBytes ||
		!utf8.ValidString(source) || strings.TrimSpace(source) == "" {
		return UnboundedCPUFanoutFact{}, false
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX))
	file, err := parser.Parse(strings.NewReader(source), "")
	if err != nil {
		return UnboundedCPUFanoutFact{}, false
	}
	bounds := newParseOutput(DialectPOSIX, 1)
	if !checkPOSIXBounds(file, &bounds) {
		return UnboundedCPUFanoutFact{}, false
	}
	if fact, ok := exactPOSIXPythonCPUFanoutEnvelope(file.Stmts); ok {
		return fact, true
	}
	if len(file.Stmts) != 1 {
		return UnboundedCPUFanoutFact{}, false
	}

	outer := file.Stmts[0]
	if !exactPlainForegroundPOSIXStatement(outer) {
		return UnboundedCPUFanoutFact{}, false
	}
	loop, ok := outer.Cmd.(*syntax.ForClause)
	if !ok || loop.Select || loop.Braces || len(loop.Do) != 1 {
		return UnboundedCPUFanoutFact{}, false
	}

	count, ok := exactStaticPOSIXFanoutCount(loop.Loop)
	if !ok || count < MinimumExactPOSIXUnboundedCPUFanout {
		return UnboundedCPUFanoutFact{}, false
	}
	if !exactBackgroundPOSIXBusyLoop(loop.Do[0]) {
		return UnboundedCPUFanoutFact{}, false
	}
	return UnboundedCPUFanoutFact{FanoutCount: count}, true
}

type exactPythonCPUProof struct {
	helperName string
}

// exactPOSIXPythonCPUFanoutEnvelope recognizes three closed envelopes observed
// around the same literal Python busy-loop worker:
//
//	for ...; do python3 -c <literal> & done; echo <literal>
//	pkill ...; sleep 1; for ...; do nice -n -20 python3 -c <literal> & done; echo <literal>
//	for ...; do nice -n -20 python3 -c <literal> & done; echo <literal>; ps ... | grep ... | grep ... | head ...
//
// Prefixes and suffixes are admitted only when their complete syntax matches
// the cleanup or read-only observation grammar below. This prevents an
// otherwise valid worker from being extracted through a conditional launch,
// resource limit, post-launch kill/wait, or unknown wrapper.
func exactPOSIXPythonCPUFanoutEnvelope(statements []*syntax.Stmt) (UnboundedCPUFanoutFact, bool) {
	switch len(statements) {
	case 2:
		count, _, wrapped, ok := exactPOSIXPythonCPUFanoutCore(statements[0])
		if !ok || wrapped || !exactPOSIXLiteralEcho(statements[1]) {
			return UnboundedCPUFanoutFact{}, false
		}
		return UnboundedCPUFanoutFact{FanoutCount: count}, true
	case 3:
		count, _, wrapped, ok := exactPOSIXPythonCPUFanoutCore(statements[0])
		if !ok || !wrapped || !exactPOSIXLiteralEcho(statements[1]) ||
			!exactPOSIXPythonFanoutObservation(statements[2]) {
			return UnboundedCPUFanoutFact{}, false
		}
		return UnboundedCPUFanoutFact{FanoutCount: count}, true
	case 4:
		count, proof, wrapped, ok := exactPOSIXPythonCPUFanoutCore(statements[2])
		if !ok || !wrapped || !exactPOSIXPythonFanoutCleanup(statements[0], proof.helperName) ||
			!exactPOSIXOneSecondSleep(statements[1]) || !exactPOSIXLiteralEcho(statements[3]) {
			return UnboundedCPUFanoutFact{}, false
		}
		return UnboundedCPUFanoutFact{FanoutCount: count}, true
	default:
		return UnboundedCPUFanoutFact{}, false
	}
}

func exactPOSIXPythonCPUFanoutCore(statement *syntax.Stmt) (uint64, exactPythonCPUProof, bool, bool) {
	if !exactPlainForegroundPOSIXStatement(statement) {
		return 0, exactPythonCPUProof{}, false, false
	}
	loop, ok := statement.Cmd.(*syntax.ForClause)
	if !ok || loop.Select || loop.Braces || len(loop.Do) != 1 {
		return 0, exactPythonCPUProof{}, false, false
	}
	count, ok := exactStaticPOSIXFanoutCount(loop.Loop)
	if !ok || count < MinimumExactPOSIXUnboundedCPUFanout {
		return 0, exactPythonCPUProof{}, false, false
	}
	worker := loop.Do[0]
	if worker == nil || !worker.Background || worker.Negated || worker.Coprocess ||
		worker.Disown || len(worker.Redirs) != 0 {
		return 0, exactPythonCPUProof{}, false, false
	}
	call, ok := worker.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return 0, exactPythonCPUProof{}, false, false
	}
	argv := call.Args
	wrapped := false
	if len(argv) == 6 && exactStaticPOSIXWord(argv[0]) == "nice" &&
		exactStaticPOSIXWord(argv[1]) == "-n" && exactStaticPOSIXWord(argv[2]) == "-20" {
		wrapped, argv = true, argv[3:]
	}
	if len(argv) != 3 || exactStaticPOSIXWord(argv[0]) != "python3" ||
		exactStaticPOSIXWord(argv[1]) != "-c" {
		return 0, exactPythonCPUProof{}, false, false
	}
	source, ok := exactQuotedPOSIXWord(argv[2])
	if !ok {
		return 0, exactPythonCPUProof{}, false, false
	}
	proof, ok := parseExactPythonCPUBusyLoop(source)
	if !ok {
		return 0, exactPythonCPUProof{}, false, false
	}
	return count, proof, wrapped, true
}

func exactQuotedPOSIXWord(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	value, quote, expands := projectPOSIXWordPart(word.Parts[0])
	if expands || value == "" || quote != QuoteSingle && quote != QuoteDouble || !utf8.ValidString(value) {
		return "", false
	}
	return value, true
}

type exactPythonCPULine struct {
	indent int
	tokens []string
}

// parseExactPythonCPUBusyLoop parses a deliberately tiny Python grammar. It is
// not a heuristic scan: every nonblank byte must belong to the grammar and all
// identifiers must join consistently. The admitted helper performs a finite
// pure primality calculation, while the top-level constant-true loop invokes
// that helper and monotonically increments its positive integer input. No I/O,
// pacing, dynamic code, exception handling, or exit edge is representable.
func parseExactPythonCPUBusyLoop(source string) (exactPythonCPUProof, bool) {
	lines, ok := lexExactPythonCPULines(source)
	if !ok || (len(lines) != 12 && len(lines) != 13) {
		return exactPythonCPUProof{}, false
	}
	index := 0
	if len(lines) == 13 {
		if !exactPythonCPULineIs(lines[index], 0, "import", "sys") {
			return exactPythonCPUProof{}, false
		}
		index++
	}
	if !exactPythonCPULineIs(lines[index], 0, "import", "math") {
		return exactPythonCPUProof{}, false
	}
	index++

	function := lines[index]
	if function.indent != 0 || len(function.tokens) != 6 || function.tokens[0] != "def" ||
		!exactPythonCPUIdentifier(function.tokens[1]) || function.tokens[2] != "(" ||
		!exactPythonCPUIdentifier(function.tokens[3]) || function.tokens[4] != ")" ||
		function.tokens[5] != ":" {
		return exactPythonCPUProof{}, false
	}
	helperName, parameter := function.tokens[1], function.tokens[3]
	index++
	if !exactPythonCPULineIs(lines[index], 4, "if", parameter, "<", "2", ":") ||
		!exactPythonCPULineIs(lines[index+1], 8, "return", "False") {
		return exactPythonCPUProof{}, false
	}
	index += 2

	iterator := lines[index]
	if iterator.indent != 4 || len(iterator.tokens) != 20 || iterator.tokens[0] != "for" ||
		!exactPythonCPUIdentifier(iterator.tokens[1]) || iterator.tokens[2] != "in" ||
		!exactPythonTokensEqual(iterator.tokens[3:], "range", "(", "2", ",", "int", "(",
			"math", ".", "sqrt", "(", parameter, ")", ")", "+", "1", ")", ":") {
		return exactPythonCPUProof{}, false
	}
	loopVariable := iterator.tokens[1]
	index++
	if !exactPythonCPULineIs(lines[index], 8, "if", parameter, "%", loopVariable, "==", "0", ":") ||
		!exactPythonCPULineIs(lines[index+1], 12, "return", "False") ||
		!exactPythonCPULineIs(lines[index+2], 4, "return", "True") {
		return exactPythonCPUProof{}, false
	}
	index += 3

	assignment := lines[index]
	if assignment.indent != 0 || len(assignment.tokens) != 3 ||
		!exactPythonCPUIdentifier(assignment.tokens[0]) || assignment.tokens[1] != "=" ||
		assignment.tokens[2] != "2" {
		return exactPythonCPUProof{}, false
	}
	counter := assignment.tokens[0]
	if helperName == parameter || helperName == loopVariable || helperName == counter ||
		parameter == loopVariable || parameter == counter || loopVariable == counter {
		return exactPythonCPUProof{}, false
	}
	index++
	if !exactPythonCPULineIs(lines[index], 0, "while", "True", ":") ||
		!exactPythonCPULineIs(lines[index+1], 4, helperName, "(", counter, ")") ||
		!exactPythonCPULineIs(lines[index+2], 4, counter, "+=", "1") || index+3 != len(lines) {
		return exactPythonCPUProof{}, false
	}
	return exactPythonCPUProof{helperName: helperName}, true
}

func lexExactPythonCPULines(source string) ([]exactPythonCPULine, bool) {
	if source == "" || len(source) > maxCommandBytes || strings.ContainsAny(source, "\r\t") {
		return nil, false
	}
	rawLines := strings.Split(source, "\n")
	if len(rawLines) > 32 {
		return nil, false
	}
	lines := make([]exactPythonCPULine, 0, len(rawLines))
	for _, raw := range rawLines {
		if len(raw) > maxScalarBytes {
			return nil, false
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		body := raw[indent:]
		if body == "" {
			continue
		}
		tokens, ok := lexExactPythonCPULine(body)
		if !ok {
			return nil, false
		}
		lines = append(lines, exactPythonCPULine{indent: indent, tokens: tokens})
	}
	return lines, len(lines) != 0
}

func lexExactPythonCPULine(line string) ([]string, bool) {
	tokens := make([]string, 0, 20)
	for index := 0; index < len(line); {
		if len(tokens) >= 24 {
			return nil, false
		}
		switch value := line[index]; {
		case value == ' ':
			index++
		case isModelPythonNameStart(value):
			start := index
			for index++; index < len(line) && isModelPythonNameContinue(line[index]); index++ {
			}
			tokens = append(tokens, line[start:index])
		case value >= '0' && value <= '9':
			start := index
			for index++; index < len(line) && line[index] >= '0' && line[index] <= '9'; index++ {
			}
			tokens = append(tokens, line[start:index])
		case index+1 < len(line) && (line[index:index+2] == "+=" || line[index:index+2] == "=="):
			tokens = append(tokens, line[index:index+2])
			index += 2
		case strings.ContainsRune("().,:+%<=", rune(value)):
			tokens = append(tokens, string(value))
			index++
		default:
			return nil, false
		}
	}
	return tokens, len(tokens) != 0
}

func exactPythonCPUIdentifier(value string) bool {
	if !modelPythonSafeName(value) {
		return false
	}
	switch value {
	case "False", "True", "def", "for", "if", "import", "in", "int", "math", "range",
		"return", "sqrt", "sys", "while", "break", "continue", "raise", "try", "except",
		"await", "yield", "eval", "exec", "compile", "open", "input", "sleep":
		return false
	default:
		return true
	}
}

func exactPythonCPULineIs(line exactPythonCPULine, indent int, tokens ...string) bool {
	return line.indent == indent && exactPythonTokensEqual(line.tokens, tokens...)
}

func exactPythonTokensEqual(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func exactPOSIXLiteralEcho(statement *syntax.Stmt) bool {
	if !exactPlainForegroundPOSIXStatement(statement) {
		return false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 ||
		exactStaticPOSIXWord(call.Args[0]) != "echo" {
		return false
	}
	_, ok = exactQuotedPOSIXWord(call.Args[1])
	return ok
}

func exactPOSIXPythonFanoutCleanup(statement *syntax.Stmt, helperName string) bool {
	if statement == nil || statement.Negated || statement.Background || statement.Coprocess ||
		statement.Disown || len(statement.Redirs) != 1 {
		return false
	}
	redirect := statement.Redirs[0]
	if redirect == nil || redirect.Op != syntax.RdrOut || redirect.N == nil ||
		redirect.N.Value != "2" || exactStaticPOSIXWord(redirect.Word) != "/dev/null" {
		return false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 3 ||
		exactStaticPOSIXWord(call.Args[0]) != "pkill" || exactStaticPOSIXWord(call.Args[1]) != "-f" {
		return false
	}
	pattern, ok := exactQuotedPOSIXWord(call.Args[2])
	return ok && pattern == "python3 -c.*"+helperName
}

func exactPOSIXOneSecondSleep(statement *syntax.Stmt) bool {
	if !exactPlainForegroundPOSIXStatement(statement) {
		return false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	return ok && len(call.Assigns) == 0 && len(call.Args) == 2 &&
		exactStaticPOSIXWord(call.Args[0]) == "sleep" && exactStaticPOSIXWord(call.Args[1]) == "1"
}

func exactPOSIXPythonFanoutObservation(statement *syntax.Stmt) bool {
	commands, ok := flattenExactPOSIXPipeline(statement)
	return ok && len(commands) == 4 &&
		exactPOSIXStaticCall(commands[0], "ps", "-eo", "pid,ni,cmd") &&
		exactPOSIXStaticCall(commands[1], "grep", "python3") &&
		exactPOSIXStaticCall(commands[2], "grep", "-v", "grep") &&
		exactPOSIXStaticCall(commands[3], "head", "-5")
}

func flattenExactPOSIXPipeline(statement *syntax.Stmt) ([]*syntax.CallExpr, bool) {
	if statement == nil || statement.Negated || statement.Background || statement.Coprocess ||
		statement.Disown || len(statement.Redirs) != 0 {
		return nil, false
	}
	if call, ok := statement.Cmd.(*syntax.CallExpr); ok {
		if len(call.Assigns) != 0 {
			return nil, false
		}
		return []*syntax.CallExpr{call}, true
	}
	binary, ok := statement.Cmd.(*syntax.BinaryCmd)
	if !ok || binary.Op.String() != "|" {
		return nil, false
	}
	left, leftOK := flattenExactPOSIXPipeline(binary.X)
	right, rightOK := flattenExactPOSIXPipeline(binary.Y)
	if !leftOK || !rightOK {
		return nil, false
	}
	return append(left, right...), true
}

func exactPOSIXStaticCall(call *syntax.CallExpr, argv ...string) bool {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) != len(argv) {
		return false
	}
	for index := range argv {
		if exactStaticPOSIXWord(call.Args[index]) != argv[index] {
			return false
		}
	}
	return true
}

func exactStaticPOSIXFanoutCount(loop syntax.Loop) (uint64, bool) {
	words, ok := loop.(*syntax.WordIter)
	if !ok || words.Name == nil || words.Name.Value == "" ||
		!words.InPos.IsValid() || len(words.Items) != 1 {
		return 0, false
	}
	item := words.Items[0]
	if item == nil || len(item.Parts) != 1 {
		return 0, false
	}
	substitution, ok := item.Parts[0].(*syntax.CmdSubst)
	if !ok || substitution.Backquotes || substitution.TempFile ||
		substitution.ReplyVar || len(substitution.Stmts) != 1 {
		return 0, false
	}
	statement := substitution.Stmts[0]
	if !exactPlainForegroundPOSIXStatement(statement) {
		return 0, false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 3 ||
		exactStaticPOSIXWord(call.Args[0]) != "seq" ||
		exactStaticPOSIXWord(call.Args[1]) != "1" {
		return 0, false
	}
	upper := exactStaticPOSIXWord(call.Args[2])
	count, err := strconv.ParseUint(upper, 10, 64)
	if err != nil || strconv.FormatUint(count, 10) != upper {
		return 0, false
	}
	return count, true
}

func exactBackgroundPOSIXBusyLoop(statement *syntax.Stmt) bool {
	if statement == nil || !statement.Background || statement.Negated ||
		statement.Coprocess || statement.Disown || len(statement.Redirs) != 0 {
		return false
	}
	subshell, ok := statement.Cmd.(*syntax.Subshell)
	if !ok || len(subshell.Stmts) != 1 {
		return false
	}
	whileStatement := subshell.Stmts[0]
	if !exactPlainForegroundPOSIXStatement(whileStatement) {
		return false
	}
	loop, ok := whileStatement.Cmd.(*syntax.WhileClause)
	if !ok || loop.Until || len(loop.Cond) != 1 || len(loop.Do) != 1 ||
		!exactPOSIXConstantSuccess(loop.Cond[0]) ||
		!exactPOSIXConstantSuccess(loop.Do[0]) {
		return false
	}
	return true
}

func exactPOSIXConstantSuccess(statement *syntax.Stmt) bool {
	if !exactPlainForegroundPOSIXStatement(statement) {
		return false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 1 {
		return false
	}
	program := exactStaticPOSIXWord(call.Args[0])
	return program == ":" || program == "true"
}

func exactPlainForegroundPOSIXStatement(statement *syntax.Stmt) bool {
	return statement != nil && !statement.Negated && !statement.Background &&
		!statement.Coprocess && !statement.Disown && len(statement.Redirs) == 0 &&
		statement.Cmd != nil
}

func exactStaticPOSIXWord(word *syntax.Word) string {
	if word == nil || len(word.Parts) != 1 {
		return ""
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	return literal.Value
}
