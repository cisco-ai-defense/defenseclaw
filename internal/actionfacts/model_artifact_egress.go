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
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	modelArtifactRootDigestDomain        = "defenseclaw/actionfacts/model-artifact-egress/root/v1"
	modelArtifactDestinationDigestDomain = "defenseclaw/actionfacts/model-artifact-egress/destination/v1"
	maxModelArtifactPythonBytes          = 32 * 1024
	maxModelArtifactPythonLines          = 256
	maxModelArtifactPythonTokensPerLine  = 192
)

// ModelArtifactResourceClass is the closed resource vocabulary emitted by the
// model-artifact egress proof.
type ModelArtifactResourceClass string

const (
	ModelArtifactResourceCheckpoint ModelArtifactResourceClass = "model_checkpoint"
)

// ModelArtifactEgressScope is the closed traversal scope proven by the source.
type ModelArtifactEgressScope string

const (
	ModelArtifactEgressScopeRecursive ModelArtifactEgressScope = "recursive"
)

// ModelArtifactEgressTransport is the closed network transport proven by the
// source-to-sink join.
type ModelArtifactEgressTransport string

const (
	ModelArtifactEgressTransportHTTPMultipart ModelArtifactEgressTransport = "http_multipart"
)

// ModelArtifactEgressFact is a value-safe projection of one exact recursive
// checkpoint upload. Source paths, destination URLs, Python source, variable
// names, and multipart field names never cross this boundary.
type ModelArtifactEgressFact struct {
	CommandID                 int64
	ResourceClass             ModelArtifactResourceClass
	Scope                     ModelArtifactEgressScope
	Transport                 ModelArtifactEgressTransport
	SourceRootIdentityDigest  string
	DestinationIdentityDigest string
	DestinationScope          NetworkScope
}

// ExactRecursiveModelArtifactMultipartEgress recognizes one direct python or
// python3 -c invocation whose completely consumed, bounded source proves this
// lineage:
//
//   - os.walk recursively enumerates one static checkpoint root;
//   - a path is derived from that walk's directory and filename variables;
//   - that same path is opened for binary reading; and
//   - the resulting handle is passed in the files= mapping of requests.post to
//     one static, non-loopback HTTP(S) endpoint.
//
// The helper intentionally accepts the ordinary ActionFacts opaque-interpreter
// parse state because this parser, rather than the generic shell classifier,
// owns the complete Python grammar. It never evaluates source or performs DNS.
func ExactRecursiveModelArtifactMultipartEgress(
	input Input,
	facts Facts,
) (ModelArtifactEgressFact, bool) {
	command, source, ok := exactModelArtifactPythonInvocation(input, facts)
	if !ok {
		return ModelArtifactEgressFact{}, false
	}
	proof, ok := parseModelArtifactPython(source)
	if !ok {
		return ModelArtifactEgressFact{}, false
	}
	root, ok := exactModelArtifactRoot(proof.root, facts.CWD, facts.ActiveHome)
	if !ok || root == "/" {
		return ModelArtifactEgressFact{}, false
	}
	destination, scope, ok := exactModelArtifactDestination(proof.destination)
	if !ok {
		return ModelArtifactEgressFact{}, false
	}
	return ModelArtifactEgressFact{
		CommandID:                 command.ID,
		ResourceClass:             ModelArtifactResourceCheckpoint,
		Scope:                     ModelArtifactEgressScopeRecursive,
		Transport:                 ModelArtifactEgressTransportHTTPMultipart,
		SourceRootIdentityDigest:  framedPrivateDigest(modelArtifactRootDigestDomain, root),
		DestinationIdentityDigest: framedPrivateDigest(modelArtifactDestinationDigestDomain, destination),
		DestinationScope:          scope,
	}, true
}

// ModelArtifactRootIdentityDigest returns the same opaque root identity used
// by ExactRecursiveModelArtifactMultipartEgress. It is intended for compiling
// trusted protected-root policy values, not for telemetry.
func ModelArtifactRootIdentityDigest(root, cwd, activeHome string) string {
	normalized, ok := exactModelArtifactRoot(root, cwd, activeHome)
	if !ok || normalized == "/" {
		return ""
	}
	return framedPrivateDigest(modelArtifactRootDigestDomain, normalized)
}

func exactModelArtifactRoot(root, cwd, activeHome string) (string, bool) {
	for _, segment := range strings.Split(root, "/") {
		if segment == ".." {
			return "", false
		}
	}
	return exactNormalizedPOSIXPath(root, cwd, activeHome)
}

// ModelArtifactDestinationIdentityDigest returns the same opaque destination
// identity used by ExactRecursiveModelArtifactMultipartEgress. Dynamic,
// malformed, non-HTTP(S), and loopback destinations return an empty value.
func ModelArtifactDestinationIdentityDigest(destination string) string {
	normalized, _, ok := exactModelArtifactDestination(destination)
	if !ok {
		return ""
	}
	return framedPrivateDigest(modelArtifactDestinationDigestDomain, normalized)
}

func exactModelArtifactPythonInvocation(
	input Input,
	facts Facts,
) (CommandFact, string, bool) {
	if strings.ToLower(strings.TrimSpace(input.Tool)) != facts.Tool ||
		facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) != 1 {
		return CommandFact{}, "", false
	}
	derived := Analyze(input)
	if derived.Tool != facts.Tool || derived.CWD != facts.CWD ||
		derived.ActiveHome != facts.ActiveHome || derived.Parse.Status != facts.Parse.Status ||
		derived.Parse.Dialect != facts.Parse.Dialect || len(derived.Parse.Issues) != len(facts.Parse.Issues) ||
		len(derived.Commands) != 1 || !equalModelArtifactCommand(derived.Commands[0], facts.Commands[0]) {
		return CommandFact{}, "", false
	}
	for index := range derived.Parse.Issues {
		if derived.Parse.Issues[index] != facts.Parse.Issues[index] {
			return CommandFact{}, "", false
		}
	}
	if !modelArtifactPythonParseEligible(facts.Parse) {
		return CommandFact{}, "", false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || command.Kind != CommandKindProcess ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Wrappers) != 0 || len(command.Argv) != 3 ||
		(command.Program != "python" && command.Program != "python3") ||
		command.Argv[0] != command.Executable || command.Argv[1] != "-c" ||
		!exactModelArtifactRedirects(command.Redirects) {
		return CommandFact{}, "", false
	}
	if len(command.Argv[2]) == 0 || len(command.Argv[2]) > maxModelArtifactPythonBytes ||
		!utf8.ValidString(command.Argv[2]) || strings.IndexByte(command.Argv[2], 0) >= 0 {
		return CommandFact{}, "", false
	}
	return command, command.Argv[2], true
}

func modelArtifactPythonParseEligible(parse ParseResult) bool {
	if parse.Status != StatusPartial {
		return false
	}
	return len(parse.Issues) == 1 && parse.Issues[0] == IssueOpaqueArtifact ||
		len(parse.Issues) == 2 && parse.Issues[0] == IssueUnsupportedConstruct &&
			parse.Issues[1] == IssueOpaqueArtifact
}

func equalModelArtifactCommand(left, right CommandFact) bool {
	if left.ID != right.ID || left.ParentCommandID != right.ParentCommandID ||
		left.PipelineID != right.PipelineID || left.ControlFlowUncertain != right.ControlFlowUncertain ||
		left.Kind != right.Kind || left.Dialect != right.Dialect || left.Effect != right.Effect ||
		left.Executable != right.Executable || left.Program != right.Program ||
		left.ArgvComplete != right.ArgvComplete || len(left.Argv) != len(right.Argv) ||
		len(left.Wrappers) != len(right.Wrappers) || len(left.Redirects) != len(right.Redirects) {
		return false
	}
	for index := range left.Argv {
		if left.Argv[index] != right.Argv[index] {
			return false
		}
	}
	for index := range left.Redirects {
		if left.Redirects[index] != right.Redirects[index] {
			return false
		}
	}
	return true
}

func exactModelArtifactRedirects(redirects []RedirectFact) bool {
	if len(redirects) == 0 {
		return true
	}
	// A stderr-to-stdout merge does not wrap, condition, or alter the program.
	return len(redirects) == 1 && redirects[0].FD == 2 &&
		redirects[0].Access == PathAccessWrite &&
		(redirects[0].Target == "" || redirects[0].Target == "&1") &&
		!redirects[0].Expands
}

func exactModelArtifactDestination(raw string) (string, NetworkScope, bool) {
	if raw == "" || len(raw) > maxScalarBytes || strings.TrimSpace(raw) != raw ||
		validateScalar(raw, maxScalarBytes) != "" || strings.ContainsRune(raw, '#') {
		return "", "", false
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", "", false
	}
	normalizedHost, scope, kind, _ := deriveNetworkTarget(host)
	if normalizedHost == "" || kind != NetworkTargetSingleHost ||
		scope == NetworkScopeLoopback {
		return "", "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), scope, true
}

type modelArtifactPythonProof struct {
	root        string
	destination string
}

type modelPythonTokenKind uint8

const (
	modelPythonName modelPythonTokenKind = iota + 1
	modelPythonString
	modelPythonNumber
	modelPythonPunct
)

type modelPythonToken struct {
	kind   modelPythonTokenKind
	value  string
	prefix byte
}

type modelPythonLineKind uint8

const (
	modelLineImport modelPythonLineKind = iota + 1
	modelLineFunction
	modelLineStaticAssignment
	modelLineWalk
	modelLineFileLoop
	modelLinePathJoin
	modelLineRelativePath
	modelLineOpen
	modelLinePost
	modelLinePrint
	modelLineCounter
	modelLineStatusIf
	modelLineElse
	modelLineRaiseForStatus
	modelLineFunctionCall
)

type modelPythonLine struct {
	indent int
	parent int
	kind   modelPythonLineKind
	tokens []modelPythonToken
	block  bool
}

type modelPythonFunction struct {
	name         string
	parameter    string
	defaultValue string
	line         int
}

type modelPythonStatic struct {
	value   string
	line    int
	parent  int
	literal bool
}

func parseModelArtifactPython(source string) (modelArtifactPythonProof, bool) {
	lines, ok := lexModelArtifactPython(source)
	if !ok {
		return modelArtifactPythonProof{}, false
	}
	statics := make(map[string]modelPythonStatic)
	functions := make(map[string]modelPythonFunction)
	assignments := make(map[string]int)
	importsOS, importsRequests := false, false

	for index := range lines {
		kind, block, assigned, ok := classifyModelPythonLine(lines[index].tokens)
		if !ok {
			return modelArtifactPythonProof{}, false
		}
		lines[index].kind, lines[index].block = kind, block
		if assigned != "" {
			assignments[assigned]++
			if assignments[assigned] != 1 {
				return modelArtifactPythonProof{}, false
			}
		}
		switch kind {
		case modelLineImport:
			for _, token := range lines[index].tokens[1:] {
				importsOS = importsOS || token.value == "os"
				importsRequests = importsRequests || token.value == "requests"
			}
		case modelLineStaticAssignment:
			statics[assigned] = modelPythonStatic{
				value: lines[index].tokens[2].value, line: index, parent: lines[index].parent,
				literal: exactModelPythonLiteral(lines[index].tokens[2]),
			}
		case modelLineFunction:
			function, parsed := parseModelPythonFunction(lines[index].tokens, index)
			if !parsed || lines[index].parent != -1 || functions[function.name].name != "" {
				return modelArtifactPythonProof{}, false
			}
			functions[function.name] = function
		}
	}
	if !importsOS || !importsRequests {
		return modelArtifactPythonProof{}, false
	}
	for index := range lines {
		line := lines[index]
		if line.kind != modelLineFunctionCall {
			continue
		}
		function, ok := functions[line.tokens[0].value]
		if !ok || function.line >= index {
			return modelArtifactPythonProof{}, false
		}
	}

	var proof modelArtifactPythonProof
	proofCount := 0
	for walkIndex := range lines {
		walk := lines[walkIndex]
		if walk.kind != modelLineWalk {
			continue
		}
		candidate, ok := proveModelArtifactWalk(lines, walkIndex, statics, functions)
		if !ok {
			continue
		}
		proof, proofCount = candidate, proofCount+1
	}
	return proof, proofCount == 1
}

func lexModelArtifactPython(source string) ([]modelPythonLine, bool) {
	if strings.ContainsRune(source, '\r') {
		source = strings.ReplaceAll(source, "\r\n", "\n")
		if strings.ContainsRune(source, '\r') {
			return nil, false
		}
	}
	rawLines := strings.Split(source, "\n")
	if len(rawLines) > maxModelArtifactPythonLines {
		return nil, false
	}
	lines := make([]modelPythonLine, 0, len(rawLines))
	stack := make([]int, 0, 8)
	for _, raw := range rawLines {
		if len(raw) > maxScalarBytes || strings.ContainsRune(raw, '\t') {
			return nil, false
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		tokens, ok := lexModelPythonLine(raw[indent:])
		if !ok {
			return nil, false
		}
		if len(tokens) == 0 {
			continue
		}
		for len(stack) > 0 && indent <= lines[stack[len(stack)-1]].indent {
			stack = stack[:len(stack)-1]
		}
		parent := -1
		if indent > 0 {
			if len(stack) == 0 {
				return nil, false
			}
			parent = stack[len(stack)-1]
		} else if len(stack) != 0 {
			return nil, false
		}
		lines = append(lines, modelPythonLine{indent: indent, parent: parent, tokens: tokens})
		index := len(lines) - 1
		if tokens[len(tokens)-1].value == ":" {
			stack = append(stack, index)
		}
	}
	return lines, len(lines) != 0
}

func lexModelPythonLine(line string) ([]modelPythonToken, bool) {
	tokens := make([]modelPythonToken, 0, 24)
	for index := 0; index < len(line); {
		if len(tokens) >= maxModelArtifactPythonTokensPerLine {
			return nil, false
		}
		char := line[index]
		switch {
		case char == ' ':
			index++
		case char == '#':
			return tokens, true
		case isModelPythonNameStart(char):
			if (char == 'f' || char == 'F') && index+1 < len(line) &&
				(line[index+1] == '\'' || line[index+1] == '"') {
				token, next, ok := lexModelPythonString(line, index+1, char)
				if !ok {
					return nil, false
				}
				tokens, index = append(tokens, token), next
				continue
			}
			start := index
			for index++; index < len(line) && isModelPythonNameContinue(line[index]); index++ {
			}
			tokens = append(tokens, modelPythonToken{kind: modelPythonName, value: line[start:index]})
		case char >= '0' && char <= '9':
			start := index
			for index++; index < len(line) && line[index] >= '0' && line[index] <= '9'; index++ {
			}
			tokens = append(tokens, modelPythonToken{kind: modelPythonNumber, value: line[start:index]})
		case char == '\'' || char == '"':
			token, next, ok := lexModelPythonString(line, index, 0)
			if !ok {
				return nil, false
			}
			tokens, index = append(tokens, token), next
		default:
			operator := ""
			if index+1 < len(line) {
				pair := line[index : index+2]
				if pair == "+=" || pair == "==" || pair == ">=" || pair == "<=" || pair == "!=" {
					operator = pair
				}
			}
			if operator != "" {
				tokens = append(tokens, modelPythonToken{kind: modelPythonPunct, value: operator})
				index += 2
				continue
			}
			if !strings.ContainsRune("()[]{},.:=+-*/", rune(char)) {
				return nil, false
			}
			tokens = append(tokens, modelPythonToken{kind: modelPythonPunct, value: string(char)})
			index++
		}
	}
	return tokens, true
}

func lexModelPythonString(line string, quoteIndex int, prefix byte) (modelPythonToken, int, bool) {
	quote := line[quoteIndex]
	if quoteIndex+2 < len(line) && line[quoteIndex+1] == quote && line[quoteIndex+2] == quote {
		return modelPythonToken{}, 0, false
	}
	start := quoteIndex + 1
	for index := start; index < len(line); index++ {
		if line[index] == '\\' {
			index++
			if index >= len(line) {
				return modelPythonToken{}, 0, false
			}
			continue
		}
		if line[index] == quote {
			return modelPythonToken{
				kind: modelPythonString, value: line[start:index], prefix: prefix,
			}, index + 1, true
		}
	}
	return modelPythonToken{}, 0, false
}

func isModelPythonNameStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isModelPythonNameContinue(value byte) bool {
	return isModelPythonNameStart(value) || value >= '0' && value <= '9'
}

func classifyModelPythonLine(
	tokens []modelPythonToken,
) (modelPythonLineKind, bool, string, bool) {
	for index, token := range tokens {
		if token.kind == modelPythonName && modelPythonForbiddenName(token.value) {
			return 0, false, "", false
		}
		if token.value == ";" || index > 0 && tokens[index-1].value == "\\" {
			return 0, false, "", false
		}
	}
	if exactModelPythonImport(tokens) {
		return modelLineImport, false, "", true
	}
	if _, ok := parseModelPythonFunction(tokens, 0); ok {
		return modelLineFunction, true, "", true
	}
	if name, _, ok := modelPythonStaticAssignment(tokens); ok {
		return modelLineStaticAssignment, false, name, true
	}
	if _, ok := modelPythonWalk(tokens); ok {
		return modelLineWalk, true, "", true
	}
	if modelPythonFileLoop(tokens) {
		return modelLineFileLoop, true, "", true
	}
	if name, ok := modelPythonPathJoin(tokens); ok {
		return modelLinePathJoin, false, name, true
	}
	if name, ok := modelPythonRelativePath(tokens); ok {
		return modelLineRelativePath, false, name, true
	}
	if modelPythonOpen(tokens) {
		return modelLineOpen, true, "", true
	}
	if name, ok := modelPythonPost(tokens); ok {
		return modelLinePost, false, name, true
	}
	if modelPythonSimpleCall(tokens, "print") {
		return modelLinePrint, false, "", true
	}
	if len(tokens) == 3 && tokens[0].kind == modelPythonName &&
		tokens[1].value == "+=" && tokens[2].kind == modelPythonNumber {
		return modelLineCounter, false, "", true
	}
	if modelPythonStatusIf(tokens) {
		return modelLineStatusIf, true, "", true
	}
	if modelPythonValues(tokens, "else", ":") {
		return modelLineElse, true, "", true
	}
	if modelPythonRaiseForStatus(tokens) {
		return modelLineRaiseForStatus, false, "", true
	}
	if modelPythonFunctionCall(tokens) {
		return modelLineFunctionCall, false, "", true
	}
	return 0, false, "", false
}

func modelPythonForbiddenName(name string) bool {
	switch name {
	case "eval", "exec", "compile", "__import__", "globals", "locals", "getattr", "setattr", "delattr", "subprocess", "system", "popen":
		return true
	default:
		return strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__")
	}
}

func exactModelPythonImport(tokens []modelPythonToken) bool {
	if len(tokens) < 2 || tokens[0].value != "import" {
		return false
	}
	wantName := true
	for _, token := range tokens[1:] {
		if wantName {
			if token.kind != modelPythonName || (token.value != "os" && token.value != "requests") {
				return false
			}
		} else if token.value != "," {
			return false
		}
		wantName = !wantName
	}
	return !wantName
}

func parseModelPythonFunction(tokens []modelPythonToken, line int) (modelPythonFunction, bool) {
	if len(tokens) != 8 && len(tokens) != 6 || tokens[0].value != "def" ||
		tokens[1].kind != modelPythonName || tokens[2].value != "(" ||
		tokens[3].kind != modelPythonName || tokens[len(tokens)-2].value != ")" ||
		tokens[len(tokens)-1].value != ":" {
		return modelPythonFunction{}, false
	}
	function := modelPythonFunction{name: tokens[1].value, parameter: tokens[3].value, line: line}
	if len(tokens) == 8 {
		if tokens[4].value != "=" || !exactModelPythonLiteral(tokens[5]) {
			return modelPythonFunction{}, false
		}
		function.defaultValue = tokens[5].value
	}
	return function, true
}

func modelPythonStaticAssignment(tokens []modelPythonToken) (string, string, bool) {
	if len(tokens) != 3 || tokens[0].kind != modelPythonName || tokens[1].value != "=" ||
		(tokens[2].kind != modelPythonNumber && !exactModelPythonLiteral(tokens[2])) {
		return "", "", false
	}
	return tokens[0].value, tokens[2].value, true
}

func modelPythonWalk(tokens []modelPythonToken) (string, bool) {
	if len(tokens) != 14 || tokens[0].value != "for" || tokens[1].kind != modelPythonName ||
		tokens[2].value != "," || tokens[3].kind != modelPythonName || tokens[4].value != "," ||
		tokens[5].kind != modelPythonName || tokens[6].value != "in" ||
		!modelPythonValues(tokens[7:11], "os", ".", "walk", "(") ||
		tokens[12].value != ")" || tokens[13].value != ":" {
		return "", false
	}
	// The slice length above deliberately leaves no room for hidden arguments.
	return tokens[11].value, tokens[11].kind == modelPythonName || exactModelPythonLiteral(tokens[11])
}

func modelPythonFileLoop(tokens []modelPythonToken) bool {
	if len(tokens) == 5 {
		return tokens[0].value == "for" && tokens[1].kind == modelPythonName &&
			tokens[2].value == "in" && tokens[3].kind == modelPythonName && tokens[4].value == ":"
	}
	return len(tokens) == 8 && tokens[0].value == "for" && tokens[1].kind == modelPythonName &&
		tokens[2].value == "in" && tokens[3].value == "sorted" && tokens[4].value == "(" &&
		tokens[5].kind == modelPythonName && tokens[6].value == ")" && tokens[7].value == ":"
}

func modelPythonPathJoin(tokens []modelPythonToken) (string, bool) {
	if len(tokens) != 12 || tokens[0].kind != modelPythonName || tokens[1].value != "=" ||
		!modelPythonValues(tokens[2:8], "os", ".", "path", ".", "join", "(") ||
		tokens[8].kind != modelPythonName || tokens[9].value != "," ||
		tokens[10].kind != modelPythonName || tokens[11].value != ")" {
		return "", false
	}
	return tokens[0].value, true
}

func modelPythonRelativePath(tokens []modelPythonToken) (string, bool) {
	if len(tokens) != 12 || tokens[0].kind != modelPythonName || tokens[1].value != "=" ||
		!modelPythonValues(tokens[2:8], "os", ".", "path", ".", "relpath", "(") ||
		tokens[8].kind != modelPythonName || tokens[9].value != "," ||
		(tokens[10].kind != modelPythonName && !exactModelPythonLiteral(tokens[10])) ||
		tokens[11].value != ")" {
		return "", false
	}
	return tokens[0].value, true
}

func modelPythonOpen(tokens []modelPythonToken) bool {
	return len(tokens) == 10 && modelPythonValues(tokens[:2], "with", "open") &&
		tokens[2].value == "(" && tokens[3].kind == modelPythonName && tokens[4].value == "," &&
		exactModelPythonLiteral(tokens[5]) && tokens[5].value == "rb" && tokens[6].value == ")" &&
		tokens[7].value == "as" && tokens[8].kind == modelPythonName && tokens[9].value == ":"
}

func modelPythonPost(tokens []modelPythonToken) (string, bool) {
	start, assigned := 0, ""
	if len(tokens) >= 3 && tokens[0].kind == modelPythonName && tokens[1].value == "=" {
		assigned, start = tokens[0].value, 2
	}
	remaining := tokens[start:]
	if len(remaining) != 18 && len(remaining) != 22 ||
		!modelPythonValues(remaining[:4], "requests", ".", "post", "(") ||
		(remaining[4].kind != modelPythonName && !exactModelPythonLiteral(remaining[4])) ||
		!modelPythonValues(remaining[5:9], ",", "files", "=", "{") ||
		!exactModelPythonLiteral(remaining[9]) || remaining[10].value != ":" ||
		remaining[11].value != "(" ||
		(remaining[12].kind != modelPythonName && !exactModelPythonLiteral(remaining[12])) ||
		remaining[13].value != "," || remaining[14].kind != modelPythonName ||
		remaining[15].value != ")" {
		return "", false
	}
	if len(remaining) == 18 && !modelPythonValues(remaining[16:], "}", ")") {
		return "", false
	}
	if len(remaining) == 22 &&
		(!modelPythonValues(remaining[16:20], "}", ",", "timeout", "=") ||
			remaining[20].kind != modelPythonNumber) {
		return "", false
	}
	if len(remaining) == 22 && remaining[21].value != ")" {
		return "", false
	}
	return assigned, true
}

func modelPythonSimpleCall(tokens []modelPythonToken, name string) bool {
	if len(tokens) < 3 || tokens[0].value != name || tokens[1].value != "(" ||
		tokens[len(tokens)-1].value != ")" {
		return false
	}
	for _, token := range tokens[2 : len(tokens)-1] {
		if token.value == "(" || token.value == ")" || token.value == "[" ||
			token.value == "{" || token.value == "=" {
			return false
		}
	}
	return true
}

func modelPythonStatusIf(tokens []modelPythonToken) bool {
	return len(tokens) == 7 && tokens[0].value == "if" && tokens[1].kind == modelPythonName &&
		modelPythonValues(tokens[2:5], ".", "status_code", "==") &&
		tokens[5].kind == modelPythonNumber && tokens[6].value == ":"
}

func modelPythonRaiseForStatus(tokens []modelPythonToken) bool {
	return len(tokens) == 5 && tokens[0].kind == modelPythonName &&
		modelPythonValues(tokens[1:], ".", "raise_for_status", "(", ")")
}

func modelPythonFunctionCall(tokens []modelPythonToken) bool {
	return (len(tokens) == 3 || len(tokens) == 4) && tokens[0].kind == modelPythonName &&
		tokens[1].value == "(" && tokens[len(tokens)-1].value == ")" &&
		(len(tokens) == 3 || exactModelPythonLiteral(tokens[2]))
}

func exactModelPythonLiteral(token modelPythonToken) bool {
	return token.kind == modelPythonString && token.prefix == 0 && token.value != "" &&
		utf8.ValidString(token.value) && !strings.ContainsRune(token.value, '\\')
}

func modelPythonValues(tokens []modelPythonToken, values ...string) bool {
	if len(tokens) != len(values) {
		return false
	}
	for index := range tokens {
		if values[index] != "" && tokens[index].value != values[index] {
			return false
		}
	}
	return true
}

func proveModelArtifactWalk(
	lines []modelPythonLine,
	walkIndex int,
	statics map[string]modelPythonStatic,
	functions map[string]modelPythonFunction,
) (modelArtifactPythonProof, bool) {
	walk := lines[walkIndex]
	if !modelPythonImportsBefore(lines, walkIndex) {
		return modelArtifactPythonProof{}, false
	}
	if walk.parent >= 0 && lines[walk.parent].kind != modelLineFunction {
		return modelArtifactPythonProof{}, false
	}
	rootToken := walk.tokens[11]
	root, ok := resolveModelPythonRoot(lines, walkIndex, rootToken, statics, functions)
	if !ok {
		return modelArtifactPythonProof{}, false
	}
	directoryName, filesName := walk.tokens[1].value, walk.tokens[5].value
	for fileIndex := range lines {
		fileLine := lines[fileIndex]
		if fileLine.kind != modelLineFileLoop || fileLine.parent != walkIndex {
			continue
		}
		fileName := fileLine.tokens[1].value
		iterName := fileLine.tokens[3].value
		if fileLine.tokens[3].value == "sorted" {
			iterName = fileLine.tokens[5].value
		}
		if iterName != filesName {
			continue
		}
		for pathIndex := range lines {
			pathLine := lines[pathIndex]
			if pathIndex <= fileIndex || pathLine.kind != modelLinePathJoin || pathLine.parent != fileIndex ||
				pathLine.tokens[8].value != directoryName || pathLine.tokens[10].value != fileName {
				continue
			}
			pathName := pathLine.tokens[0].value
			for openIndex := range lines {
				openLine := lines[openIndex]
				if openIndex <= pathIndex || openLine.kind != modelLineOpen || openLine.parent != fileIndex ||
					openLine.tokens[3].value != pathName {
					continue
				}
				handle := openLine.tokens[8].value
				for postIndex := range lines {
					postLine := lines[postIndex]
					if postIndex <= openIndex || postLine.kind != modelLinePost || postLine.parent != openIndex {
						continue
					}
					remaining := postLine.tokens
					if remaining[1].value == "=" {
						remaining = remaining[2:]
					}
					if remaining[14].value != handle ||
						!modelPythonMultipartNameMatches(
							lines, fileIndex, pathIndex, postIndex, pathName, rootToken, remaining[12].value,
						) {
						continue
					}
					destination, ok := resolveModelPythonStatic(
						lines, remaining[4], postIndex, postLine.parent, statics,
					)
					if !ok {
						continue
					}
					return modelArtifactPythonProof{root: root, destination: destination}, true
				}
			}
		}
	}
	return modelArtifactPythonProof{}, false
}

func modelPythonImportsBefore(lines []modelPythonLine, before int) bool {
	osImported, requestsImported := false, false
	for index := 0; index < before; index++ {
		if lines[index].kind != modelLineImport {
			continue
		}
		for _, token := range lines[index].tokens[1:] {
			osImported = osImported || token.value == "os"
			requestsImported = requestsImported || token.value == "requests"
		}
	}
	return osImported && requestsImported
}

func modelPythonMultipartNameMatches(
	lines []modelPythonLine,
	fileIndex int,
	pathIndex int,
	postIndex int,
	pathName string,
	rootToken modelPythonToken,
	value string,
) bool {
	if value == pathName {
		return true
	}
	for index, line := range lines {
		if line.kind != modelLineRelativePath || line.parent != fileIndex || line.tokens[0].value != value ||
			line.tokens[8].value != pathName || index <= pathIndex || index >= postIndex {
			continue
		}
		return line.tokens[10].kind == rootToken.kind && line.tokens[10].value == rootToken.value
	}
	return false
}

func resolveModelPythonRoot(
	lines []modelPythonLine,
	walkIndex int,
	token modelPythonToken,
	statics map[string]modelPythonStatic,
	functions map[string]modelPythonFunction,
) (string, bool) {
	if exactModelPythonLiteral(token) {
		return token.value, true
	}
	if value, ok := resolveModelPythonStatic(lines, token, walkIndex, lines[walkIndex].parent, statics); ok {
		return value, true
	}
	functionLine := modelPythonAncestor(lines, walkIndex, modelLineFunction)
	if functionLine < 0 {
		return "", false
	}
	function, ok := functions[lines[functionLine].tokens[1].value]
	if !ok || token.value != function.parameter {
		return "", false
	}
	callValue, callCount := "", 0
	for lineIndex, line := range lines {
		if line.parent != -1 || line.kind != modelLineFunctionCall ||
			line.tokens[0].value != function.name {
			continue
		}
		callCount++
		if lineIndex <= function.line {
			return "", false
		}
		if len(line.tokens) == 4 {
			callValue = line.tokens[2].value
		} else {
			callValue = function.defaultValue
		}
	}
	return callValue, callCount == 1 && callValue != ""
}

func resolveModelPythonStatic(
	lines []modelPythonLine,
	token modelPythonToken,
	before int,
	parent int,
	statics map[string]modelPythonStatic,
) (string, bool) {
	if exactModelPythonLiteral(token) {
		return token.value, true
	}
	static, ok := statics[token.value]
	return static.value, ok && static.literal && static.line < before &&
		modelPythonParentContains(lines, parent, static.parent)
}

func modelPythonParentContains(lines []modelPythonLine, descendant, ancestor int) bool {
	if ancestor == -1 {
		return true
	}
	for current := descendant; current >= 0; current = lines[current].parent {
		if current == ancestor {
			return true
		}
	}
	return false
}

func modelPythonAncestor(lines []modelPythonLine, index int, kind modelPythonLineKind) int {
	for parent := lines[index].parent; parent >= 0; parent = lines[parent].parent {
		if lines[parent].kind == kind {
			return parent
		}
	}
	return -1
}
