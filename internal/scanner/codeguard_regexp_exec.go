// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// CG-EXEC-001 reads exec( as command execution. In JavaScript and
// TypeScript, name.exec( is also RegExp.prototype.exec, the ordinary way to
// match a regular expression and read its groups: it runs no command. A
// Copilot patch that added a log parser calling logLinePattern.exec(line)
// raised a HIGH Unsafe command execution finding (rel-1-0-10:GAP-1152).
//
// A call of exec on a name the file proves is a regular expression is
// matching, so CG-EXEC-001 does not read that call. The proof reads the code
// of the whole file, with comments, string text and regular expression
// bodies masked out:
//   - one statement const name = <initializer> whose whole initializer is a
//     regular expression literal or a RegExp(...) call;
//   - every other occurrence of the name is a member use (name.x or
//     name?.x, not assigned to) or the first argument of a string method
//     that takes a pattern (s.match(name), s.replace(name, ...));
//   - every occurrence lies inside the block that holds the const.
//
// Any other occurrence (a parameter of a function, method or arrow, on one
// line or many; a destructuring; an object key; an import; a rebinding in
// the same line) leaves the name unproven, and so does a file the masking
// cannot read (an unterminated string or comment) or one that can change
// what a name or RegExp.prototype.exec means (with, a RegExp.prototype
// write) (rel-1-0-10:GAP-1185). exec on any other receiver (child_process
// or an alias of it, shelljs, a member such as this.re, a name the file
// does not prove) still fires, and so does every other part of a line the
// rule matched.

// codeGuardExecRuleID is the builtin rule this file narrows.
const codeGuardExecRuleID = "CG-EXEC-001"

// jsLikeExtensions are the file extensions CG-EXEC-001 reads whose exec(
// may be the RegExp method.
var jsLikeExtensions = map[string]bool{".js": true, ".ts": true}

// jsIdentifier is one name of the code.
var jsIdentifier = lazyregexp.New(`[A-Za-z_$][\w$]*`)

// jsExecCall is a call of the exec method on a name: name.exec( or
// name?.exec(.
var jsExecCall = lazyregexp.New(`([A-Za-z_$][\w$]*)\s*(?:\?\.|\.)\s*exec\s*\(`)

// jsConstHead is the start of a statement const name = (export const, and
// a TypeScript RegExp annotation, allowed). The initializer follows.
var jsConstHead = lazyregexp.New(`(?m)(?:^|[;{}])[ \t]*(?:export[ \t]+)?const[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[ \t]*RegExp[ \t]*)?=[ \t]*`)

// jsRegExpCall is the head of a RegExp(...) or new RegExp(...) initializer.
var jsRegExpCall = lazyregexp.New(`^(?:new[ \t]+)?RegExp[ \t]*\(`)

// jsMeaningChange is code that can change what a name or the exec method of
// a regular expression means: a with statement, or any reach into a
// prototype (prototype, __proto__, getPrototypeOf, setPrototypeOf).
var jsMeaningChange = lazyregexp.New(`(?i)\bwith\s*\(|prototype|__proto__`)

// jsPatternMethods are the string methods whose first argument is a
// pattern: a call argument there is a use, not a binding.
var jsPatternMethods = map[string]bool{
	"match": true, "matchAll": true, "replace": true, "replaceAll": true, "search": true, "split": true,
}

// jsRegexAfterWords are the keywords after which a slash starts a regular
// expression literal, not a division.
var jsRegexAfterWords = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "throw": true, "yield": true, "await": true, "instanceof": true,
}

// jsContinuationWords continue an expression on the next line: a const
// whose initializer is followed by one of them is not a whole literal.
var jsContinuationWords = map[string]bool{"in": true, "instanceof": true, "as": true, "satisfies": true}

// jsRegExpReceivers collects the lines of a JavaScript or TypeScript file
// and drops the CG-EXEC-001 findings whose only exec( calls are the RegExp
// method of names the file proves are regular expressions. A nil collector
// (any other file type) keeps every finding.
type jsRegExpReceivers struct {
	source strings.Builder
}

func newJSRegExpReceivers(ext string) *jsRegExpReceivers {
	if !jsLikeExtensions[ext] {
		return nil
	}
	return &jsRegExpReceivers{}
}

// observe reads one line of the file.
func (r *jsRegExpReceivers) observe(line string) {
	if r == nil {
		return
	}
	r.source.WriteString(line)
	r.source.WriteByte('\n')
}

// drop removes each builtin CG-EXEC-001 finding whose line no longer
// matches the rule once the RegExp exec calls of proven names are taken
// out. A custom rule that reuses the ID is kept: it is not this rule.
func (r *jsRegExpReceivers) drop(findings []Finding) []Finding {
	if r == nil {
		return findings
	}
	builtin := false
	for _, finding := range findings {
		builtin = builtin || finding.CodeGuardBuiltinMatch(codeGuardExecRuleID)
	}
	if !builtin {
		return findings
	}
	proven := jsProvenRegExpNames(r.source.String())
	if len(proven) == 0 {
		return findings
	}
	execRule, ok := builtinRuleByID(codeGuardExecRuleID)
	if !ok {
		return findings
	}
	kept := findings[:0]
	for _, finding := range findings {
		if finding.CodeGuardBuiltinMatch(codeGuardExecRuleID) &&
			!execRule.matches(withoutRegExpExec(finding.Description, proven)) {
			continue
		}
		kept = append(kept, finding)
	}
	return kept
}

// withoutRegExpExec is line with every exec call on a proven regular
// expression name taken out.
func withoutRegExpExec(line string, proven map[string]bool) string {
	matches := jsExecCall.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return line
	}
	var out strings.Builder
	last := 0
	for _, match := range matches {
		start, nameStart, nameEnd := match[0], match[2], match[3]
		if start > 0 && jsNameOrMemberByte(line[start-1]) || !proven[line[nameStart:nameEnd]] {
			continue
		}
		out.WriteString(line[last:start])
		out.WriteString(" ")
		last = match[1]
	}
	out.WriteString(line[last:])
	return out.String()
}

// jsProvenRegExpNames is the set of names the whole source proves are
// regular expressions (see the top of this file). It is empty when the
// masking cannot read the source.
func jsProvenRegExpNames(source string) map[string]bool {
	code, literalEnd, ok := jsMaskCode(source)
	if !ok || jsMeaningChange.MatchString(code) {
		return nil
	}
	closeOf, ok := jsBraceMatches(code)
	if !ok {
		return nil
	}
	type declaration struct{ name, blockStart, blockEnd int }
	declared := map[string][]declaration{}
	for _, head := range jsConstHead.FindAllStringSubmatchIndex(code, -1) {
		end, whole := jsWholeRegExpInitializer(code, head[1], literalEnd)
		if !whole || !jsStatementEnds(code, end) {
			continue
		}
		name := code[head[2]:head[3]]
		blockStart, blockEnd := jsEnclosingBlock(code, head[2], closeOf)
		declared[name] = append(declared[name], declaration{head[2], blockStart, blockEnd})
	}
	unproven := map[string]bool{}
	for name, declarations := range declared {
		unproven[name] = len(declarations) != 1
	}
	for _, loc := range jsIdentifier.FindAllStringIndex(code, -1) {
		name := code[loc[0]:loc[1]]
		declarations, ok := declared[name]
		if !ok || unproven[name] || loc[0] == declarations[0].name || jsPropertyName(code, loc[0]) {
			continue
		}
		decl := declarations[0]
		unproven[name] = loc[0] < decl.blockStart || loc[1] > decl.blockEnd ||
			(!jsMemberUse(code, loc[1]) && !jsPatternArgument(code, loc[0], loc[1]))
	}
	proven := map[string]bool{}
	for name := range declared {
		if !unproven[name] {
			proven[name] = true
		}
	}
	return proven
}

// jsMaskCode is source with comments, the text of strings and template
// literals and the bodies of regular expression literals replaced by
// spaces (lengths and newlines kept, ${...} of a template kept as code),
// and the end (after the flags) of each regular expression literal by its
// start. ok is false when a string, comment, template or literal does not
// end where the language says it must.
func jsMaskCode(source string) (string, map[int]int, bool) {
	code := []byte(source)
	literalEnd := map[int]int{}
	mask := func(from, to int) {
		for i := from; i < to; i++ {
			if code[i] != '\n' {
				code[i] = ' '
			}
		}
	}
	// templateDepth holds, for each open ${ of a template, the depth of the
	// braces opened inside it.
	var templateDepth []int
	var prevByte byte
	prevWord := ""
	inTemplate := false
	for i := 0; i < len(source); {
		if inTemplate {
			start := i
			for i < len(source) && source[i] != '`' && (source[i] != '$' || i+1 >= len(source) || source[i+1] != '{') {
				if source[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(source) {
				return "", nil, false
			}
			mask(start, i)
			inTemplate = false
			if source[i] == '`' {
				// the template is an operand: a slash after it divides
				prevByte, prevWord = ')', ""
				i++
			} else {
				templateDepth = append(templateDepth, 0)
				prevByte, prevWord = '{', ""
				i += 2
			}
			continue
		}
		c := source[i]
		switch {
		case c == '/' && i+1 < len(source) && source[i+1] == '/':
			end := strings.IndexByte(source[i:], '\n')
			if end < 0 {
				end = len(source) - i
			}
			mask(i, i+end)
			i += end
			continue
		case c == '/' && i+1 < len(source) && source[i+1] == '*':
			end := strings.Index(source[i+2:], "*/")
			if end < 0 {
				return "", nil, false
			}
			mask(i, i+2+end+2)
			i += 2 + end + 2
			continue
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(source) && source[j] != c {
				if source[j] == '\n' {
					return "", nil, false
				}
				if source[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(source) {
				return "", nil, false
			}
			mask(i+1, j)
			i = j + 1
			prevByte, prevWord = ')', ""
			continue
		case c == '`':
			inTemplate = true
			i++
			continue
		case c == '/' && jsSlashStartsRegExp(prevByte, prevWord):
			j, inClass := i+1, false
			for j < len(source) && (inClass || source[j] != '/') {
				switch source[j] {
				case '\n':
					return "", nil, false
				case '\\':
					j++
				case '[':
					inClass = true
				case ']':
					inClass = false
				}
				j++
			}
			if j >= len(source) {
				return "", nil, false
			}
			mask(i+1, j)
			j++
			for j < len(source) && source[j] >= 'a' && source[j] <= 'z' {
				j++
			}
			literalEnd[i] = j
			i = j
			prevByte, prevWord = ')', ""
			continue
		case c == '{' && len(templateDepth) > 0:
			templateDepth[len(templateDepth)-1]++
		case c == '}' && len(templateDepth) > 0:
			if templateDepth[len(templateDepth)-1] == 0 {
				templateDepth = templateDepth[:len(templateDepth)-1]
				inTemplate = true
				i++
				continue
			}
			templateDepth[len(templateDepth)-1]--
		}
		if jsWordByte(c) {
			end := jsWordEnd(source, i)
			switch {
			case c >= '0' && c <= '9':
				prevByte, prevWord = '0', ""
			case prevByte == '.':
				prevByte, prevWord = 'a', ""
			default:
				prevByte, prevWord = 'a', source[i:end]
			}
			i = end
			continue
		}
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			prevByte, prevWord = c, ""
		}
		i++
	}
	if inTemplate || len(templateDepth) > 0 {
		return "", nil, false
	}
	return string(code), literalEnd, true
}

// jsSlashStartsRegExp reports a slash that starts a regular expression
// literal: after an operator or punctuation, or after a keyword such as
// return, not after a name, a number or a closing bracket.
func jsSlashStartsRegExp(prevByte byte, prevWord string) bool {
	if prevWord != "" {
		return jsRegexAfterWords[prevWord]
	}
	return prevByte != ')' && prevByte != ']' && (prevByte < '0' || prevByte > '9') && prevByte != 'a'
}

// jsBraceMatches maps each { of the masked code to its }. ok is false when
// the braces do not balance.
func jsBraceMatches(code string) (map[int]int, bool) {
	closeOf := map[int]int{}
	var open []int
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{':
			open = append(open, i)
		case '}':
			if len(open) == 0 {
				return nil, false
			}
			closeOf[open[len(open)-1]] = i
			open = open[:len(open)-1]
		}
	}
	return closeOf, len(open) == 0
}

// jsEnclosingBlock is the span of the innermost block holding pos (the
// whole file at the top level).
func jsEnclosingBlock(code string, pos int, closeOf map[int]int) (int, int) {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch code[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return i, closeOf[i] + 1
			}
			depth--
		}
	}
	return 0, len(code)
}

// jsWholeRegExpInitializer reports an initializer at pos that is one
// regular expression literal or one RegExp(...) call, and where it ends.
func jsWholeRegExpInitializer(code string, pos int, literalEnd map[int]int) (int, bool) {
	if end, ok := literalEnd[pos]; ok {
		return end, true
	}
	head := jsRegExpCall.FindStringIndex(code[pos:])
	if head == nil || !jsRegExpConstructorIntact(code) {
		return 0, false
	}
	depth := 0
	for i := pos + head[1] - 1; i < len(code); i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// jsDeclaringWords declare the name that follows them.
var jsDeclaringWords = map[string]bool{"function": true, "class": true, "const": true, "let": true, "var": true}

// jsRegExpConstructorIntact reports that the code never binds or assigns
// the name RegExp, so RegExp(...) is the builtin constructor: every RegExp
// in the code is a call or new, or a type (after :, <, |, & or instanceof),
// and none follows function, class, const, let or var.
func jsRegExpConstructorIntact(code string) bool {
	for _, loc := range jsIdentifier.FindAllStringIndex(code, -1) {
		if code[loc[0]:loc[1]] != "RegExp" {
			continue
		}
		before := jsSkipSpaceBack(code, loc[0])
		wordStart := before
		for wordStart > 0 && jsWordByte(code[wordStart-1]) {
			wordStart--
		}
		word := code[wordStart:before]
		if jsDeclaringWords[word] {
			return false
		}
		if word == "new" || word == "instanceof" ||
			before > 0 && strings.IndexByte(":<|&", code[before-1]) >= 0 {
			continue
		}
		after := jsSkipSpace(code, loc[1])
		if after < len(code) && code[after] == '(' &&
			(before == 0 || code[before-1] != '*' && code[before-1] != '.') {
			continue
		}
		return false
	}
	return true
}

// jsStatementEnds reports that the statement ends at pos: a semicolon, a
// closing brace, the end of the file, or a new line that starts a new
// statement rather than continuing the expression.
func jsStatementEnds(code string, pos int) bool {
	newline := false
	for ; pos < len(code); pos++ {
		switch code[pos] {
		case ' ', '\t', '\r':
			continue
		case '\n':
			newline = true
			continue
		}
		break
	}
	if pos >= len(code) || code[pos] == ';' || code[pos] == '}' {
		return true
	}
	if !newline {
		return false
	}
	word := code[pos:jsWordEnd(code, pos)]
	return word != "" && (word[0] < '0' || word[0] > '9') && !jsContinuationWords[word]
}

// jsPropertyName reports a name that is the property of a member access
// (obj.re, obj?.re): not the declared name. A spread (...re) is the name.
func jsPropertyName(code string, start int) bool {
	i := jsSkipSpaceBack(code, start)
	if i <= 0 || code[i-1] != '.' {
		return false
	}
	return i < 2 || code[i-2] != '.'
}

// jsMemberUse reports a name followed by a member access (name.x or
// name?.x) whose member is not assigned to.
func jsMemberUse(code string, end int) bool {
	i := jsSkipSpace(code, end)
	switch {
	case strings.HasPrefix(code[i:], "?."):
		i += 2
	case strings.HasPrefix(code[i:], ".") && !strings.HasPrefix(code[i:], ".."):
		i++
	default:
		return false
	}
	start := jsSkipSpace(code, i)
	end = jsWordEnd(code, start)
	if end == start {
		return false
	}
	// lastIndex is the one member a matching loop writes; it is a number
	// and cannot change what exec does.
	return code[start:end] == "lastIndex" || !jsAssignmentAt(code, jsSkipSpace(code, end))
}

// jsPatternArgument reports a name that is the first argument of a string
// method taking a pattern: s.match(name) or s.replace(name, ...).
func jsPatternArgument(code string, start, end int) bool {
	i := jsSkipSpaceBack(code, start)
	if i <= 0 || code[i-1] != '(' {
		return false
	}
	methodEnd := jsSkipSpaceBack(code, i-1)
	methodStart := methodEnd
	for methodStart > 0 && jsWordByte(code[methodStart-1]) {
		methodStart--
	}
	dot := jsSkipSpaceBack(code, methodStart)
	if !jsPatternMethods[code[methodStart:methodEnd]] || dot <= 0 || code[dot-1] != '.' {
		return false
	}
	after := jsSkipSpace(code, end)
	return after < len(code) && (code[after] == ')' || code[after] == ',')
}

// jsAssignmentAt reports an assignment operator at i (=, +=, ??= ...), not
// a comparison or an arrow.
func jsAssignmentAt(code string, i int) bool {
	for _, op := range []string{"**=", "<<=", ">>>=", ">>=", "&&=", "||=", "??=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="} {
		if strings.HasPrefix(code[i:], op) {
			return true
		}
	}
	return strings.HasPrefix(code[i:], "=") && !strings.HasPrefix(code[i:], "==") && !strings.HasPrefix(code[i:], "=>")
}

// jsWordByte reports a byte of a name or a number.
func jsWordByte(b byte) bool {
	return b == '_' || b == '$' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// jsWordEnd is the end of the name or number that starts at i (i itself
// when none does).
func jsWordEnd(code string, i int) int {
	for i < len(code) && jsWordByte(code[i]) {
		i++
	}
	return i
}

func jsSkipSpace(code string, i int) int {
	for i < len(code) && (code[i] == ' ' || code[i] == '\t' || code[i] == '\n' || code[i] == '\r') {
		i++
	}
	return i
}

func jsSkipSpaceBack(code string, i int) int {
	for i > 0 && (code[i-1] == ' ' || code[i-1] == '\t' || code[i-1] == '\n' || code[i-1] == '\r') {
		i--
	}
	return i
}

// builtinRuleByID is the builtin CodeGuard rule with the ID.
func builtinRuleByID(id string) (rule, bool) {
	for _, candidate := range builtinRules {
		if candidate.id == id {
			return candidate, true
		}
	}
	return rule{}, false
}

// jsNameOrMemberByte reports a byte that, before a name, makes the name part
// of a longer name or a member (this.re, obj.re): not the declared name.
func jsNameOrMemberByte(b byte) bool {
	return b == '.' || jsWordByte(b)
}
