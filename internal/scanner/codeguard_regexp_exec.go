// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// CG-EXEC-001 reads exec( as command execution. In JavaScript and
// TypeScript, name.exec( is also RegExp.prototype.exec, the ordinary way to
// match a regular expression and read its groups: it runs no command. A
// Copilot patch that added a log parser calling logLinePattern.exec(line)
// raised a HIGH Unsafe command execution finding (rel-1-0-10:GAP-1152).
//
// A call of exec on a name the file proves is a regular expression is
// matching, so CG-EXEC-001 does not read that call. Two readings of the file
// must both prove the name:
//
//   - The line reading of rel (rel-1-0-10:GAP-1152): one line declares
//     const name = a regular expression literal or a RegExp, and no other
//     line binds the name (a declaration, an import or require, a parameter,
//     an assignment). It is the floor: the whole-file reading only takes
//     names away from it, so this narrowing never drops a finding rel keeps
//     (rel-1-0-10:GAP-1185 review r1).
//   - The whole-file reading (rel-1-0-10:GAP-1185), over the code of the
//     file with comments, string and template text and regular expression
//     bodies masked out:
//   - one statement const name = <initializer> whose whole initializer is
//     a regular expression literal or a RegExp(...) call, RegExp not
//     bound or assigned anywhere;
//   - every other occurrence of the name lies inside the block that holds
//     the const and only reads it: a RegExp member that is not written
//     (name.exec, name.test, name.source; name.lastIndex may be written),
//     or the name as a value (a call argument, an object or array element,
//     the right side of =, an operand);
//   - nothing in the file can change what exec on a regular expression
//     means: no with statement, no reach into a prototype or a constructor
//     (prototype, __proto__, getPrototypeOf, also as the text of a string
//     such as a bracketed key, or a string "constructor"), and no write of
//     an exec member on anything.
//
// An occurrence that binds or writes the name (a parameter of a function,
// method, arrow or catch, on one line or many; a destructuring or import; a
// declaration; an assignment, ++ or --; a for-in or for-of head), a computed
// member name[...] or a member that is not a RegExp member, and a file the
// masking cannot read (an unterminated string, comment or bracket), leave
// the name unproven. exec on any other receiver (child_process or an alias
// of it, shelljs, a member such as this.re, a name the file does not prove)
// still fires, and so does every other part of a line the rule matched.

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

// The line reading (rel). jsLineRegExpConst is a const declaration of a
// name bound to a regular expression literal or to a RegExp object.
var jsLineRegExpConst = lazyregexp.New(`\bconst\s+([A-Za-z_$][\w$]*)\s*(?::\s*RegExp\s*)?=\s*(?:/[^/*\s]|(?:new\s+)?RegExp\s*\()`)

// jsLineDeclaration marks a line that declares names: the names before the
// first = are bound there (all of them when there is no =).
var jsLineDeclaration = lazyregexp.New(`\b(?:const|let|var|class)\b`)

// jsLineParameters marks a line that may bind parameters: the names before
// the body ({) or the arrow (=>) are bound there.
var jsLineParameters = lazyregexp.New(`\bfunction\b|=>|\bcatch\b`)

// jsLineImport marks a line that brings names in from a module: every name
// of the line is bound there.
var jsLineImport = lazyregexp.New(`\bimport\b|\brequire\s*\(`)

// jsLineAssignment is an assignment (plain or compound) of a name that is
// not a member: name =, name +=, name ??= ... but not ==, === or =>.
var jsLineAssignment = lazyregexp.New(`(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*(?:\*\*|<<|>>>|>>|&&|\|\||\?\?|[-+*/%&|^])?=(?:[^=>]|$)`)

// jsConstHead is the start of a statement const name = (export const, and
// a TypeScript RegExp annotation, allowed). The initializer follows.
var jsConstHead = lazyregexp.New(`(?m)(?:^|[;{}])[ \t]*(?:export[ \t]+)?const[ \t]+([A-Za-z_$][\w$]*)[ \t]*(?::[ \t]*RegExp[ \t]*)?=[ \t]*`)

// jsRegExpCall is the head of a RegExp(...) or new RegExp(...) initializer.
var jsRegExpCall = lazyregexp.New(`^(?:new[ \t]+)?RegExp[ \t]*\(`)

// jsMeaningChange is code that can change what a name or the exec method of
// a regular expression means: a with statement, any reach into a prototype
// (prototype, __proto__, getPrototypeOf, setPrototypeOf), or a write of an
// exec member (x.exec = ..., x.exec ??= ...).
var jsMeaningChange = lazyregexp.New(`(?i)\bwith\s*\(|prototype|__proto__|\.\s*exec\s*(?:\*\*|<<|>>>|>>|&&|\|\||\?\?|[-+*/%&|^])?=(?:[^=]|$)`)

// jsRegExpMembers are the members of a RegExp object. Any other member of a
// proven name (constructor, __proto__, a name the object was given) reaches
// past the regular expression.
var jsRegExpMembers = map[string]bool{
	"exec": true, "test": true, "source": true, "flags": true, "lastIndex": true, "global": true,
	"ignoreCase": true, "multiline": true, "sticky": true, "unicode": true, "unicodeSets": true,
	"dotAll": true, "hasIndices": true, "toString": true, "compile": true,
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

// jsBindingWords bind, declare or name the name that follows them.
var jsBindingWords = map[string]bool{
	"const": true, "let": true, "var": true, "function": true, "class": true, "import": true, "as": true,
	"enum": true, "interface": true, "type": true, "namespace": true, "module": true, "declare": true,
	"get": true, "set": true, "static": true, "readonly": true, "public": true, "private": true,
	"protected": true, "abstract": true, "override": true, "accessor": true, "infer": true,
}

// jsExpressionWords are keywords an expression can follow: a [ after them
// starts an array, not a computed member.
var jsExpressionWords = map[string]bool{
	"return": true, "typeof": true, "case": true, "in": true, "of": true, "new": true, "delete": true,
	"void": true, "throw": true, "yield": true, "await": true, "else": true, "do": true, "instanceof": true,
	"const": true, "let": true, "var": true, "export": true, "default": true, "extends": true,
}

// jsObjectLiteralAfter are the tokens after which a { starts an object
// literal rather than a block.
var jsObjectLiteralAfter = map[string]bool{
	"=": true, "(": true, ",": true, ":": true, "[": true, "?": true, "!": true, "...": true, "|": true,
	"&": true, "+": true, "-": true, "==": true, "!=": true, "<": true, ">": true, "return": true,
	"yield": true, "await": true, "throw": true, "default": true, "case": true, "export": true,
}

// jsMultiByteTokens are the tokens of more than one byte that the use of a
// name is read against (longest first).
var jsMultiByteTokens = []string{"...", "=>", "++", "--", "?.", "==", "!="}

// jsRegExpReceivers collects the lines of a JavaScript or TypeScript file
// and drops the CG-EXEC-001 findings whose only exec( calls are the RegExp
// method of names the file proves are regular expressions. A nil collector
// (any other file type) keeps every finding.
type jsRegExpReceivers struct {
	source strings.Builder
	// The line reading (rel): the names a line declares as a regular
	// expression const, and how many lines bind each name.
	lineRegExp map[string]bool
	lineBinds  map[string]int
}

func newJSRegExpReceivers(ext string) *jsRegExpReceivers {
	if !jsLikeExtensions[ext] {
		return nil
	}
	return &jsRegExpReceivers{lineRegExp: map[string]bool{}, lineBinds: map[string]int{}}
}

// observe reads one line of the file.
func (r *jsRegExpReceivers) observe(line string) {
	if r == nil {
		return
	}
	r.source.WriteString(line)
	r.source.WriteByte('\n')

	bound := map[string]bool{}
	bindAll := func(text string) {
		for _, name := range jsIdentifier.FindAllString(text, -1) {
			bound[name] = true
		}
	}
	if jsLineImport.MatchString(line) {
		bindAll(line)
	}
	if loc := jsLineDeclaration.FindStringIndex(line); loc != nil {
		head := line[loc[0]:]
		if eq := strings.Index(head, "="); eq >= 0 {
			head = head[:eq]
		}
		bindAll(head)
	}
	if jsLineParameters.MatchString(line) {
		head := line
		for _, end := range []string{"=>", "{"} {
			if cut := strings.Index(head, end); cut >= 0 {
				head = head[:cut]
			}
		}
		bindAll(head)
	}
	for _, match := range jsLineAssignment.FindAllStringSubmatch(line, -1) {
		bound[match[1]] = true
	}
	for _, match := range jsLineRegExpConst.FindAllStringSubmatch(line, -1) {
		r.lineRegExp[match[1]] = true
		bound[match[1]] = true
	}
	for name := range bound {
		r.lineBinds[name]++
	}
}

// drop removes each builtin CG-EXEC-001 finding whose line no longer
// matches the rule once the RegExp exec calls of proven names are taken
// out. A custom rule that reuses the ID is kept: it is not this rule.
func (r *jsRegExpReceivers) drop(findings []Finding) []Finding {
	if r == nil || len(r.lineRegExp) == 0 {
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
	for name := range proven {
		if !r.lineRegExp[name] || r.lineBinds[name] != 1 {
			delete(proven, name)
		}
	}
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
	code, literalEnd, textReachesPrototype, ok := jsMaskCode(source)
	if !ok || textReachesPrototype || jsMeaningChange.MatchString(code) {
		return nil
	}
	groups, ok := jsGroupsOf(code)
	if !ok {
		return nil
	}
	// Whether RegExp is the builtin constructor is one reading of the whole
	// file, the same for every RegExp(...) initializer: it runs once, on the
	// first one, so the proof stays linear in the size of the file
	// (rel-1-0-10:GAP-1271).
	constructorIntact := sync.OnceValue(func() bool { return jsRegExpConstructorIntact(code) })
	type declaration struct{ name, blockStart, blockEnd int }
	declared := map[string][]declaration{}
	for _, head := range jsConstHead.FindAllStringSubmatchIndex(code, -1) {
		end, whole := jsWholeRegExpInitializer(code, head[1], literalEnd, groups, constructorIntact)
		if !whole || !jsStatementEnds(code, end) {
			continue
		}
		name := code[head[2]:head[3]]
		blockStart, blockEnd := groups.block(head[2])
		declared[name] = append(declared[name], declaration{head[2], blockStart, blockEnd})
	}
	unproven := map[string]bool{}
	for name, declarations := range declared {
		unproven[name] = len(declarations) != 1
	}
	for _, loc := range jsIdentifier.FindAllStringIndex(code, -1) {
		name := code[loc[0]:loc[1]]
		declarations, ok := declared[name]
		if !ok || unproven[name] || loc[0] == declarations[0].name {
			continue
		}
		use := groups.use(loc[0], loc[1])
		if use == jsUseKey {
			continue
		}
		decl := declarations[0]
		unproven[name] = loc[0] < decl.blockStart || loc[1] > decl.blockEnd || use != jsUseReads
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
// start. textReachesPrototype reports a string or template text that names
// a prototype or a constructor (a bracketed key such as x["prototype"]):
// masking would hide that reach. ok is false when a string, comment,
// template or literal does not end where the language says it must.
func jsMaskCode(source string) (code string, literalEnd map[int]int, textReachesPrototype bool, ok bool) {
	masked := []byte(source)
	literalEnd = map[int]int{}
	mask := func(from, to int) {
		if jsTextReachesPrototype(source[from:to]) {
			textReachesPrototype = true
		}
		for i := from; i < to; i++ {
			if masked[i] != '\n' {
				masked[i] = ' '
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
				return "", nil, false, false
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
			for k := i; k < i+end; k++ {
				masked[k] = ' '
			}
			i += end
			continue
		case c == '/' && i+1 < len(source) && source[i+1] == '*':
			end := strings.Index(source[i+2:], "*/")
			if end < 0 {
				return "", nil, false, false
			}
			for k := i; k < i+2+end+2; k++ {
				if masked[k] != '\n' {
					masked[k] = ' '
				}
			}
			i += 2 + end + 2
			continue
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(source) && source[j] != c {
				if source[j] == '\n' {
					return "", nil, false, false
				}
				if source[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(source) {
				return "", nil, false, false
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
					return "", nil, false, false
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
				return "", nil, false, false
			}
			for k := i + 1; k < j; k++ {
				masked[k] = ' '
			}
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
		return "", nil, false, false
	}
	return string(masked), literalEnd, textReachesPrototype, true
}

// jsTextReachesPrototype reports string or template text that names a
// prototype (prototype, __proto__, getPrototypeOf) or is the key
// "constructor".
func jsTextReachesPrototype(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "prototype") || strings.Contains(lower, "__proto__") ||
		strings.TrimSpace(text) == "constructor"
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

// jsGroup is one bracket pair of the masked code: (), [] or {}. parent is
// the index of the pair that holds it (-1 at the top level), brace the
// index of the innermost { } that holds or is it (-1 at the top level).
type jsGroup struct {
	open, close, parent, brace int
}

// jsGroups are the bracket pairs of the masked code, in the order they
// open, and closed, their indexes in the order they close. Each use of a
// name reads its groups through binary searches and facts read once per
// group (memo), so the whole proof stays linear in the size of the file
// (rel-1-0-10:GAP-1271).
type jsGroups struct {
	code   string
	list   []jsGroup
	closed []int
	memo   []jsGroupFacts
}

// jsGroupFacts are the facts of one group read so far: 0 not read yet, 1
// false, 2 true.
type jsGroupFacts struct {
	parameters, forHead, computedMember, objectLiteral, pattern int8
}

// jsFact is the fact in slot, read once.
func jsFact(slot *int8, read func() bool) bool {
	if *slot == 0 {
		*slot = 1
		if read() {
			*slot = 2
		}
	}
	return *slot == 2
}

// jsCloses maps each opening bracket to its closing one.
var jsCloses = map[byte]byte{'(': ')', '[': ']', '{': '}'}

// jsGroupsOf pairs the brackets of the masked code. ok is false when they
// do not balance.
func jsGroupsOf(code string) (*jsGroups, bool) {
	groups := &jsGroups{code: code}
	var open []int
	for i := 0; i < len(code); i++ {
		switch c := code[i]; c {
		case '(', '[', '{':
			parent, brace := -1, -1
			if len(open) > 0 {
				parent = open[len(open)-1]
				brace = groups.list[parent].brace
			}
			if c == '{' {
				brace = len(groups.list)
			}
			groups.list = append(groups.list, jsGroup{open: i, close: -1, parent: parent, brace: brace})
			open = append(open, len(groups.list)-1)
		case ')', ']', '}':
			if len(open) == 0 {
				return nil, false
			}
			top := open[len(open)-1]
			if jsCloses[code[groups.list[top].open]] != c {
				return nil, false
			}
			groups.list[top].close = i
			groups.closed = append(groups.closed, top)
			open = open[:len(open)-1]
		}
	}
	groups.memo = make([]jsGroupFacts, len(groups.list))
	return groups, len(open) == 0
}

// closeAfter is the position just after the bracket that closes the one
// opening at open. ok is false when no group opens there.
func (g *jsGroups) closeAfter(open int) (int, bool) {
	i := sort.Search(len(g.list), func(k int) bool { return g.list[k].open >= open })
	if i == len(g.list) || g.list[i].open != open {
		return 0, false
	}
	return g.list[i].close + 1, true
}

// kind is the opening bracket of group i.
func (g *jsGroups) kind(i int) byte { return g.code[g.list[i].open] }

// innermost is the index of the innermost group that holds pos (-1 at the
// top level): the group that opened last before pos if no bracket closed
// after it, else the parent of the group that closed last before pos.
func (g *jsGroups) innermost(pos int) int {
	opened := sort.Search(len(g.list), func(k int) bool { return g.list[k].open >= pos }) - 1
	closed := sort.Search(len(g.closed), func(k int) bool { return g.list[g.closed[k]].close >= pos }) - 1
	if closed < 0 || opened >= 0 && g.list[opened].open > g.list[g.closed[closed]].close {
		return opened
	}
	return g.list[g.closed[closed]].parent
}

// block is the span of the innermost { } holding pos (the whole file at
// the top level).
func (g *jsGroups) block(pos int) (int, int) {
	if i := g.innermost(pos); i >= 0 {
		if b := g.list[i].brace; b >= 0 {
			return g.list[b].open, g.list[b].close + 1
		}
	}
	return 0, len(g.code)
}

// jsUse is how one occurrence uses a declared name.
type jsUse int

const (
	// jsUseBinds binds or writes the name, or reaches past the regular
	// expression: the name is not proven.
	jsUseBinds jsUse = iota
	// jsUseReads only reads the name or a RegExp member of it.
	jsUseReads
	// jsUseKey is a property key or a member name: not the name.
	jsUseKey
)

// use reads the occurrence of a declared name at [start, end).
func (g *jsGroups) use(start, end int) jsUse {
	code := g.code
	if jsPropertyName(code, start) {
		return jsUseKey
	}
	before, _ := jsTokenBefore(code, start)
	next := jsTokenAfter(code, end)
	inner := g.innermost(start)
	switch {
	case next == "." || next == "?.":
		if jsRegExpMemberRead(code, end) {
			return jsUseReads
		}
		return jsUseBinds
	case next == ":" && (before == "{" || before == ",") && (inner < 0 || g.kind(inner) == '{'):
		return jsUseKey
	case next == "[" || next == "=>" || next == "++" || next == "--" || next == "of" || next == "in" ||
		before == "++" || before == "--" || before == "*" || jsBindingWords[before] ||
		jsAssignmentAt(code, jsSkipSpace(code, end)):
		return jsUseBinds
	}
	if inner < 0 {
		// a comma at the top level may continue a declaration list
		if before == "," {
			return jsUseBinds
		}
		return jsUseReads
	}
	switch g.kind(inner) {
	case '(':
		if g.parameters(inner) || g.forHead(inner) {
			return jsUseBinds
		}
	case '[':
		if !g.computedMember(inner) && g.pattern(inner) {
			return jsUseBinds
		}
	case '{':
		if g.pattern(inner) || before == "," && !g.objectLiteral(inner) {
			return jsUseBinds
		}
	}
	return jsUseReads
}

// parameters reports a ( ) group that is a parameter list: of a catch, a
// function, a method or an arrow (its ) followed by {, => or a type).
func (g *jsGroups) parameters(i int) bool {
	return jsFact(&g.memo[i].parameters, func() bool { return g.readParameters(i) })
}

func (g *jsGroups) readParameters(i int) bool {
	before, at := jsTokenBefore(g.code, g.list[i].open)
	switch before {
	case "catch", "function":
		return true
	case "if", "while", "switch", "for", "with":
		return false
	}
	if before != "" && jsWordByte(before[0]) {
		if word, _ := jsTokenBefore(g.code, at); word == "function" {
			return true
		}
	}
	next := jsTokenAfter(g.code, g.list[i].close+1)
	return next == "=>" || next == "{" || next == ":"
}

// forHead reports the ( ) of a for statement.
func (g *jsGroups) forHead(i int) bool {
	return jsFact(&g.memo[i].forHead, func() bool { return g.readForHead(i) })
}

func (g *jsGroups) readForHead(i int) bool {
	before, at := jsTokenBefore(g.code, g.list[i].open)
	if before == "await" {
		before, _ = jsTokenBefore(g.code, at)
	}
	return before == "for"
}

// computedMember reports a [ ] that follows an operand: obj[key].
func (g *jsGroups) computedMember(i int) bool {
	return jsFact(&g.memo[i].computedMember, func() bool { return g.readComputedMember(i) })
}

func (g *jsGroups) readComputedMember(i int) bool {
	before, _ := jsTokenBefore(g.code, g.list[i].open)
	switch {
	case before == ")" || before == "]" || before == "?." || before == `"` || before == "'" || before == "`":
		return true
	case before != "" && jsWordByte(before[0]):
		return !jsExpressionWords[before]
	}
	return false
}

// objectLiteral reports a { } that starts an object literal, not a block.
func (g *jsGroups) objectLiteral(i int) bool {
	return jsFact(&g.memo[i].objectLiteral, func() bool { return g.readObjectLiteral(i) })
}

func (g *jsGroups) readObjectLiteral(i int) bool {
	before, _ := jsTokenBefore(g.code, g.list[i].open)
	return jsObjectLiteralAfter[before]
}

// pattern reports a [ ] or { } that binds the names in it: a destructuring
// declaration or assignment, an import list, a for-in or for-of target, or
// one inside a parameter list or another pattern.
func (g *jsGroups) pattern(i int) bool {
	return jsFact(&g.memo[i].pattern, func() bool { return g.readPattern(i) })
}

func (g *jsGroups) readPattern(i int) bool {
	group := g.list[i]
	if before, _ := jsTokenBefore(g.code, group.open); before == "const" || before == "let" || before == "var" {
		return true
	}
	if next := jsTokenAfter(g.code, group.close+1); next == "from" || next == "of" || next == "in" ||
		jsAssignmentAt(g.code, jsSkipSpace(g.code, group.close+1)) {
		return true
	}
	parent := group.parent
	if parent < 0 {
		return false
	}
	switch g.kind(parent) {
	case '(':
		return g.parameters(parent) || g.forHead(parent)
	case '[':
		return !g.computedMember(parent) && g.pattern(parent)
	default:
		return g.pattern(parent)
	}
}

// jsTokenBefore is the token that ends right before i, and where it starts:
// a name or keyword, one of the multi-byte tokens, or one byte ("" at the
// start of the code).
func jsTokenBefore(code string, i int) (string, int) {
	end := jsSkipSpaceBack(code, i)
	if end == 0 {
		return "", 0
	}
	if jsWordByte(code[end-1]) {
		start := end
		for start > 0 && jsWordByte(code[start-1]) {
			start--
		}
		return code[start:end], start
	}
	for _, token := range jsMultiByteTokens {
		if strings.HasSuffix(code[:end], token) {
			return token, end - len(token)
		}
	}
	return code[end-1 : end], end - 1
}

// jsTokenAfter is the token that starts at or after i: a name or keyword,
// one of the multi-byte tokens, or one byte ("" at the end of the code).
func jsTokenAfter(code string, i int) string {
	start := jsSkipSpace(code, i)
	if start >= len(code) {
		return ""
	}
	if end := jsWordEnd(code, start); end > start {
		return code[start:end]
	}
	for _, token := range jsMultiByteTokens {
		if strings.HasPrefix(code[start:], token) {
			return token
		}
	}
	return code[start : start+1]
}

// jsWholeRegExpInitializer reports an initializer at pos that is one
// regular expression literal or one RegExp(...) call, and where it ends.
// constructorIntact is jsRegExpConstructorIntact of the code, read once per
// file; the call ends at the ) the bracket pairs give its (.
func jsWholeRegExpInitializer(code string, pos int, literalEnd map[int]int, groups *jsGroups, constructorIntact func() bool) (int, bool) {
	if end, ok := literalEnd[pos]; ok {
		return end, true
	}
	head := jsRegExpCall.FindStringIndex(code[pos:])
	if head == nil || !constructorIntact() {
		return 0, false
	}
	return groups.closeAfter(pos + head[1] - 1)
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

// jsRegExpMemberRead reports a name followed by a member access (name.x or
// name?.x) whose member is a RegExp member that is not assigned to.
func jsRegExpMemberRead(code string, end int) bool {
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
	member := code[start:end]
	if !jsRegExpMembers[member] {
		return false
	}
	// lastIndex is the one member a matching loop writes; it is a number
	// and cannot change what exec does.
	return member == "lastIndex" || !jsAssignmentAt(code, jsSkipSpace(code, end))
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
