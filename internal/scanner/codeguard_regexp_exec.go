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
// matching, so CG-EXEC-001 does not read that call. The proof is a const
// declaration of the name bound to a regular expression literal or to a
// RegExp built at run time, and no other line of the file that binds the
// name (a declaration, an import or require, a parameter, an assignment).
// exec on any other receiver (child_process or an alias of it, shelljs, a
// member such as this.re, a name the file does not prove) still fires, and
// so does every other part of a line the rule matched.

// codeGuardExecRuleID is the builtin rule this file narrows.
const codeGuardExecRuleID = "CG-EXEC-001"

// jsLikeExtensions are the file extensions whose exec( may be the RegExp
// method.
var jsLikeExtensions = map[string]bool{
	".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true,
}

// jsRegExpConst is a const declaration of a name bound to a regular
// expression literal (the slash is not a comment) or to a RegExp object.
var jsRegExpConst = lazyregexp.New(`\bconst\s+([A-Za-z_$][\w$]*)\s*(?::\s*RegExp\s*)?=\s*(?:/[^/*\s]|(?:new\s+)?RegExp\s*\()`)

// jsIdentifier is one name of a line.
var jsIdentifier = lazyregexp.New(`[A-Za-z_$][\w$]*`)

// jsDeclarationKeyword marks a line that declares names: the names before
// the first = are bound there (all of them when there is no =).
var jsDeclarationKeyword = lazyregexp.New(`\b(?:const|let|var|class)\b`)

// jsParameterKeyword marks a line that may bind parameters: the names
// before the body ({) or the arrow (=>) are bound there.
var jsParameterKeyword = lazyregexp.New(`\bfunction\b|=>|\bcatch\b`)

// jsImportKeyword marks a line that brings names in from a module: every
// name of the line is bound there.
var jsImportKeyword = lazyregexp.New(`\bimport\b|\brequire\s*\(`)

// jsAssignment is an assignment (plain or compound) of a name that is not a
// member: name =, name +=, name ??= ... but not ==, === or =>.
var jsAssignment = lazyregexp.New(`(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*(?:\*\*|<<|>>>|>>|&&|\|\||\?\?|[-+*/%&|^])?=(?:[^=>]|$)`)

// jsExecCall is a call of the exec method on a name: name.exec( or
// name?.exec(.
var jsExecCall = lazyregexp.New(`([A-Za-z_$][\w$]*)\s*(?:\?\.|\.)\s*exec\s*\(`)

// jsRegExpReceivers collects, line by line, the names a JavaScript or
// TypeScript file proves are regular expressions, and drops the CG-EXEC-001
// findings whose only exec( calls are the RegExp method of those names. A
// nil collector (any other file type) keeps every finding.
type jsRegExpReceivers struct {
	regexp map[string]bool
	binds  map[string]int
}

func newJSRegExpReceivers(ext string) *jsRegExpReceivers {
	if !jsLikeExtensions[strings.ToLower(ext)] {
		return nil
	}
	return &jsRegExpReceivers{regexp: map[string]bool{}, binds: map[string]int{}}
}

// observe reads one line of the file.
func (r *jsRegExpReceivers) observe(line string) {
	if r == nil {
		return
	}
	bound := map[string]bool{}
	bindAll := func(text string) {
		for _, name := range jsIdentifier.FindAllString(text, -1) {
			bound[name] = true
		}
	}
	if jsImportKeyword.MatchString(line) {
		bindAll(line)
	}
	if loc := jsDeclarationKeyword.FindStringIndex(line); loc != nil {
		head := line[loc[0]:]
		if eq := strings.Index(head, "="); eq >= 0 {
			head = head[:eq]
		}
		bindAll(head)
	}
	if jsParameterKeyword.MatchString(line) {
		head := line
		for _, end := range []string{"=>", "{"} {
			if cut := strings.Index(head, end); cut >= 0 {
				head = head[:cut]
			}
		}
		bindAll(head)
	}
	for _, match := range jsAssignment.FindAllStringSubmatch(line, -1) {
		bound[match[1]] = true
	}
	for _, match := range jsRegExpConst.FindAllStringSubmatch(line, -1) {
		r.regexp[match[1]] = true
		bound[match[1]] = true
	}
	for name := range bound {
		r.binds[name]++
	}
}

// provenRegExp reports a name the whole file proves is a regular
// expression: one const binding to a regular expression and no other line
// that binds the name.
func (r *jsRegExpReceivers) provenRegExp(name string) bool {
	return r.regexp[name] && r.binds[name] == 1
}

// withoutRegExpExec is line with every exec call on a proven regular
// expression name taken out.
func (r *jsRegExpReceivers) withoutRegExpExec(line string) string {
	matches := jsExecCall.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return line
	}
	var out strings.Builder
	last := 0
	for _, match := range matches {
		start, nameStart, nameEnd := match[0], match[2], match[3]
		if start > 0 && jsNameOrMemberByte(line[start-1]) || !r.provenRegExp(line[nameStart:nameEnd]) {
			continue
		}
		out.WriteString(line[last:start])
		out.WriteString(" ")
		last = match[1]
	}
	out.WriteString(line[last:])
	return out.String()
}

// drop removes each builtin CG-EXEC-001 finding whose line no longer
// matches the rule once the RegExp exec calls of proven names are taken
// out. A custom rule that reuses the ID is kept: it is not this rule.
func (r *jsRegExpReceivers) drop(findings []Finding) []Finding {
	if r == nil || len(r.regexp) == 0 {
		return findings
	}
	execRule, ok := builtinRuleByID(codeGuardExecRuleID)
	if !ok {
		return findings
	}
	kept := findings[:0]
	for _, finding := range findings {
		if finding.CodeGuardBuiltinMatch(codeGuardExecRuleID) &&
			!execRule.matches(r.withoutRegExpExec(finding.Description)) {
			continue
		}
		kept = append(kept, finding)
	}
	return kept
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
	return b == '.' || b == '_' || b == '$' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
