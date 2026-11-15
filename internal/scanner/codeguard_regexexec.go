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

package scanner

import (
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// codeFileContext is what one file says about its own names, read before
// its lines are matched: the JavaScript and TypeScript names bound to a
// regular expression. A rule with a fileView reads a line through it.
type codeFileContext struct {
	regex map[string]bool // names assigned a regular expression
	other map[string]bool // names assigned anything else
}

// jsAssignment is a name assigned a value on one line (a declaration, a
// class field, a typed field). Group 1 is the name, group 2 the value.
var jsAssignment = lazyregexp.New("(?:^|[^\\w$.])([A-Za-z_$][\\w$]*)\\s*(?::\\s*[\\w$<>\\[\\]| .]+?)?\\s*=\\s*([^=>\\s].*)$")

// jsRegexLiteralBody is a regular expression literal: /body/flags, where the
// body may hold an escaped character or a character class with a slash.
const jsRegexLiteralBody = `/(?:[^/\\\n\[*]|\\.|\[(?:[^\]\\]|\\.)*\])(?:[^/\\\n\[]|\\.|\[(?:[^\]\\]|\\.)*\])*/[dgimsuvy]*`

// jsRegexValue is a value that is a regular expression: a literal, or a
// RegExp construction.
var jsRegexValue = lazyregexp.New(`^(?:` + jsRegexLiteralBody + `(?:[\s;,).]|$)|(?:new\s+)?RegExp\s*\()`)

// jsRegexExecOnLiteral is exec called on a regular expression literal or a
// RegExp construction written at the call. The literal must stand where a
// value starts, so a division chain (a/b/g.exec) is not read as one.
var jsRegexExecOnLiteral = lazyregexp.New(`(^|[=(,:;!&|?{\[\s]|\breturn\b|\bawait\b)\s*(?:` + jsRegexLiteralBody + `|(?:new\s+)?RegExp\s*\([^()]*\))\s*\.exec\(`)

// jsExecReceiver is a name called with .exec(.
var jsExecReceiver = lazyregexp.New(`[A-Za-z_$][\w$]*\s*\??\.\s*exec\(`)

var jsExecReceiverName = lazyregexp.New(`^[A-Za-z_$][\w$]*`)

func newCodeFileContext() *codeFileContext {
	return &codeFileContext{regex: map[string]bool{}, other: map[string]bool{}}
}

// learn reads one line of a JavaScript or TypeScript file.
func (c *codeFileContext) learn(line string) {
	m := jsAssignment.FindStringSubmatch(line)
	if m == nil {
		return
	}
	if jsRegexValue.MatchString(m[2]) {
		c.regex[m[1]] = true
	} else {
		c.other[m[1]] = true
	}
}

// regexName reports a name that the file only ever binds to a regular
// expression. A name that is also assigned anything else (a reused or
// shadowed name) is not one.
func (c *codeFileContext) regexName(name string) bool {
	return c != nil && c.regex[name] && !c.other[name]
}

// execMethodView is the line CG-EXEC-001 reads: RegExp.prototype.exec is a
// pattern match, not a command. A call of exec on a regular expression
// literal or construction, or on a name the file binds only to one, is
// blanked. exec on any other receiver (child_process.exec, a shell client,
// a name bound to a module or left unbound) and a bare exec( keep
// matching (rel-1-0-10, CI #1456 gw17: a Copilot patch with
// pattern.exec(line) was alerted as unsafe command execution).
func execMethodView(line string, fc *codeFileContext) string {
	line = jsRegexExecOnLiteral.ReplaceAllString(line, "$1 ")
	if fc == nil {
		return line
	}
	return jsExecReceiver.ReplaceAllStringFunc(line, func(call string) string {
		if name := jsExecReceiverName.FindString(call); fc.regexName(name) {
			return " "
		}
		return call
	})
}
