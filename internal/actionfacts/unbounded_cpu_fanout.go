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
	if !checkPOSIXBounds(file, &bounds) || len(file.Stmts) != 1 {
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
