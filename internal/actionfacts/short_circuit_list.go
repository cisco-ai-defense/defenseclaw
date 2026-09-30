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
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShortCircuitListReduction returns a complete view of a partial POSIX
// action with && or || lists, read as if every command of each list runs.
// facts must be Analyze(input).
//
// A block stops the whole tool call before any of it runs, so a command that
// runs only when the one before it succeeds (&&) or fails (||) is judged as
// if it runs: a rule that blocks `a; b` also blocks `a && b` and `a || b`.
// The view is the analysis of a twin of the command in which each && or ||
// list is the sequence of its commands, one statement per line. It has every
// command of the action and every fact they own; it differs from the action
// only in that every command is certain to run and the parse is complete, so
// a caller may count a semantic result on it, match or not, for an
// expression that reads neither (semantic.Program.ListReductionSafe).
//
// The view is unavailable unless every statement of every list is plain (not
// negated, in the background or a coprocess), the command defines no
// function and has no here-document, the twin analysis is complete, and
// every command in it is a plain POSIX process with a static argv.
func ShortCircuitListReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || len(facts.Commands) == 0 ||
		!containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) {
		return Facts{}, false
	}
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial {
		return Facts{}, false
	}
	twinSource, ok := shortCircuitListSequence(capture.source)
	if !ok {
		return Facts{}, false
	}
	twin, _ := analyzeWithRedirectTargets(input, twinSource)
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 ||
		twin.Parse.Dialect != facts.Parse.Dialect || len(twin.Commands) == 0 {
		return Facts{}, false
	}
	for _, command := range twin.Commands {
		if !plainPOSIXProcess(command) {
			return Facts{}, false
		}
	}
	return twin, true
}

// shortCircuitListSequence returns source with each top-level && or || list
// replaced by its commands, one statement per line. It declines a source
// without such a list, one with a negated, background or coprocess statement
// in a list, and one where a statement could change what another runs (a
// function definition) or where cutting the text could lose input (a
// here-document).
func shortCircuitListSequence(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return "", false
	}
	declined := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			declined = true
		case *syntax.Redirect:
			declined = declined || typed.Op == syntax.Hdoc || typed.Op == syntax.DashHdoc
		}
		return !declined
	})
	if declined {
		return "", false
	}
	kept := make([]string, 0, len(file.Stmts))
	reduced := false
	var flatten func(stmt *syntax.Stmt) bool
	flatten = func(stmt *syntax.Stmt) bool {
		if posixStatementHasUnsupportedControl(stmt) {
			return false
		}
		if list, isList := stmt.Cmd.(*syntax.BinaryCmd); isList && len(stmt.Redirs) == 0 &&
			(list.Op == syntax.AndStmt || list.Op == syntax.OrStmt) {
			reduced = true
			return flatten(list.X) && flatten(list.Y)
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end <= start || end > len(source) {
			return false
		}
		kept = append(kept, source[start:end])
		return true
	}
	for _, stmt := range file.Stmts {
		if !flatten(stmt) {
			return "", false
		}
	}
	if !reduced {
		return "", false
	}
	return strings.Join(kept, "\n"), true
}
