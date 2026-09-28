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

// ShortCircuitListReduction returns a complete view of the commands of a
// partial POSIX action that are certain to run, when the action has && or ||
// lists. facts must be Analyze(input).
//
// The view is the analysis of a twin of the command that keeps every
// statement of the top-level sequence and replaces each && or || list with
// its first command: the only command of the list that always runs. Commands
// after && or || run only when the command before them succeeds or fails, so
// the view leaves them out, with every fact they own. A caller may count a
// semantic match on it only for an expression whose match more commands and
// facts cannot undo (semantic.Program.ListReductionSafe), and a non-match on
// it proves nothing about the action.
//
// The view is unavailable unless every top-level statement and list head is
// plain (not negated, in the background or a coprocess), the command defines
// no function and has no here-document, the twin analysis is complete, and
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
	twinSource, ok := shortCircuitListHeads(capture.source)
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

// shortCircuitListHeads returns source with each top-level && or || list
// replaced by its first command, one statement per line. It declines a
// source without such a list, and one where a left-out command could change
// what a kept one runs (a function definition) or where cutting the text
// could lose input (a here-document).
func shortCircuitListHeads(source string) (string, bool) {
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
	for _, stmt := range file.Stmts {
		head := stmt
		for !posixStatementHasUnsupportedControl(head) && len(head.Redirs) == 0 {
			list, isList := head.Cmd.(*syntax.BinaryCmd)
			if !isList || (list.Op != syntax.AndStmt && list.Op != syntax.OrStmt) {
				break
			}
			head, reduced = list.X, true
		}
		if posixStatementHasUnsupportedControl(head) {
			return "", false
		}
		start, end := int(head.Pos().Offset()), int(head.End().Offset())
		if start < 0 || end <= start || end > len(source) {
			return "", false
		}
		kept = append(kept, source[start:end])
	}
	if !reduced {
		return "", false
	}
	return strings.Join(kept, "\n"), true
}
