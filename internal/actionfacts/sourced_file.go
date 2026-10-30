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
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// sourcedFilePlaceholder stands in for a sourced file in the twin that
// SourcedFileReduction analyzes.
const sourcedFilePlaceholder = "true"

// SourcedFileReduction returns a complete view of a partial POSIX action
// whose opaque artifacts are only files it sources by a static name, such as
// `source .env && aws dynamodb scan --table-name T` or
// `set -a; source .env; set +a; aws ...`. facts must be Analyze(input).
//
// The sourced file runs in the current shell and its content is not known,
// so the action stays partial and no semantic rule ran on it: a custom rule
// about the aws call after it was only a detection-only regex finding
// (GAP-0117). The view is the analysis of a twin in which each such
// `source FILE` or `. FILE` statement is a no-op, reduced further as the
// other reductions reduce a partial twin, without the placeholder commands.
//
// The real action runs every command of the view after the sourced files,
// but a sourced file may change what they run (a function named like the
// program, exit, cd). That can only make a match on the view wrong in the
// blocking direction, never hide one, so a caller may count a match on the
// view only for an expression that is semantic.Program.StaticArgvSubsetSafe,
// and a non-match proves nothing.
//
// The view is unavailable unless every source or . command of the action is
// a plain top-level statement (alone or in an && or || list) whose words are
// all literal, the command defines no function and has no here-document, and
// the twin has no opaque artifact of its own.
func SourcedFileReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPOSIX ||
		len(facts.Commands) == 0 || !containsIssue(facts.Parse.Issues, IssueOpaqueArtifact) {
		return Facts{}, false
	}
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial {
		return Facts{}, false
	}
	twinSource, ok := sourcedFileTwin(capture.source)
	if !ok {
		return Facts{}, false
	}
	twinInput := input
	twinInput.Command = twinSource
	twinInput.Argv = nil
	twinInput.Args = nil
	if twinInput.CWD == "" {
		twinInput.CWD = extractArgsForTool(input.Args, input.Tool).cwd
	}
	twin := Analyze(twinInput)
	if twin.Parse.Dialect != DialectPOSIX || containsIssue(twin.Parse.Issues, IssueOpaqueArtifact) {
		return Facts{}, false
	}
	switch {
	case twin.Authoritative() && twin.Parse.Status == StatusComplete:
		view = twin
	default:
		reduced := false
		if candidate, found := ShortCircuitListReduction(twinInput, twin); found {
			view, reduced = candidate, true
		} else if candidate, _, found := StaticCommandSubsetReduction(twinInput, twin); found {
			view, reduced = candidate, true
		} else if candidate, found := UnmodeledProgramArgvReduction(twinInput, twin); found {
			view, reduced = candidate, true
		}
		if !reduced {
			return Facts{}, false
		}
	}
	return withoutSourcedFilePlaceholders(view, facts), len(view.Commands) > 0
}

// withoutSourcedFilePlaceholders drops the placeholder commands the twin
// added for the sourced files, unless the action itself runs that command.
func withoutSourcedFilePlaceholders(view, facts Facts) Facts {
	for _, command := range facts.Commands {
		if isSourcedFilePlaceholder(command) {
			return view
		}
	}
	dropped := map[int64]bool{}
	commands := make([]CommandFact, 0, len(view.Commands))
	for _, command := range view.Commands {
		if isSourcedFilePlaceholder(command) {
			dropped[command.ID] = true
			continue
		}
		commands = append(commands, command)
	}
	view.Commands = commands
	if len(dropped) == 0 {
		return view
	}
	paths := view.Paths[:0:0]
	for _, path := range view.Paths {
		if !dropped[path.CommandID] {
			paths = append(paths, path)
		}
	}
	view.Paths = paths
	return view
}

func isSourcedFilePlaceholder(command CommandFact) bool {
	return command.ParentCommandID == 0 && len(command.Argv) == 1 &&
		command.Argv[0] == sourcedFilePlaceholder
}

// sourcedFileTwin returns source with every top-level `source FILE` or
// `. FILE` statement whose words are all literal replaced by a no-op. It
// declines a source without one, one with a source or . command anywhere
// else (a pipeline, subshell, block or substitution) or with a dynamic word,
// and one with a function definition or a here-document.
func sourcedFileTwin(source string) (string, bool) {
	if source == "" {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(shellparse.Reader(source), "")
	if err != nil {
		return "", false
	}
	declined := false
	sourcing := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			declined = true
		case *syntax.Redirect:
			declined = declined || typed.Op == syntax.Hdoc || typed.Op == syntax.DashHdoc
		case *syntax.CallExpr:
			if len(typed.Args) > 0 && isSourceWord(typed.Args[0]) {
				sourcing++
			}
		}
		return !declined
	})
	if declined || sourcing == 0 {
		return "", false
	}
	type span struct{ start, end int }
	var spans []span
	var visit func(stmt *syntax.Stmt) bool
	visit = func(stmt *syntax.Stmt) bool {
		if posixStatementHasUnsupportedControl(stmt) {
			return false
		}
		if list, isList := stmt.Cmd.(*syntax.BinaryCmd); isList && len(stmt.Redirs) == 0 &&
			(list.Op == syntax.AndStmt || list.Op == syntax.OrStmt) {
			return visit(list.X) && visit(list.Y)
		}
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 || !isSourceWord(call.Args[0]) {
			return true
		}
		if len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) < 2 {
			return false
		}
		for _, word := range call.Args {
			if word.Lit() == "" {
				return false
			}
		}
		start, end := int(call.Pos().Offset()), int(call.End().Offset())
		if start < 0 || end <= start || end > len(source) {
			return false
		}
		spans = append(spans, span{start, end})
		return true
	}
	for _, stmt := range file.Stmts {
		if !visit(stmt) {
			return "", false
		}
	}
	if len(spans) != sourcing {
		return "", false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	twin := source
	for _, cut := range spans {
		twin = twin[:cut.start] + sourcedFilePlaceholder + twin[cut.end:]
	}
	return twin, true
}

func isSourceWord(word *syntax.Word) bool {
	literal := word.Lit()
	return literal == "source" || literal == "."
}
