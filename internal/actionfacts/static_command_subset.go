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

// shellStateBuiltins change what later commands of the same action run or
// where their relative paths point. When one of them has a runtime-expanded
// word, the static commands after it cannot be read on their own.
var shellStateBuiltins = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "eval": true, "source": true,
	".": true, "exec": true, "exit": true, "return": true, "alias": true,
	"unalias": true, "enable": true, "trap": true, "set": true, "shopt": true,
	"unset": true, "export": true, "declare": true, "typeset": true,
	"local": true, "readonly": true, "hash": true, "builtin": true,
	"command": true,
}

// StaticCommandSubsetReduction returns a complete view of a partial POSIX
// action that keeps only the commands the shell is certain to run with a
// static argv, such as `echo marker` in `echo marker > /tmp/x-$(id -u).txt`,
// `echo marker > $PWD/x.txt` or `echo marker | tee /tmp/x-$USER.txt`.
// facts must be Analyze(input).
//
// The action runs every kept command exactly as the view has it, so the
// action has at least the view's commands and the facts they own. The view
// lacks the other commands, the runtime-expanded redirects, and the paths,
// network facts and data flows of the dropped commands. A caller may count a
// semantic match on it only for an expression whose match more commands,
// redirects, paths, network facts and data flows cannot undo
// (semantic.Program.StaticCommandSubsetSafe); a non-match proves nothing.
//
// A kept command is a POSIX process whose every argument is static, whose
// execution is certain, and whose parent commands are kept too. The view is
// unavailable when the only issues are not runtime-expanded words and
// unsupported constructs, when the command defines a function, or when a
// dropped command is a shell builtin that could change what the kept ones
// run or where their paths point (cd $DIR, eval "$X", exec $X, ...).
func StaticCommandSubsetReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPOSIX ||
		len(facts.Commands) == 0 || !containsIssue(facts.Parse.Issues, IssueDynamicWord) {
		return Facts{}, false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueDynamicWord && issue != IssueUnsupportedConstruct {
			return Facts{}, false
		}
	}
	_, capture := analyzeWithRedirectTargets(input, "")
	if definesFunction(capture.source) {
		return Facts{}, false
	}

	byID := make(map[int64]CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		byID[command.ID] = command
	}
	kept := make(map[int64]bool, len(facts.Commands))
	var keep func(command CommandFact, depth int) bool
	keep = func(command CommandFact, depth int) bool {
		if depth > len(facts.Commands) || !staticCertainPOSIXProcess(command) {
			return false
		}
		if command.ParentCommandID == 0 {
			return true
		}
		parent, found := byID[command.ParentCommandID]
		return found && keep(parent, depth+1)
	}
	commands := make([]CommandFact, 0, len(facts.Commands))
	for _, command := range cloneCommands(facts.Commands) {
		if !keep(command, 0) {
			if shellStateBuiltins[strings.ToLower(command.Program)] {
				return Facts{}, false
			}
			continue
		}
		kept[command.ID] = true
		redirects := make([]RedirectFact, 0, len(command.Redirects))
		for _, redirect := range command.Redirects {
			if !redirect.Expands && redirect.Target != "" {
				redirects = append(redirects, redirect)
			}
		}
		command.Redirects = redirects
		command.ArgvComplete = true
		commands = append(commands, command)
	}
	if len(commands) == 0 {
		return Facts{}, false
	}

	view = facts
	view.Parse = ParseResult{Status: StatusComplete, Dialect: facts.Parse.Dialect}
	view.Commands = commands
	view.Paths = nil
	for _, path := range facts.Paths {
		if kept[path.CommandID] {
			view.Paths = append(view.Paths, path)
		}
	}
	view.Network = nil
	for _, network := range facts.Network {
		if kept[network.CommandID] {
			view.Network = append(view.Network, network)
		}
	}
	view.DataFlows = nil
	for _, flow := range facts.DataFlows {
		if (flow.FromCommandID == 0 || kept[flow.FromCommandID]) &&
			(flow.ToCommandID == 0 || kept[flow.ToCommandID]) {
			view.DataFlows = append(view.DataFlows, flow)
		}
	}
	return view, true
}

// staticCertainPOSIXProcess reports whether command is a POSIX process that
// is certain to run, with a program and every argument static. Its
// ArgvComplete may still be false when only a redirect target expands.
func staticCertainPOSIXProcess(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		(command.Kind != CommandKindProcess && command.Kind != "") ||
		command.Effect != EffectExecute || command.ControlFlowUncertain ||
		command.Background || len(command.Argv) == 0 || command.Argv[0] == "" ||
		command.Executable == "" || command.Program == "" ||
		len(command.Arguments) != len(command.Argv) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return false
		}
	}
	return true
}

// definesFunction reports whether source fails to parse or declares a shell
// function, which could change what a later static command runs.
func definesFunction(source string) bool {
	if source == "" {
		return true
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return true
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.FuncDecl); ok {
			found = true
		}
		return !found
	})
	return found
}
