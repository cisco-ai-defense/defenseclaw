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
	"slices"
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
// execution is certain or only depends on a plain && or || list (which a
// complete parse counts as well), and whose parent commands are kept too. The view is
// unavailable when the only issues are not runtime-expanded words and
// unsupported constructs, when the command defines a function, or when a
// dropped command is a shell builtin that could change what the kept ones
// run or where their paths point (cd $DIR, eval "$X", exec $X, ...).
//
// A command certain to run whose program word is static but some of whose
// arguments expand at runtime, such as `echo marker $USER` (GAP-0029), is
// kept with partial argv set: its argv and arguments are only its static
// words, in order, its effect is execute, and it has no operations,
// wrappers, paths, network facts or data flows. A runtime-expanded word becomes zero or more words, so each
// static word is still an argument of the real process, but its position,
// the argument count and what the command does are not known. A caller may
// count a match on such a view only for an expression that also reads argv,
// arguments, operations and wrappers only where more of them can only keep
// a match, and never reads effect (semantic.Program.StaticArgvSubsetSafe).
func StaticCommandSubsetReduction(input Input, facts Facts) (view Facts, partialArgv bool, ok bool) {
	return staticCommandSubset(input, facts, false)
}

// UnmodeledProgramArgvReduction returns a complete argv-only view of a
// partial POSIX action whose uncertainty includes a program with no modeled
// operand grammar, such as `hostname` or `terraform plan`. ActionFacts cannot
// say what such a program's operands mean, so the action stays partial, and
// a custom CEL rule about the program and its argv never ran: its regex
// pattern was used instead (GAP-0912). facts must be Analyze(input).
//
// The view keeps the commands StaticCommandSubsetReduction would keep, each
// reduced as its partial-argv commands are: only static argv words, effect
// execute, and no operations, wrappers, paths, network facts or data flows. A
// command whose every word is static keeps ArgvComplete, since its argv is
// exactly what runs. A caller may count a match on the view only for an
// expression that is semantic.Program.StaticArgvSubsetSafe; a non-match
// proves nothing.
func UnmodeledProgramArgvReduction(input Input, facts Facts) (Facts, bool) {
	view, _, ok := staticCommandSubset(input, facts, true)
	return view, ok
}

// staticCommandSubset is StaticCommandSubsetReduction, or with unmodeled
// set, UnmodeledProgramArgvReduction.
func staticCommandSubset(input Input, facts Facts, unmodeled bool) (view Facts, partialArgv bool, ok bool) {
	defer func() {
		if recover() != nil {
			view, partialArgv, ok = Facts{}, false, false
		}
	}()
	required := IssueDynamicWord
	if unmodeled {
		required = IssueUnknownOperandGrammar
	}
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPOSIX ||
		len(facts.Commands) == 0 || !containsIssue(facts.Parse.Issues, required) {
		return Facts{}, false, false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueDynamicWord && issue != IssueUnsupportedConstruct &&
			(!unmodeled || issue != IssueUnknownOperandGrammar) {
			return Facts{}, false, false
		}
	}
	_, capture := analyzeWithRedirectTargets(input, "")
	if definesFunction(capture.source) {
		return Facts{}, false, false
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
		static := keep(command, 0)
		if !static {
			parent, found := byID[command.ParentCommandID]
			if !partialArgvPOSIXProcess(command) ||
				(command.ParentCommandID != 0 && (!found || !keep(parent, 1))) {
				if shellStateBuiltins[strings.ToLower(command.Program)] {
					return Facts{}, false, false
				}
				continue
			}
		}
		redirects := make([]RedirectFact, 0, len(command.Redirects))
		for _, redirect := range command.Redirects {
			if !redirect.Expands && redirect.Target != "" {
				redirects = append(redirects, redirect)
			}
		}
		command.Redirects = redirects
		// As in ShortCircuitListReduction, a block stops the whole call, so
		// an && or || list member is judged as if it runs.
		command.ControlFlowUncertain = false
		command.ControlFlowOperator = ControlFlowOperatorNone
		if static && unmodeled {
			// The argv is exact; what the operands mean is not known.
			command.ArgvComplete = true
			command.Effect = EffectExecute
			command.Operations = nil
			command.Wrappers = nil
		} else if static {
			kept[command.ID] = true
			command.ArgvComplete = true
		} else {
			partialArgv = true
			argv := make([]string, 0, len(command.Argv))
			arguments := make([]ArgumentFact, 0, len(command.Arguments))
			for index, argument := range command.Arguments {
				if !argument.Expands && argument.StaticGlob == "" {
					argv = append(argv, command.Argv[index])
					arguments = append(arguments, argument)
				}
			}
			command.Argv, command.Arguments = argv, arguments
			command.ArgvComplete = false
			// It runs; what its effect is depends on the expanded words.
			command.Effect = EffectExecute
			command.Operations = nil
			command.Wrappers = nil
		}
		commands = append(commands, command)
	}
	if len(commands) == 0 {
		return Facts{}, false, false
	}
	if unmodeled {
		// Nothing but the commands and the files their static redirects
		// write: any other fact may rest on an operand grammar ActionFacts
		// does not have, but the shell opens a redirect target whatever the
		// program is, so `: > file` writes file (GAP-1344).
		return Facts{
			Tool:       facts.Tool,
			CWD:        facts.CWD,
			ActiveHome: facts.ActiveHome,
			Parse:      ParseResult{Status: StatusComplete, Dialect: facts.Parse.Dialect},
			Commands:   commands,
			Paths:      staticRedirectPaths(commands, facts.Paths),
		}, true, true
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
	return view, partialArgv, true
}

// staticRedirectPaths returns the path facts of paths that are the static
// redirect targets the view commands kept, with the redirect's access.
func staticRedirectPaths(commands []CommandFact, paths []PathFact) []PathFact {
	var kept []PathFact
	for _, path := range paths {
		for _, command := range commands {
			if command.ID == path.CommandID && slices.ContainsFunc(command.Redirects, func(redirect RedirectFact) bool {
				return redirect.Target == path.Value && redirect.Access == path.Access
			}) {
				kept = append(kept, path)
				break
			}
		}
	}
	return kept
}

// partialArgvPOSIXProcess reports whether command is a POSIX process that is
// certain to run, with a static program word that is not a shell builtin
// changing later commands, but with runtime-expanded or glob arguments.
func partialArgvPOSIXProcess(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		(command.Kind != CommandKindProcess && command.Kind != "") ||
		(command.Effect != EffectExecute && command.Effect != EffectUncertain) ||
		!certainOrListMember(command) || command.Background ||
		len(command.Argv) == 0 || command.Argv[0] == "" ||
		command.Executable == "" || command.Program == "" ||
		len(command.Arguments) != len(command.Argv) ||
		command.Arguments[0].Expands || command.Arguments[0].StaticGlob != "" ||
		shellStateBuiltins[strings.ToLower(command.Program)] {
		return false
	}
	for _, argument := range command.Arguments[1:] {
		if argument.Expands || argument.StaticGlob != "" {
			return true
		}
	}
	return false
}

// staticCertainPOSIXProcess reports whether command is a POSIX process that
// is certain to run, with a program and every argument static. Its
// ArgvComplete may still be false when only a redirect target expands.
func staticCertainPOSIXProcess(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		(command.Kind != CommandKindProcess && command.Kind != "") ||
		command.Effect != EffectExecute || !certainOrListMember(command) ||
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

// certainOrListMember reports whether command runs unconditionally or only
// as a member of a plain && or || list (`echo marker $USER && echo done`,
// `true && echo marker $USER`). A complete parse counts a match on such a
// list member too, so a runtime-expanded word elsewhere must not make the
// same match detection-only (GAP-0029). Commands under if, while, for, case,
// a function, a subshell, a negation or a mixed &&/|| list stay uncertain.
func certainOrListMember(command CommandFact) bool {
	return !command.ControlFlowUncertain ||
		command.ControlFlowOperator == ControlFlowOperatorAnd ||
		command.ControlFlowOperator == ControlFlowOperatorOr
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
