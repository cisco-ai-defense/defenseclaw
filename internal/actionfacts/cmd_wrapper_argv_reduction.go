// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
)

// OpaqueCMDWrapperArgvReduction keeps the static argv of cmd.exe calls inside
// a PowerShell list, or of a cmd.exe call read in the CMD grammar itself (a
// Windows shell call whose first word is cmd.exe, GAP-1727). A single quoted
// /c or /r body is also parsed recursively as CMD, so a rule on the argv of
// the child can match it. CMD AutoRun and later statements may do more; only
// a positive monotone match on this view can authorize enforcement.
func OpaqueCMDWrapperArgvReduction(input Input, facts Facts) (Facts, bool) {
	// PowerShell permits a call operator before a bare executable, but the
	// general parser treats that form as an opaque expression. Reparse only
	// the static command after a leading call operator. Both parses must
	// describe one command, with no other uncertainty in the original.
	commandText := input.Command
	if commandText == "" && len(input.Args) > 0 {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if extracted.status == StatusComplete && len(extracted.argv) == 0 {
			commandText = extracted.command
		}
	}
	callOperator := callOperatorCMD(commandText, facts) && len(input.Argv) == 0
	if callOperator {
		trimmed := strings.TrimLeftFunc(commandText, unicode.IsSpace)
		input.Command = strings.TrimLeftFunc(trimmed[1:], unicode.IsSpace)
		// The tool may have supplied its working directory inside Args.
		// Keep that verified context when dropping the original arguments.
		input.CWD = facts.CWD
		input.ActiveHome = facts.ActiveHome
		input.Args = nil
		facts = Analyze(input)
	}
	// The outer grammar: PowerShell; CMD when the call itself was read as
	// CMD; or POSIX (Git Bash, or a generic Windows shell call read as POSIX)
	// under a Windows home. In CMD and POSIX, cmd.exe /c without /d stays
	// partial for AutoRun, so even a sole quoted body has no ordinary
	// projection of its child.
	outer := facts.Parse.Dialect
	outerOK := outer == DialectPowerShell || outer == DialectCMD ||
		outer == DialectPOSIX && trustedWindowsHomeLiteral.MatchString(strings.ReplaceAll(facts.ActiveHome, `\`, "/"))
	if facts.Parse.Status != StatusPartial || !outerOK ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		len(facts.Commands) == 0 || callOperator && len(facts.Commands) != 1 {
		return Facts{}, false
	}
	view := Facts{
		Tool: facts.Tool, CWD: facts.CWD, ActiveHome: facts.ActiveHome,
		Parse: ParseResult{Status: StatusComplete, Dialect: outer},
	}
	wrapped := false
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.Dialect != outer ||
			command.Background || command.ControlFlowUncertain || !command.ArgvComplete ||
			len(command.Arguments) != len(command.Argv) || len(command.Argv) == 0 {
			return Facts{}, false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || argument.StaticGlob != "" {
				return Facts{}, false
			}
		}
		if (command.Program != "cmd" && command.Program != "cmd.exe") ||
			(command.Executable != "cmd" && command.Executable != "cmd.exe") {
			command.Operations, command.Redirects, command.Wrappers = nil, nil, nil
			command.ID = int64(len(view.Commands) + 1)
			view.Commands = append(view.Commands, command)
			continue
		}
		bodyIndex, ok := cmdWrapperBodyIndex(command.Argv)
		if !ok || bodyIndex >= len(command.Argv) {
			return Facts{}, false
		}
		quotedBody := bodyIndex+1 == len(command.Argv) &&
			command.Arguments[bodyIndex].Quote != QuoteNone
		var inner Facts
		if quotedBody {
			// Parse the body in cmd.exe's dialect. A complete sole quoted
			// command has its ordinary projection; this view is for lists.
			innerInput := Input{
				Tool: "cmd", Command: command.Argv[bodyIndex],
				CWD: facts.CWD, ActiveHome: facts.ActiveHome, DialectHint: DialectCMD,
			}
			inner = Analyze(innerInput)
			if outer == DialectPowerShell && len(facts.Commands) == 1 && inner.EnforcementEligible() {
				return Facts{}, false
			}
		}
		wrapped = true
		command.Operations, command.Redirects, command.Wrappers = nil, nil, nil
		command.ID = int64(len(view.Commands) + 1)
		view.Commands = append(view.Commands, command)
		if !quotedBody {
			// The outer argv is still a positive monotone projection for
			// unquoted and cmd.exe double-quote spellings.
			continue
		}
		listPartial := inner.Parse.Status == StatusPartial &&
			len(inner.Parse.Issues) == 1 && inner.Parse.Issues[0] == IssueUnsupportedConstruct
		if (!inner.EnforcementEligible() && !listPartial) || len(inner.Commands) == 0 ||
			len(view.Commands)+len(inner.Commands) > maxCommands ||
			len(view.Paths)+len(inner.Paths) > maxPathFacts {
			return Facts{}, false
		}
		for _, child := range inner.Commands {
			if child.ParentCommandID != 0 || child.Dialect != DialectCMD ||
				child.Background || !child.ArgvComplete {
				return Facts{}, false
			}
			oldID := child.ID
			child.ID = int64(len(view.Commands) + 1)
			child.ParentCommandID = command.ID
			child.ControlFlowUncertain = false
			child.ControlFlowOperator = ControlFlowOperatorNone
			view.Commands = append(view.Commands, child)
			for _, path := range inner.Paths {
				if path.CommandID == oldID {
					path.CommandID = child.ID
					view.Paths = append(view.Paths, path)
				}
			}
		}
	}
	return view, wrapped
}

func cmdWrapperBodyIndex(argv []string) (int, bool) {
	for i := 1; i < len(argv); i++ {
		parts := strings.Split(strings.ToLower(argv[i]), "/")
		if len(parts) < 2 || parts[0] != "" {
			return 0, false
		}
		for partIndex, part := range parts[1:] {
			if part == "c" || part == "r" {
				if partIndex != len(parts)-2 {
					return 0, false
				}
				return i + 1, true
			}
			if !staticCMDOption("/" + part) {
				return 0, false
			}
		}
	}
	return 0, false
}

func staticCMDOption(value string) bool {
	switch strings.ToLower(value) {
	case "/d", "/q", "/s", "/a", "/u":
		return true
	}
	value = strings.ToLower(value)
	for _, prefix := range []string{"/e:", "/v:", "/f:"} {
		if strings.HasPrefix(value, prefix) {
			return value[len(prefix):] == "on" || value[len(prefix):] == "off"
		}
	}
	if !strings.HasPrefix(value, "/t:") || len(value) < 4 || len(value) > 5 {
		return false
	}
	for _, digit := range value[3:] {
		if digit < '0' || digit > '9' && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func callOperatorCMD(command string, facts Facts) bool {
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Parse.Issues) != 2 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		facts.Parse.Issues[1] != IssueDynamicWord || len(facts.Commands) != 1 {
		return false
	}
	opaque := facts.Commands[0]
	if opaque.ParentCommandID != 0 || opaque.Background || opaque.ControlFlowUncertain ||
		opaque.Program != "" || opaque.Executable != "" || opaque.Effect != EffectUncertain ||
		opaque.ArgvComplete || len(opaque.Argv) != 0 || len(opaque.Arguments) != 1 ||
		opaque.Arguments[0].Value != "&" || !opaque.Arguments[0].Expands {
		return false
	}
	trimmed := strings.TrimLeftFunc(command, unicode.IsSpace)
	if !strings.HasPrefix(trimmed, "&") || len(trimmed) < 2 {
		return false
	}
	if unicode.IsSpace(rune(trimmed[1])) {
		return true
	}
	// PowerShell also accepts the call operator adjacent to a fixed cmd
	// executable. Only that exact executable is eligible for this argv view;
	// a computed program word still has no monotone projection.
	space := strings.IndexFunc(trimmed[1:], unicode.IsSpace)
	if space <= 0 {
		return false
	}
	name := trimmed[1 : space+1]
	return strings.EqualFold(name, "cmd") || strings.EqualFold(name, "cmd.exe")
}
