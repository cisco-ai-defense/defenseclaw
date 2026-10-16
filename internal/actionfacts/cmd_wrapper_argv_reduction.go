// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
)

// OpaqueCMDWrapperArgvReduction keeps the exact outer argv of a PowerShell
// call to cmd.exe /c whose unquoted body cannot be parsed as a complete child
// command. CMD AutoRun may execute before the body, so the full action stays
// partial. A caller may use only a positive, monotone match on this argv;
// absence of a match proves nothing about the child or AutoRun.
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
	if callOperatorCMD(commandText, facts) && len(input.Argv) == 0 {
		trimmed := strings.TrimLeftFunc(commandText, unicode.IsSpace)
		input.Command = strings.TrimLeftFunc(trimmed[1:], unicode.IsSpace)
		// The tool may have supplied its working directory inside Args.
		// Keep that verified context when dropping the original arguments.
		input.CWD = facts.CWD
		input.ActiveHome = facts.ActiveHome
		input.Args = nil
		facts = Analyze(input)
	}
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		len(facts.Commands) != 1 {
		return Facts{}, false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.Program != "cmd" ||
		(command.Executable != "cmd" && command.Executable != "cmd.exe") ||
		command.Dialect != DialectPowerShell || command.Background || command.ControlFlowUncertain ||
		!command.ArgvComplete || len(command.Argv) < 3 || len(command.Arguments) != len(command.Argv) {
		return Facts{}, false
	}
	commandSwitch := 1
	for commandSwitch < len(command.Argv) && staticCMDOption(command.Argv[commandSwitch]) {
		commandSwitch++
	}
	if commandSwitch+1 >= len(command.Argv) || !strings.EqualFold(command.Argv[commandSwitch], "/c") {
		return Facts{}, false
	}
	// A sole quoted /c body already has a complete argument boundary. The
	// ordinary wrapper analysis handles it, as before this reduction.
	if commandSwitch+2 == len(command.Argv) && command.Arguments[commandSwitch+1].Quote != QuoteNone {
		return Facts{}, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return Facts{}, false
		}
	}
	// Only the outer process and its argv are certain. Derived operations,
	// redirects and paths, and everything cmd.exe or AutoRun may run, are omitted.
	command.Operations = nil
	command.Redirects = nil
	command.Wrappers = nil
	return Facts{
		Tool: facts.Tool, CWD: facts.CWD, ActiveHome: facts.ActiveHome,
		Parse:    ParseResult{Status: StatusComplete, Dialect: DialectPowerShell},
		Commands: []CommandFact{command},
	}, true
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
	if !strings.HasPrefix(trimmed, "&") || len(trimmed) < 2 || !unicode.IsSpace(rune(trimmed[1])) {
		return false
	}
	return true
}
