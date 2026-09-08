// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

const (
	macOSSoftwareUpdateActivateScript = `tell app "System Preferences" to activate`
	macOSSoftwareUpdatePromptScript   = `tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"`
	macOSSecurityUpdatePromptScript   = `display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer`
)

// classifyMacOSUpdateCredentialPrompt owns only the two closed AppleScript
// argv forms published by Atomic Red Team T1056.002. Generic osascript and
// generic hidden-answer dialogs deliberately remain unsupported.
func classifyMacOSUpdateCredentialPrompt(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if command.ArgvComplete && staticArguments(command.Arguments) &&
		exactFakeMacOSUpdateCredentialPromptArgv(command.Argv) {
		addOperation(command, OperationCredentialRead)
		return
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

// ExactFakeMacOSUpdateCredentialPrompt proves execution of one of the two
// exact fake-update credential dialogs from Atomic Red Team T1056.002. It
// accepts a direct invocation or the same invocation inside command
// substitution, as used by the source corpus to capture the submitted value.
// Pipelines, redirects, wrappers, conditional flow, dynamic argv, modified
// prompt text, and every other osascript program are rejected.
func ExactFakeMacOSUpdateCredentialPrompt(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if command.Program != "osascript" || command.Executable != "osascript" ||
			command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
			command.ControlFlowUncertain || command.PipelineID != 0 ||
			!command.ArgvComplete || !staticArguments(command.Arguments) ||
			len(command.Wrappers) != 0 || len(command.Redirects) != 0 ||
			!hasFactOperation(command, OperationCredentialRead) ||
			!exactFakeMacOSUpdateCredentialPromptArgv(command.Argv) {
			continue
		}
		if command.ParentCommandID == 0 ||
			hasCommandSubstitutionOutputFlow(facts, command.ID, command.ParentCommandID) {
			return true
		}
	}
	return false
}

func exactFakeMacOSUpdateCredentialPromptArgv(argv []string) bool {
	if len(argv) == 7 && argv[0] == "osascript" &&
		argv[1] == "-e" && argv[2] == macOSSoftwareUpdateActivateScript &&
		argv[3] == "-e" && argv[4] == macOSSoftwareUpdateActivateScript &&
		argv[5] == "-e" && argv[6] == macOSSoftwareUpdatePromptScript {
		return true
	}
	return len(argv) == 3 && argv[0] == "osascript" && argv[1] == "-e" &&
		argv[2] == macOSSecurityUpdatePromptScript
}

func hasCommandSubstitutionOutputFlow(facts Facts, sourceID, parentID int64) bool {
	if sourceID == 0 || parentID == 0 {
		return false
	}
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == sourceID && flow.ToCommandID == parentID &&
			flow.From == DataStdout && flow.To == DataProcess {
			return true
		}
	}
	return false
}
