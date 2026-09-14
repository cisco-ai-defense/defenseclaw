// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// POSIXLiteralPasswordChangeForm identifies one source-supported, closed
// pipeline shape. It deliberately distinguishes unattended password-change
// automation from the anomalous trailing-shell form found in attack telemetry.
type POSIXLiteralPasswordChangeForm string

const (
	POSIXLiteralPasswordChangeTwoStageAutomation      POSIXLiteralPasswordChangeForm = "two_stage_automation"
	POSIXLiteralPasswordChangeThreeStageTrailingShell POSIXLiteralPasswordChangeForm = "three_stage_trailing_shell"
)

// POSIXLiteralPasswordChangeOutcome is trusted result context supplied by a
// connector. Command text never proves that a password mutation succeeded.
type POSIXLiteralPasswordChangeOutcome string

const (
	POSIXLiteralPasswordChangeOutcomeUnknown   POSIXLiteralPasswordChangeOutcome = "unknown"
	POSIXLiteralPasswordChangeOutcomeSucceeded POSIXLiteralPasswordChangeOutcome = "succeeded"
	POSIXLiteralPasswordChangeOutcomeFailed    POSIXLiteralPasswordChangeOutcome = "failed"
)

// POSIXLiteralPasswordChangeFact is a value-free proof. The account and
// password literals are discarded; only the sink command and closed form are
// retained for bounded policy or result-aware chain evaluation.
type POSIXLiteralPasswordChangeFact struct {
	CommandID int64
	Form      POSIXLiteralPasswordChangeForm
}

// ExactPOSIXLiteralPasswordChange reports a completed password mutation only
// when the entire action is authoritative, the connector reports success, and
// every command belongs to one of the source-supported literal pipeline
// grammars. It never treats generic passwd/chpasswd use as proof.
func ExactPOSIXLiteralPasswordChange(
	facts Facts,
	outcome POSIXLiteralPasswordChangeOutcome,
) (POSIXLiteralPasswordChangeFact, bool) {
	if outcome != POSIXLiteralPasswordChangeOutcomeSucceeded ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return POSIXLiteralPasswordChangeFact{}, false
	}
	fact, ok := exactPOSIXLiteralPasswordChangePipeline(
		facts.Commands,
		facts.DataFlows,
	)
	if !ok {
		return POSIXLiteralPasswordChangeFact{}, false
	}
	for _, command := range facts.Commands {
		if command.ID == fact.CommandID &&
			hasFactOperation(command, OperationAccountChange) {
			return fact, true
		}
	}
	return POSIXLiteralPasswordChangeFact{}, false
}

// ExactPOSIXLiteralPasswordChangeTrailingShell reports only the exact
// three-stage literal password-change pipeline whose final command is a bare
// Bash process. It is a value-free command-shape predicate for pre-execution
// policy: account and password operands are validated and then discarded.
// Ordinary two-stage password-change automation is deliberately excluded.
func ExactPOSIXLiteralPasswordChangeTrailingShell(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	fact, ok := exactPOSIXLiteralPasswordChangePipeline(
		facts.Commands, facts.DataFlows,
	)
	return ok && fact.Form == POSIXLiteralPasswordChangeThreeStageTrailingShell
}

func preclassifyPOSIXLiteralPasswordChange(out *parseOutput) {
	if out == nil {
		return
	}
	fact, ok := exactPOSIXLiteralPasswordChangePipeline(out.commands, out.dataFlows)
	if !ok {
		return
	}
	for index := range out.commands {
		if out.commands[index].ID == fact.CommandID {
			addOperation(&out.commands[index], OperationAccountChange)
			return
		}
	}
}

func classifyPOSIXLiteralPasswordChange(
	out *parseOutput,
	command *CommandFact,
) {
	if out == nil || command == nil || command.Dialect != DialectPOSIX {
		if out != nil {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if exactPOSIXPasswordToolPreview(*command) {
		command.Effect = EffectPreview
		return
	}
	if hasFactOperation(*command, OperationAccountChange) {
		return
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

func exactPOSIXLiteralPasswordChangeTrailingShell(
	out *parseOutput,
	command *CommandFact,
) bool {
	if out == nil || command == nil || command.Program != "bash" {
		return false
	}
	fact, ok := exactPOSIXLiteralPasswordChangePipeline(
		out.commands,
		out.dataFlows,
	)
	return ok &&
		fact.Form == POSIXLiteralPasswordChangeThreeStageTrailingShell &&
		len(out.commands) == 3 && out.commands[2].ID == command.ID
}

func exactPOSIXLiteralPasswordChangePipeline(
	commands []CommandFact,
	flows []DataFlowFact,
) (POSIXLiteralPasswordChangeFact, bool) {
	if len(commands) != 2 && len(commands) != 3 {
		return POSIXLiteralPasswordChangeFact{}, false
	}
	for index := range commands {
		if !exactPOSIXLiteralPasswordPipelineCommand(commands[index]) {
			return POSIXLiteralPasswordChangeFact{}, false
		}
	}
	source, sink := commands[0], commands[1]
	if source.Program != "echo" ||
		(sink.Program != "passwd" && sink.Program != "chpasswd") ||
		source.PipelineID == 0 || sink.PipelineID != source.PipelineID ||
		!exactPOSIXLiteralPasswordSource(source, sink.Program) ||
		len(sink.Argv) != 1 {
		return POSIXLiteralPasswordChangeFact{}, false
	}

	form := POSIXLiteralPasswordChangeTwoStageAutomation
	if len(commands) == 2 {
		// The mined two-stage family uses passwd exclusively. Keeping chpasswd
		// out avoids turning every ordinary chpasswd automation into this proof.
		if sink.Program != "passwd" {
			return POSIXLiteralPasswordChangeFact{}, false
		}
	} else {
		shell := commands[2]
		if shell.Program != "bash" || len(shell.Argv) != 1 ||
			shell.PipelineID != source.PipelineID {
			return POSIXLiteralPasswordChangeFact{}, false
		}
		form = POSIXLiteralPasswordChangeThreeStageTrailingShell
	}
	if !exactPOSIXLiteralPasswordPipelineFlows(commands, flows) {
		return POSIXLiteralPasswordChangeFact{}, false
	}
	return POSIXLiteralPasswordChangeFact{
		CommandID: sink.ID,
		Form:      form,
	}, true
}

func exactPOSIXLiteralPasswordPipelineCommand(command CommandFact) bool {
	if command.ID == 0 || command.Dialect != DialectPOSIX ||
		command.ParentCommandID != 0 || command.PipelineID == 0 ||
		command.ControlFlowUncertain || command.Background ||
		(command.Kind != "" && command.Kind != CommandKindProcess) ||
		command.Effect != EffectExecute ||
		!command.ArgvComplete || len(command.Argv) != len(command.Arguments) ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		!staticArguments(command.Arguments) || command.Program == "" ||
		command.Executable != command.Program || command.Argv[0] != command.Program {
		return false
	}
	switch command.Program {
	case "echo", "passwd", "chpasswd", "bash":
		return true
	default:
		return false
	}
}

func exactPOSIXLiteralPasswordPipelineFlows(
	commands []CommandFact,
	flows []DataFlowFact,
) bool {
	if len(flows) != len(commands)-1 {
		return false
	}
	for index, flow := range flows {
		if flow.FromCommandID != commands[index].ID ||
			flow.ToCommandID != commands[index+1].ID ||
			flow.From != DataStdout || flow.To != DataStdin {
			return false
		}
	}
	return true
}

func exactPOSIXLiteralPasswordSource(
	source CommandFact,
	sinkProgram string,
) bool {
	switch sinkProgram {
	case "passwd":
		return exactPOSIXPasswdEchoTuple(source)
	case "chpasswd":
		return exactPOSIXChpasswdEchoTuple(source)
	default:
		return false
	}
}

func exactPOSIXPasswdEchoTuple(command CommandFact) bool {
	var payload string
	switch {
	case len(command.Argv) == 3 && command.Argv[1] == "-e" &&
		command.Arguments[2].Quote == QuoteDouble:
		payload = command.Argv[2]
		if strings.HasSuffix(payload, `\n`) {
			return false
		}
	case len(command.Argv) == 2 && command.Arguments[1].Quote == QuoteDouble:
		payload = command.Argv[1]
		if !strings.HasSuffix(payload, `\n`) {
			return false
		}
		payload = strings.TrimSuffix(payload, `\n`)
	default:
		return false
	}
	if strings.ContainsAny(payload, "\r\n") {
		return false
	}
	fields := strings.Split(payload, `\n`)
	return len(fields) == 3 && staticAccountOperand(fields[0]) &&
		exactPOSIXLiteralPasswordValue(fields[1]) && fields[1] == fields[2]
}

func exactPOSIXChpasswdEchoTuple(command CommandFact) bool {
	if len(command.Argv) != 2 || command.Arguments[1].Quote != QuoteDouble ||
		strings.ContainsAny(command.Argv[1], "\r\n") {
		return false
	}
	account, password, found := strings.Cut(command.Argv[1], ":")
	return found && !strings.Contains(password, ":") &&
		staticAccountOperand(account) && exactPOSIXLiteralPasswordValue(password)
}

func exactPOSIXLiteralPasswordValue(value string) bool {
	return value != "" && len(value) <= 1024 &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func exactPOSIXPasswordToolPreview(command CommandFact) bool {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || command.Background ||
		(command.Kind != "" && command.Kind != CommandKindProcess) ||
		!command.ArgvComplete ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		command.Executable != command.Program {
		return false
	}
	switch command.Program {
	case "passwd":
		if len(command.Argv) == 2 &&
			(command.Argv[1] == "--help" || command.Argv[1] == "--version") {
			return true
		}
		return (len(command.Argv) == 2 || len(command.Argv) == 3) &&
			(command.Argv[1] == "-S" || command.Argv[1] == "--status") &&
			(len(command.Argv) == 2 || staticAccountOperand(command.Argv[2]))
	case "chpasswd":
		return len(command.Argv) == 2 &&
			(command.Argv[1] == "-h" || command.Argv[1] == "--help" ||
				command.Argv[1] == "-V" || command.Argv[1] == "--version")
	default:
		return false
	}
}
