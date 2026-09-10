// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "slices"

const (
	firewallStepFlushAll      = "flush-all"
	firewallStepFlushInput    = "flush-input"
	firewallStepAcceptInput   = "accept-input"
	firewallStepAcceptForward = "accept-forward"
	firewallStepAcceptOutput  = "accept-output"
)

// classifyCompleteFirewallRelaxationStep projects only the literal iptables
// argv forms used by ExactCompleteFirewallRelaxation. Sequence completeness is
// deliberately owned by that bounded prerequisite rather than inferred from a
// single permissive firewall operation.
func classifyCompleteFirewallRelaxationStep(out *parseOutput, command *CommandFact) bool {
	if command == nil || !staticArguments(command.Arguments) {
		return false
	}
	if _, ok := exactFirewallRelaxationArgvStep(*command); !ok {
		return false
	}
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

func exactFirewallRelaxationArgvStep(command CommandFact) (string, bool) {
	if command.Program != "iptables" {
		return "", false
	}
	switch {
	case slices.Equal(command.Argv, []string{"iptables", "-F"}):
		return firewallStepFlushAll, true
	case slices.Equal(command.Argv, []string{"iptables", "-F", "INPUT"}):
		return firewallStepFlushInput, true
	case slices.Equal(command.Argv, []string{"iptables", "-P", "INPUT", "ACCEPT"}):
		return firewallStepAcceptInput, true
	case slices.Equal(command.Argv, []string{"iptables", "-P", "FORWARD", "ACCEPT"}):
		return firewallStepAcceptForward, true
	case slices.Equal(command.Argv, []string{"iptables", "-P", "OUTPUT", "ACCEPT"}):
		return firewallStepAcceptOutput, true
	default:
		return "", false
	}
}

func exactFirewallRelaxationCommandStep(command CommandFact) (string, bool) {
	if command.ControlFlowUncertain || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		!command.ArgvComplete || len(command.Redirects) != 0 ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return "", false
		}
	}
	return exactFirewallRelaxationArgvStep(command)
}

// ExactCompleteFirewallRelaxation proves one complete, static iptables action:
// either flush INPUT (or all chains) followed by setting INPUT's default policy
// to ACCEPT, or setting INPUT, FORWARD, and OUTPUT default policies to ACCEPT in
// that order. Every top-level command must be part of the proof. This excludes
// partial/reordered sequences, dynamic operands, shell control flow, pipelines,
// redirects, script-text writes, unrelated commands, and wrappers other than a
// literal option-free sudo.
func ExactCompleteFirewallRelaxation(facts Facts) bool {
	if !facts.Authoritative() || len(facts.Commands) == 0 {
		return false
	}
	steps := make([]string, 0, 3)
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		step, ok := exactFirewallRelaxationTopLevelStep(facts, command)
		if !ok {
			return false
		}
		steps = append(steps, step)
	}
	return slices.Equal(steps, []string{firewallStepFlushAll, firewallStepAcceptInput}) ||
		slices.Equal(steps, []string{firewallStepFlushInput, firewallStepAcceptInput}) ||
		slices.Equal(steps, []string{
			firewallStepAcceptInput,
			firewallStepAcceptForward,
			firewallStepAcceptOutput,
		})
}

func exactFirewallRelaxationTopLevelStep(facts Facts, command CommandFact) (string, bool) {
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	if command.Program != "sudo" {
		return exactFirewallRelaxationCommandStep(command)
	}
	if len(command.Argv) < 2 {
		return "", false
	}
	var matched string
	for _, child := range facts.Commands {
		if child.ParentCommandID != command.ID {
			continue
		}
		if matched != "" || len(child.Wrappers) != 1 ||
			child.Wrappers[0].Executable != "sudo" ||
			!slices.Equal(command.Argv[1:], child.Argv) {
			return "", false
		}
		step, ok := exactFirewallRelaxationCommandStep(child)
		if !ok {
			return "", false
		}
		matched = step
	}
	return matched, matched != ""
}
