// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
)

const (
	endpointStepFalconStop       = "falcon-stop"
	endpointStepFalconDisable    = "falcon-disable"
	endpointStepCarbonBlackCore  = "carbon-black-core-unload"
	endpointStepCarbonBlackEDR   = "carbon-black-edr-unload"
	endpointStepLittleSnitch     = "little-snitch-unload"
	endpointStepSysmonUninstall  = "sysmon-uninstall"
	endpointStepMDATPDisable     = "mdatp-realtime-disable"
	endpointStepWinDefendStop    = "windefend-stop"
	endpointStepWinDefendDisable = "windefend-disable"
	endpointStepWinDefendQuery   = "windefend-query"
)

// classifyEndpointSecurityControl adds security semantics only to one exact,
// product-identified service or agent operation. Sequence completeness remains
// owned by ExactEndpointSecurityProductDisable; this hook only makes the closed
// command grammar available to CEL.
func classifyEndpointSecurityControl(out *parseOutput, command *CommandFact) bool {
	if command == nil || !staticArguments(command.Arguments) {
		return false
	}
	step, ok := exactEndpointSecurityArgvStep(*command)
	if !ok {
		return false
	}
	if step == endpointStepWinDefendQuery {
		addOperation(command, OperationList)
		return true
	}
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

func exactEndpointSecurityCommandStep(command CommandFact) (string, bool) {
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
	return exactEndpointSecurityArgvStep(command)
}

func exactEndpointSecurityArgvStep(command CommandFact) (string, bool) {
	switch command.Program {
	case "systemctl":
		if len(command.Argv) != 3 || command.Argv[2] != "falcon-sensor.service" {
			return "", false
		}
		switch command.Argv[1] {
		case "stop":
			return endpointStepFalconStop, true
		case "disable":
			return endpointStepFalconDisable, true
		}
	case "launchctl":
		if len(command.Argv) != 3 || command.Argv[1] != "unload" {
			return "", false
		}
		switch command.Argv[2] {
		case "/Library/LaunchDaemons/com.carbonblack.daemon.plist":
			return endpointStepCarbonBlackCore, true
		case "/Library/LaunchDaemons/com.carbonblack.defense.daemon.plist":
			return endpointStepCarbonBlackEDR, true
		case "/Library/LaunchDaemons/at.obdev.littlesnitchd.plist":
			return endpointStepLittleSnitch, true
		}
	case "sysmon", "sysmon.exe":
		if len(command.Argv) == 2 && command.Argv[1] == "-u" {
			return endpointStepSysmonUninstall, true
		}
	case "mdatp":
		if slices.Equal(command.Argv, []string{
			"mdatp", "config", "real-time-protection", "--value", "disabled",
		}) {
			return endpointStepMDATPDisable, true
		}
	case "sc", "sc.exe":
		if command.Dialect != DialectCMD && command.Dialect != DialectArgv {
			return "", false
		}
		if len(command.Argv) < 3 || !strings.EqualFold(command.Argv[2], "WinDefend") {
			return "", false
		}
		switch {
		case len(command.Argv) == 3 && strings.EqualFold(command.Argv[1], "stop"):
			return endpointStepWinDefendStop, true
		case len(command.Argv) == 4 && strings.EqualFold(command.Argv[1], "config") &&
			strings.EqualFold(command.Argv[3], "start=disabled"):
			return endpointStepWinDefendDisable, true
		case len(command.Argv) == 3 && strings.EqualFold(command.Argv[1], "query"):
			return endpointStepWinDefendQuery, true
		}
	}
	return "", false
}

// ExactEndpointSecurityProductDisable proves one of six source-supported,
// closed product operations: Falcon Sensor stop+disable, both Carbon Black
// launch daemons unloaded, Little Snitch unloaded, Sysmon uninstalled, or the
// exact WinDefend stop+disable sequence followed by its read-only status query,
// or an exact Microsoft Defender for Endpoint real-time protection disable.
// Every top-level invocation must belong to the selected proof; unrelated
// commands, dynamic operands, wrappers other than a literal sudo, pipelines,
// redirects, and conditional execution are rejected.
func ExactEndpointSecurityProductDisable(facts Facts) bool {
	if !facts.Authoritative() || len(facts.Commands) == 0 {
		return false
	}
	steps := make([]string, 0, 3)
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		step, ok := exactEndpointSecurityTopLevelStep(facts, command)
		if !ok {
			return false
		}
		steps = append(steps, step)
	}
	switch {
	case slices.Equal(steps, []string{endpointStepFalconStop, endpointStepFalconDisable}):
		return true
	case slices.Equal(steps, []string{endpointStepCarbonBlackCore, endpointStepCarbonBlackEDR}):
		return true
	case slices.Equal(steps, []string{endpointStepLittleSnitch}):
		return true
	case slices.Equal(steps, []string{endpointStepSysmonUninstall}):
		return true
	case slices.Equal(steps, []string{endpointStepMDATPDisable}):
		return true
	case slices.Equal(steps, []string{
		endpointStepWinDefendStop,
		endpointStepWinDefendDisable,
		endpointStepWinDefendQuery,
	}):
		return true
	default:
		return false
	}
}

func exactEndpointSecurityTopLevelStep(facts Facts, command CommandFact) (string, bool) {
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	if command.Program != "sudo" {
		return exactEndpointSecurityCommandStep(command)
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
		step, ok := exactEndpointSecurityCommandStep(child)
		if !ok {
			return "", false
		}
		matched = step
	}
	return matched, matched != ""
}
