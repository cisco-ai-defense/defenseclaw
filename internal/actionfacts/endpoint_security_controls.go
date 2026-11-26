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
	endpointStepFalconDisableNow = "falcon-disable-now"
	endpointStepSentinelDisable  = "sentinelone-disable"
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
	step, ok := exactEndpointSecurityArgvStep(*command, out.windowsHookHost)
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

func exactEndpointSecurityCommandStep(command CommandFact, windowsHookHost bool) (string, bool) {
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
	return exactEndpointSecurityArgvStep(command, windowsHookHost)
}

// exactEndpointSecurityArgvStep is the closed product step of one command.
// windowsHookHost says the call runs on a Windows host: there a POSIX shell
// (Git Bash, the Claude Code Bash tool) runs the native sc.exe for sc and
// sc.exe, as CMD and PowerShell do; elsewhere a POSIX sc is not the Windows
// service control program (rel-1-0-10:GAP-1656).
func exactEndpointSecurityArgvStep(command CommandFact, windowsHookHost bool) (string, bool) {
	switch command.Program {
	case "systemctl":
		if len(command.Argv) == 4 && command.Argv[1] == "disable" &&
			command.Argv[2] == "--now" &&
			(command.Argv[3] == "falcon-sensor" || command.Argv[3] == "falcon-sensor.service") {
			return endpointStepFalconDisableNow, true
		}
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
	case "sentinelctl":
		if command.Executable == "/opt/sentinelone/bin/sentinelctl" &&
			len(command.Argv) == 3 && command.Argv[1] == "control" &&
			command.Argv[2] == "disable" {
			return endpointStepSentinelDisable, true
		}
	case "sc", "sc.exe":
		if !windowsNativeExecutableDialect(command.Dialect) && command.Dialect != DialectArgv &&
			(command.Dialect != DialectPOSIX || !windowsHookHost) {
			return "", false
		}
		if len(command.Argv) < 3 || !strings.EqualFold(command.Argv[2], "WinDefend") {
			return "", false
		}
		switch {
		case len(command.Argv) == 3 && strings.EqualFold(command.Argv[1], "stop"):
			return endpointStepWinDefendStop, true
		case strings.EqualFold(command.Argv[1], "config") &&
			winDefendStartDisabled(command.Argv[3:]):
			return endpointStepWinDefendDisable, true
		case len(command.Argv) == 3 && strings.EqualFold(command.Argv[1], "query"):
			return endpointStepWinDefendQuery, true
		}
	}
	return "", false
}

// winDefendStartDisabled reports that the option words of an sc config are
// exactly the start type disabled: the documented two-word spelling
// "start= disabled" or the joined "start=disabled" (rel-1-0-10:GAP-1656).
func winDefendStartDisabled(words []string) bool {
	switch len(words) {
	case 1:
		return strings.EqualFold(words[0], "start=disabled")
	case 2:
		return strings.EqualFold(words[0], "start=") && strings.EqualFold(words[1], "disabled")
	}
	return false
}

// ExactEndpointSecurityProductDisable proves a source-supported,
// closed product operations: Falcon Sensor stop+disable, both Carbon Black
// launch daemons unloaded, Little Snitch unloaded, Sysmon uninstalled, or the
// exact WinDefend service stop, start-type disable, or stop+disable sequence
// followed by its read-only status query,
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
	case slices.Equal(steps, []string{endpointStepFalconDisableNow}):
		return true
	case slices.Equal(steps, []string{endpointStepSentinelDisable}):
		return true
	case slices.Equal(steps, []string{endpointStepWinDefendStop}),
		slices.Equal(steps, []string{endpointStepWinDefendDisable}):
		// A lone bare sc in Windows PowerShell 5.1 is Set-Content. Keep the
		// older multi-command fixture's classification, but a single stop or
		// start-type disable proves the service operation only for sc.exe, or
		// for the bare sc of CMD or of a POSIX shell on a Windows host, the
		// only POSIX reading whose step matches (rel-1-0-10:GAP-1656).
		for _, command := range facts.Commands {
			if command.ParentCommandID == 0 {
				return command.Program == "sc.exe" || command.Dialect == DialectCMD ||
					command.Dialect == DialectPOSIX
			}
		}
		return false
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

// WinDefendSequenceUnproved reports that an action holds more than one
// top-level WinDefend sc step and an sc config of the WinDefend start type,
// but the steps are not an exact WinDefend disable. The closed sequence proof
// owns such a call: a per-command reading of its stop or its start-type
// disable must not prove a disable that the whole sequence does not
// (rel-1-0-10:GAP-1194, GAP-1656), and a stop beside a start-type restore
// (start= auto) is no disable. A call with no start-type config is not a
// partial disable sequence: its WinDefend stop keeps the finding it proves
// alone, as the PowerShell reading of the same steps does
// (rel-1-0-10:GAP-1313).
func WinDefendSequenceUnproved(facts Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	winDefendSteps, startTypeConfig := 0, false
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		if winDefendStartTypeConfig(command) {
			startTypeConfig = true
		}
		if step, ok := exactEndpointSecurityTopLevelStep(facts, command); ok && isWinDefendStep(step) {
			winDefendSteps++
		}
	}
	return winDefendSteps > 1 && startTypeConfig && !ExactEndpointSecurityProductDisable(facts)
}

// winDefendStartTypeConfig reports an sc config of the WinDefend service,
// whatever start type it sets: the step of a disable or of a restore.
func winDefendStartTypeConfig(command CommandFact) bool {
	if command.Program != "sc" && command.Program != "sc.exe" {
		return false
	}
	return len(command.Argv) >= 3 && strings.EqualFold(command.Argv[1], "config") &&
		strings.EqualFold(command.Argv[2], "WinDefend")
}

// ExactWinDefendSingleStep reports that the action is exactly one WinDefend
// service stop or start-type disable that
// ExactEndpointSecurityProductDisable proves.
func ExactWinDefendSingleStep(facts Facts) bool {
	if !ExactEndpointSecurityProductDisable(facts) {
		return false
	}
	single := false
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		if single {
			return false
		}
		step, ok := exactEndpointSecurityTopLevelStep(facts, command)
		if !ok || step != endpointStepWinDefendStop && step != endpointStepWinDefendDisable {
			return false
		}
		single = true
	}
	return single
}

func isWinDefendStep(step string) bool {
	switch step {
	case endpointStepWinDefendStop, endpointStepWinDefendDisable, endpointStepWinDefendQuery:
		return true
	}
	return false
}

func exactEndpointSecurityTopLevelStep(facts Facts, command CommandFact) (string, bool) {
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	if command.Program != "sudo" {
		return exactEndpointSecurityCommandStep(command, facts.windowsHookHost)
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
		step, ok := exactEndpointSecurityCommandStep(child, facts.windowsHookHost)
		if !ok {
			return "", false
		}
		matched = step
	}
	return matched, matched != ""
}
