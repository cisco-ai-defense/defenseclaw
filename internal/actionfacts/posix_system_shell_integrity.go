// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// ExactPOSIXSystemShellReplacement proves that a direct static command replaces
// dash with Bash. This deliberately recognizes only
// the concrete binary-hijack family observed in execution-backed Terminal
// Wrench trajectories. Package-manager operations, arbitrary system binaries,
// dynamic operands, wrappers, pipelines, and unrelated shell links abstain.
func ExactPOSIXSystemShellReplacement(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		(facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv) {
		return false
	}
	for _, command := range facts.Commands {
		if exactUnconditionalPOSIXSystemShellReplacement(command) {
			return true
		}
	}
	return false
}

func exactUnconditionalPOSIXSystemShellReplacement(command CommandFact) bool {
	return exactDirectStaticPOSIXCommand(command, false) &&
		exactPOSIXSystemShellReplacementArgv(command.Program, command.Argv)
}

func exactDirectStaticPOSIXCommand(command CommandFact, allowConditional bool) bool {
	return command.Kind == CommandKindProcess && command.Effect == EffectExecute &&
		command.ParentCommandID == 0 && command.PipelineID == 0 &&
		len(command.Wrappers) == 0 && len(command.Redirects) == 0 &&
		command.ArgvComplete && staticArguments(command.Arguments) &&
		(allowConditional || !command.ControlFlowUncertain)
}

func exactPOSIXSystemShellReplacementArgv(program string, argv []string) bool {
	return program == "cp" && len(argv) == 3 && exactBashOverDash(argv[1], argv[2])
}

func exactBashOverDash(source, target string) bool {
	if source != "/bin/bash" && source != "/usr/bin/bash" {
		return false
	}
	switch target {
	case "/bin/dash", "/usr/bin/dash":
		return true
	default:
		return false
	}
}
