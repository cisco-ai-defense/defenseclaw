// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// POSIXSystemInterpreterWrapperFact is a value-free proof marker. The exact
// paths and literal wrapper bytes are intentionally discarded after the
// same-action identity joins complete.
type POSIXSystemInterpreterWrapperFact struct{}

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

// ExactPOSIXSystemInterpreterWrapper proves that one POSIX action replaces a
// versioned system Python interpreter with a literal wrapper that injects one
// absolute PYTHONPATH entry and delegates every argument to the exact `.real`
// backup. It deliberately excludes unversioned interpreters, direct edits,
// arbitrary wrapper bodies, dynamic paths, pipelines, wrappers, and staged
// paths outside /usr/bin.
func ExactPOSIXSystemInterpreterWrapper(facts Facts) bool {
	return len(facts.POSIXSystemInterpreterWrappers) == 1
}

func projectPOSIXSystemInterpreterWrappers(facts Facts) []POSIXSystemInterpreterWrapperFact {
	if facts.Parse.Dialect != DialectPOSIX {
		return nil
	}
	for _, writer := range facts.Commands {
		target, stage, ok := exactVersionedPythonWrapperWrite(writer)
		if !ok || !hasExactVersionedPythonBackup(facts.Commands, target) ||
			!hasExactVersionedPythonReplacement(facts.Commands, stage, target) {
			continue
		}
		return []POSIXSystemInterpreterWrapperFact{{}}
	}
	return nil
}

func exactVersionedPythonWrapperWrite(command CommandFact) (string, string, bool) {
	if command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		command.Program != "cat" || !command.ArgvComplete ||
		!staticArguments(command.Arguments) || len(command.Redirects) != 1 ||
		command.Redirects[0].FD != 1 ||
		command.Redirects[0].Access != PathAccessWrite ||
		command.Redirects[0].Expands {
		return "", "", false
	}
	stage := command.Redirects[0].Target
	base := strings.TrimPrefix(stage, "/usr/bin/.")
	if base == stage || !strings.HasSuffix(base, ".wrap") {
		return "", "", false
	}
	base = strings.TrimSuffix(base, ".wrap")
	if !exactVersionedPythonBasename(base) {
		return "", "", false
	}
	target := "/usr/bin/" + base
	body, ok := StaticPOSIXCatLiteralStdinOutput(command)
	if !ok || !exactVersionedPythonWrapperBody(body, target) {
		return "", "", false
	}
	return target, stage, true
}

func exactVersionedPythonBasename(value string) bool {
	if !strings.HasPrefix(value, "python3.") || len(value) < len("python3.0") ||
		len(value) > len("python3.99") {
		return false
	}
	minor := strings.TrimPrefix(value, "python3.")
	for _, character := range minor {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func exactVersionedPythonWrapperBody(body, target string) bool {
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != 4 ||
		(lines[0] != "#!/bin/sh.real" && lines[0] != "#!/bin/bash.real") ||
		lines[2] != "export PYTHONPATH" ||
		lines[3] != "exec "+target+`.real "$@"` {
		return false
	}
	const inherited = `${PYTHONPATH:+:$PYTHONPATH}`
	if !strings.HasPrefix(lines[1], "PYTHONPATH=/") ||
		!strings.HasSuffix(lines[1], inherited) {
		return false
	}
	injected := strings.TrimSuffix(strings.TrimPrefix(lines[1], "PYTHONPATH="), inherited)
	return path.Clean(injected) == injected && injected != "/" &&
		!strings.ContainsAny(injected, " \t\r\n$`*?[]{};|&<>()\\\"")
}

func hasExactVersionedPythonBackup(commands []CommandFact, target string) bool {
	for _, command := range commands {
		if exactDirectStaticPOSIXCommand(command, true) && command.Program == "mv" &&
			len(command.Argv) == 3 && command.Argv[1] == target &&
			command.Argv[2] == target+".real" {
			return true
		}
	}
	return false
}

func hasExactVersionedPythonReplacement(commands []CommandFact, stage, target string) bool {
	for _, command := range commands {
		if exactDirectStaticPOSIXCommand(command, false) && command.Program == "mv" &&
			len(command.Argv) == 4 && command.Argv[1] == "-f" &&
			command.Argv[2] == stage && command.Argv[3] == target {
			return true
		}
	}
	return false
}
