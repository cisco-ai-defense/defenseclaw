// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// ExactPOSIXNestedChrootUnrestrictedSudoersGrant proves the narrowly reviewed
// container-escape form that enters a literal temporary root and runs exactly
// one /bin/bash -c child which replaces one direct /etc/sudoers.d entry with a
// static, unrestricted passwordless grant for a non-root principal.
//
// The generic POSIX projection intentionally does not carry child filesystem
// paths across a chroot boundary. This proof preserves that invariant: it
// re-parses only the single authenticated child string, at one bounded shell
// level, and does not publish its root-relative path as a host path fact.
func ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts Facts) bool {
	if (facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv) ||
		facts.Parse.Status != StatusPartial || len(facts.Parse.Issues) != 1 ||
		facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		len(facts.Commands) != 1 {
		return false
	}

	outer := facts.Commands[0]
	if !exactUnconditionalTopLevelCommand(outer) || !outer.ArgvComplete ||
		outer.ControlFlowOperator != ControlFlowOperatorNone ||
		outer.Program != "chroot" || !exactCaseSensitivePOSIXProgram(&outer, "chroot") ||
		len(outer.Argv) != 5 || len(outer.Arguments) != len(outer.Argv) ||
		!staticArguments(outer.Arguments) {
		return false
	}
	for _, argument := range outer.Arguments {
		if argument.Quote == QuoteMixed || argument.Value == "" {
			return false
		}
	}

	invocation := parseChrootInvocation(outer.Argv)
	if !invocation.complete || invocation.preview || invocation.childIndex != 2 ||
		invocation.root != outer.Argv[1] || !exactTemporaryChrootRoot(invocation.root) ||
		outer.Argv[2] != "/bin/bash" || outer.Argv[3] != "-c" ||
		strings.TrimSpace(outer.Argv[4]) != outer.Argv[4] {
		return false
	}

	shell := parsePOSIXShellInvocation("bash", outer.Argv[2:])
	if !shell.valid || shell.interactive || shell.noExec ||
		shell.mode != posixShellModeCommand || shell.commandIndex != 2 {
		return false
	}

	// Start at the package wrapper bound so a second shell/interpreter wrapper
	// cannot be expanded. A direct printf remains fully representable.
	child := parsePOSIX(outer.Argv[4], 1, maxWrapperDepth)
	classifyOutput(&child)
	enforceAnalyzeAuthority(&child)
	if child.status != StatusComplete || len(child.issues) != 0 ||
		len(child.commands) != 1 {
		return false
	}
	return exactChrootSudoersPrintf(child.commands[0])
}

func exactTemporaryChrootRoot(value string) bool {
	if !staticAbsolutePOSIXPath(value) || path.Clean(value) != value ||
		strings.ContainsAny(value, "\x00\r\n\t") {
		return false
	}
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}

func exactChrootSudoersPrintf(command CommandFact) bool {
	if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
		command.PipelineID != 0 ||
		(command.Kind != "" && command.Kind != CommandKindProcess) ||
		command.Effect != EffectExecute || len(command.Wrappers) != 0 ||
		!command.ArgvComplete ||
		command.ControlFlowOperator != ControlFlowOperatorNone ||
		command.Program != "printf" || len(command.Arguments) != len(command.Argv) ||
		!staticArguments(command.Arguments) || len(command.Redirects) != 1 {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return false
		}
	}

	redirect := command.Redirects[0]
	if redirect.FD != 1 || redirect.Access != PathAccessWrite || redirect.Expands ||
		!exactDirectSudoersDropIn(redirect.Target) {
		return false
	}

	// The existing printf projector accepts only unredirected commands because
	// its other callers reason about stdout flow. The sole redirect was proven
	// above, so remove it only from this local copy to recover the exact bytes.
	command.Redirects = nil
	segments := StaticPOSIXPrintfFormatStdoutSegments(command)
	if len(segments) != 1 || !segments[0].LeftExact || !segments[0].RightExact {
		return false
	}
	line := strings.TrimSuffix(segments[0].Value, "\n")
	if strings.ContainsAny(line, "\r\n") ||
		!exactUnrestrictedSudoersGrantLine.MatchString(line) {
		return false
	}
	fields := strings.Fields(line)
	return len(fields) > 1 && fields[0] != "root" && fields[0] != "%root" &&
		fields[0] != "ALL"
}

func exactDirectSudoersDropIn(value string) bool {
	const prefix = "/etc/sudoers.d/"
	name := strings.TrimPrefix(value, prefix)
	if name == value || name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') {
		return false
	}
	for _, char := range name {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '_' || char == '.' || char == '-' {
			continue
		}
		return false
	}
	return true
}
