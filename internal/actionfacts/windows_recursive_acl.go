// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// ExactWindowsRecursiveEveryoneFullControl proves one unconditional icacls
// invocation that recursively grants inheritable full control to Everyone.
// The proof intentionally rejects other principals, lesser rights, inherited-
// only ACEs, dynamic arguments, and non-recursive grants.
func ExactWindowsRecursiveEveryoneFullControl(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		(facts.Parse.Dialect != DialectCMD &&
			facts.Parse.Dialect != DialectPowerShell &&
			facts.Parse.Dialect != DialectArgv) ||
		len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || command.Effect != EffectExecute ||
		!command.ArgvComplete ||
		(command.Program != "icacls" && command.Program != "icacls.exe") ||
		!hasFactOperation(command, OperationPermissionChange) ||
		len(command.Arguments) < 5 {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" ||
			argument.Quote == QuoteMixed || strings.ContainsAny(argument.Value, "*?") {
			return false
		}
	}

	recursive := false
	grantSeen := false
	for index := 2; index < len(command.Argv); index++ {
		switch strings.ToLower(command.Argv[index]) {
		case "/grant", "/grant:r":
			if grantSeen || index+1 >= len(command.Argv) ||
				!exactEveryoneInheritableFullControlACE(command.Argv[index+1]) {
				return false
			}
			grantSeen = true
			index++
		case "/t":
			if recursive {
				return false
			}
			recursive = true
		case "/c", "/l", "/q":
			// These switches alter traversal/error handling, not the grant.
		default:
			return false
		}
	}
	return grantSeen && recursive
}

func exactEveryoneInheritableFullControlACE(value string) bool {
	const principal = "everyone:"
	value = strings.TrimSpace(value)
	if len(value) <= len(principal) || !strings.EqualFold(value[:len(principal)], principal) {
		return false
	}
	rights := value[len(principal):]
	seenOI := false
	seenCI := false
	for strings.HasPrefix(rights, "(") {
		end := strings.IndexByte(rights, ')')
		if end <= 1 {
			return false
		}
		switch strings.ToUpper(rights[1:end]) {
		case "OI":
			if seenOI {
				return false
			}
			seenOI = true
		case "CI":
			if seenCI {
				return false
			}
			seenCI = true
		default:
			// In particular, IO would apply the ACE only to descendants.
			return false
		}
		rights = rights[end+1:]
	}
	return seenOI && seenCI && strings.EqualFold(rights, "F")
}
