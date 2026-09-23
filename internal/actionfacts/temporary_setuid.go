// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strconv"
	"strings"
)

// ExactTemporarySetuidExecutable proves one literal chmod that adds the
// set-user-ID bit and at least one executable bit to exactly one absolute file
// below a host temporary directory. Accepted wrappers are literal option-free
// sudo and an exact root-defaulting `su -c` script. Setgid-only modes,
// directories themselves, multiple or dynamic targets, recursive changes,
// non-root su users, and non-temporary paths are excluded.
func ExactTemporarySetuidExecutable(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if !exactTemporarySetuidCommand(command) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if exactRootSuCommandWrapper(facts, command) {
			return true
		}
		if len(command.Wrappers) != 1 || command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" ||
				len(parent.Argv) != len(command.Argv)+1 ||
				!slices.Equal(parent.Argv[1:], command.Argv) {
				continue
			}
			return true
		}
	}
	return false
}

func exactRootSuCommandWrapper(facts Facts, command CommandFact) bool {
	if len(command.Wrappers) != 1 || command.ParentCommandID == 0 {
		return false
	}
	wrapper := command.Wrappers[0]
	if wrapper.Executable != "su" && wrapper.Executable != "/bin/su" &&
		wrapper.Executable != "/usr/bin/su" {
		return false
	}
	for _, parent := range facts.Commands {
		_, exactRootCommand := exactRootSuCommand(parent)
		if parent.ID != command.ParentCommandID ||
			!exactUnconditionalTopLevelCommand(parent) || !exactRootCommand ||
			len(parent.Redirects) != 0 ||
			!slices.Equal(wrapper.Argv, parent.Argv) {
			continue
		}
		return true
	}
	return false
}

func exactTemporarySetuidCommand(command CommandFact) bool {
	if command.ControlFlowUncertain || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		command.Program != "chmod" || !command.ArgvComplete ||
		len(command.Redirects) != 0 || !staticArguments(command.Arguments) ||
		!hasFactOperation(command, OperationPermissionChange) {
		return false
	}
	argv := command.Argv
	if len(argv) == 4 && argv[1] == "--" {
		argv = append([]string{argv[0]}, argv[2:]...)
	}
	if len(argv) != 3 {
		return false
	}
	mode, err := strconv.ParseUint(argv[1], 8, 16)
	if err != nil || mode&04000 == 0 || mode&0111 == 0 {
		return false
	}
	return exactTemporaryExecutablePath(argv[2])
}

func exactTemporaryExecutablePath(value string) bool {
	if !staticAbsolutePOSIXPath(value) || path.Clean(value) != value {
		return false
	}
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if strings.HasPrefix(value, root+"/") && value != root+"/" {
			return true
		}
	}
	return false
}
