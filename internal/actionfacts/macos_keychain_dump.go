// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// ExactMacOSLoginKeychainDump proves the closed Atomic Red Team T1555.001
// command that requests decrypted entries from the login keychain. It accepts
// only a direct invocation or the same literal argv through option-free sudo.
// Keychain listing, certificate export, ordinary item lookup, dynamic targets,
// pipelines, redirects, conditional flow, and additional arguments abstain.
func ExactMacOSLoginKeychainDump(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if command.Program != "security" || command.Executable != "security" ||
			command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
			command.ControlFlowUncertain || command.PipelineID != 0 ||
			!command.ArgvComplete || !staticArguments(command.Arguments) ||
			len(command.Redirects) != 0 ||
			!hasFactOperation(command, OperationCredentialRead) ||
			!exactMacOSLoginKeychainDumpArgv(command.Argv) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if len(command.Wrappers) != 1 || command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" || len(parent.Argv) != 5 ||
				parent.Argv[1] != "security" ||
				!exactMacOSLoginKeychainDumpArgv(parent.Argv[1:]) {
				continue
			}
			return true
		}
	}
	return false
}

func exactMacOSLoginKeychainDumpArgv(argv []string) bool {
	if len(argv) != 4 || argv[0] != "security" ||
		argv[1] != "dump-keychain" || argv[2] != "-d" {
		return false
	}
	return argv[3] == "login.keychain" || argv[3] == "login.keychain-db"
}
