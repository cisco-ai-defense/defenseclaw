// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// ExactOpenSSLPKCS12PrivateKeyExtraction reports a single complete OpenSSL
// invocation that requests unencrypted private-key output from a literal
// PKCS#12 bundle. Broad certificate inspection and -nokeys forms are excluded.
func ExactOpenSSLPKCS12PrivateKeyExtraction(facts Facts) bool {
	if facts.Authoritative() && len(facts.Commands) == 1 &&
		exactOpenSSLPKCS12Command(facts.Commands[0], facts.Paths, false) {
		return true
	}
	return detectionOnlyBashLoginPKCS12Extraction(facts)
}

func exactOpenSSLPKCS12Command(
	command CommandFact,
	paths []PathFact,
	allowPipeline bool,
) bool {
	if command.Program != "openssl" && command.Program != "openssl.exe" ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
		(!allowPipeline && (command.ControlFlowUncertain || command.PipelineID != 0)) ||
		!openSSLCommandHasOperation(command, OperationCredentialRead) {
		return false
	}
	reads := 0
	for _, candidate := range paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessRead {
			continue
		}
		value := strings.ToLower(strings.ReplaceAll(candidate.Value, `\`, "/"))
		if !strings.HasSuffix(value, ".p12") && !strings.HasSuffix(value, ".pfx") &&
			!strings.HasSuffix(value, ".pkcs12") {
			return false
		}
		reads++
	}
	return reads == 1
}

func detectionOnlyBashLoginPKCS12Extraction(facts Facts) bool {
	if len(facts.Commands) != 1 {
		return false
	}
	owner := facts.Commands[0]
	if owner.Program != "bash" || !owner.ArgvComplete || len(owner.Argv) != 3 ||
		owner.Argv[1] != "-lc" || strings.TrimSpace(owner.Argv[2]) == "" ||
		owner.ParentCommandID != 0 || owner.PipelineID != 0 ||
		owner.ControlFlowUncertain || owner.Effect != EffectExecute ||
		len(owner.Redirects) != 0 || len(owner.Wrappers) != 0 ||
		!staticArguments(owner.Arguments) ||
		!exactPOSIXProgramIdentity(owner.Executable, owner.Program) {
		return false
	}
	child := parsePOSIX(owner.Argv[2], 1, 1)
	if child.status == StatusInvalid || child.status == StatusLimitExceeded {
		return false
	}
	classifyOutput(&child)
	matches := 0
	for _, command := range child.commands {
		if exactOpenSSLPKCS12Command(command, child.paths, true) {
			matches++
		}
	}
	return matches == 1
}

func openSSLCommandHasOperation(command CommandFact, operation OperationKind) bool {
	for _, candidate := range command.Operations {
		if candidate == operation {
			return true
		}
	}
	return false
}

func classifyOpenSSLPKCS12PrivateKeyExtraction(
	out *parseOutput,
	command *CommandFact,
) bool {
	if out == nil || command == nil || len(command.Argv) < 4 ||
		!staticArguments(command.Arguments) {
		return false
	}
	input := ""
	nodes := false
	for index := 2; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		switch argument {
		case "-nodes":
			if nodes {
				return false
			}
			nodes = true
		case "-in", "-passin", "-password", "-name":
			if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
				return false
			}
			if argument == "-in" {
				if input != "" {
					return false
				}
				input = command.Argv[index+1]
			}
			index++
		case "-legacy", "-info", "-clcerts", "-cacerts", "-nocerts":
		case "-nokeys", "-noout", "-help", "--help", "-out":
			return false
		default:
			return false
		}
	}
	lower := strings.ToLower(strings.ReplaceAll(input, `\`, "/"))
	if !nodes || input == "" || unresolvedCredentialRemoteScalar(input) ||
		(!strings.HasSuffix(lower, ".p12") && !strings.HasSuffix(lower, ".pfx") &&
			!strings.HasSuffix(lower, ".pkcs12")) {
		return false
	}
	addOperation(command, OperationRead)
	addOperation(command, OperationCredentialRead)
	appendCommandPath(out, command, PathAccessRead, input)
	appendFileToProcessFlow(out, command.ID)
	return true
}
