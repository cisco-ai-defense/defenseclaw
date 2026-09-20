// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"path"
	"strings"
	"unicode/utf8"
)

const pkrootSetuidShellPayload = "cp /bin/bash /tmp/.pksh && chmod 4755 /tmp/.pksh"

// ExactPKRootSetuidShell proves one literal, unconditional pkroot invocation
// whose quoted --cmd payload creates a setuid copy of /bin/bash. The payload is
// compared as inert input bytes; it is deliberately not reparsed as general
// shell input. This keeps the accepted grammar closed and prevents variables,
// substitutions, additional control flow, redirects, or unknown arguments from
// acquiring authority. Generic parsing may remain partial for this uncommon
// executable; the private proof itself is still exact and value-free.
func ExactPKRootSetuidShell(facts Facts) bool {
	return len(facts.PKRootSetuidShells) == 1
}

func projectPKRootSetuidShells(input Input) []PKRootSetuidShellFact {
	command, ok := exactPKRootSetuidShellInput(input)
	if !ok || !exactPKRootSetuidShellCommand(command) {
		return nil
	}
	return []PKRootSetuidShellFact{{}}
}

func exactPKRootSetuidShellInput(input Input) (string, bool) {
	if !strings.EqualFold(input.Tool, "shell") || input.Tool == "" ||
		len(input.Argv) != 0 || input.Command == "" ||
		len(input.Command) > maxCommandBytes || !utf8.ValidString(input.Command) ||
		strings.IndexByte(input.Command, 0) >= 0 {
		return "", false
	}
	if len(bytes.TrimSpace(input.Args)) == 0 {
		return input.Command, true
	}
	if len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) {
		return "", false
	}
	object, problem := exactJSONObject(input.Args)
	if problem.status != "" || len(object) != 1 {
		return "", false
	}
	rawCommand, ok := object["command"]
	command, okString := rawCommand.(string)
	return input.Command, ok && okString && command == input.Command
}

func exactPKRootSetuidShellCommand(command string) bool {
	const separator = " --cmd "
	index := strings.Index(command, separator)
	if index <= 0 || strings.LastIndex(command, separator) != index {
		return false
	}
	executable := command[:index]
	quotedPayload := command[index+len(separator):]
	if !exactTemporaryPKRootExecutable(executable) || len(quotedPayload) < 2 {
		return false
	}
	quote := quotedPayload[0]
	return (quote == '\'' || quote == '"') &&
		quotedPayload[len(quotedPayload)-1] == quote &&
		quotedPayload[1:len(quotedPayload)-1] == pkrootSetuidShellPayload
}

func exactTemporaryPKRootExecutable(value string) bool {
	if !staticAbsolutePOSIXPath(value) || path.Clean(value) != value ||
		!strings.HasSuffix(value, "/pkroot/run") {
		return false
	}
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}
