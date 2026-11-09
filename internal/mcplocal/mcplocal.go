// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package mcplocal holds the one rule that says which local (stdio) MCP
// server definitions the scanner refuses from the command and arguments
// alone, before anything starts. It mirrors cli/defenseclaw/scanner/mcp.py
// (_stdio_scan_command_error). The hook takes the verdict from the complete
// definition it reads as the user, because the facts it sends keep only the
// first arguments; the scanner and the watcher use the same rule.
package mcplocal

import (
	"fmt"
	"strings"
)

// The classes of verdict Judge returns, and the values a hook states.
const (
	// None: a scan starts the server (npx or uvx with a package and no
	// execution flag), or there is no command to judge.
	None = "none"
	// Launcher: the command is a path, or any program but the bare npx or uvx.
	Launcher = "launcher"
	// Arguments: npx or uvx with an execution flag or without a package.
	Arguments = "arguments"
)

// forbiddenFlags are the arguments that turn an allowlisted launcher into a
// code-running one (_FORBIDDEN_STDIO_FLAGS).
var forbiddenFlags = map[string]bool{
	"-c": true, "--command": true, "--eval": true, "-e": true, "--exec": true, "--script": true, "-x": true,
}

func launcherRefusal(command string) string {
	switch base := strings.ToLower(command); {
	case command == "":
		return ""
	case strings.ContainsAny(command, "/\\"):
		return fmt.Sprintf("command %q is a path, and paths are never an allowlisted stdio launcher: "+
			"the scanner starts only the bare names npx or uvx from PATH", command)
	case base != "npx" && base != "uvx":
		return fmt.Sprintf("command %q is not an allowlisted stdio launcher (allowed: npx, uvx): "+
			"a scan starts only npm or PyPI packages through npx or uvx, never another program", command)
	}
	return ""
}

func argumentsRefusal(command string, args []string) string {
	hasPackage := false
	for _, arg := range args {
		token := strings.TrimSpace(arg)
		flag, _, _ := strings.Cut(token, "=")
		if flag = strings.ToLower(flag); forbiddenFlags[flag] {
			return fmt.Sprintf("launcher %q uses forbidden execution flag %q", command, flag)
		}
		if token != "" && !strings.HasPrefix(token, "-") {
			hasPackage = true
		}
	}
	if !hasPackage {
		return fmt.Sprintf("launcher %q requires a package/server argument", command)
	}
	return ""
}

// Class is the class of the scanner refusal of a complete definition.
func Class(command string, args []string) string {
	class, _ := Judge(command, args, "")
	return class
}

// Judge is the scanner verdict on a local server and the reason it words.
// stated is the class a hook took from the complete definition (a claim keeps
// at most the first arguments, which cannot stand for the verdict): when it
// is set it decides, and the reason is worded from the definition as far as
// it shows the cause. Empty stated judges command and args as they are.
func Judge(command string, args []string, stated string) (class, reason string) {
	command = strings.TrimSpace(command)
	switch stated {
	case None:
		return None, ""
	case Launcher:
		if reason = launcherRefusal(command); reason == "" {
			reason = fmt.Sprintf("command %q is not an allowlisted stdio launcher (allowed: npx, uvx)", command)
		}
		return Launcher, reason
	case Arguments:
		if reason = argumentsRefusal(command, args); reason == "" {
			reason = fmt.Sprintf("launcher %q requires a package/server argument and no execution flag, and the complete definition has neither", command)
		}
		return Arguments, reason
	}
	if command == "" {
		return None, ""
	}
	if reason = launcherRefusal(command); reason != "" {
		return Launcher, reason
	}
	if reason = argumentsRefusal(command, args); reason != "" {
		return Arguments, reason
	}
	return None, ""
}
