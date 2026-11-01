// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-hook-guard is the one-line Windows install's Claude Code
// PreToolUse guard (internal/hookguard). Release builds link it with
// -H=windowsgui: the console gateway that was the guard before got a console
// window of its own whenever a caller without a console started it, and
// Windows Terminal showed it (GAP-2467). It is its own small file, not the
// launcher it checks for.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if launcher, hookArgs, ok := hookguard.Argv(args); ok {
		return hookguard.Run(launcher, hookArgs, stdin, stdout, stderr)
	}
	switch {
	case len(args) == 0:
		// Cursor imports the hooks in ~/.claude/settings.json and runs an
		// entry's command without its arguments (GAP-1011): no answer, so
		// Cursor's own hooks decide its tool calls.
		return 0
	case len(args) == 1 && args[0] == "--version":
		fmt.Fprintf(stdout, "defenseclaw-hook-guard version %s (commit=%s, built=%s)\n", version, commit, date)
		return 0
	}
	fmt.Fprintf(stderr, "defenseclaw-hook-guard: only %q <defenseclaw-hook.exe> hook --connector claudecode is accepted\n", hookguard.Subcommand)
	return 2
}
