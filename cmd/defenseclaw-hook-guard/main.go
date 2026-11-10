// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-hook-guard is the one-line Windows install's launcher guard
// (internal/hookguard) for Claude Code and, on the events they can block,
// for Codex (launcher-guard-sibling) and Devin (launcher-guard-devin),
// rel-1-0-6 GAP-0676. Release builds link it with
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

// guardExecutable is the path of this guard program; the Codex and Devin
// guards start the launcher beside it. Tests replace it.
var guardExecutable = os.Executable

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if launcher, hookArgs, ok := hookguard.Argv(args); ok {
		return hookguard.Run(launcher, hookArgs, stdin, stdout, stderr)
	}
	if hookArgs, event, contract, ok := hookguard.SiblingArgv(args); ok {
		// A guard that cannot name its own folder starts nothing, which
		// answers as a missing launcher.
		self, _ := guardExecutable()
		return hookguard.RunCodex(hookguard.SiblingLauncher(self), hookArgs, event, contract, stdin, stdout, stderr)
	}
	if hookArgs, event, ok := hookguard.DevinArgv(args); ok {
		self, _ := guardExecutable()
		return hookguard.RunDevin(hookguard.SiblingLauncher(self), hookArgs, event, stdin, stdout, stderr)
	}
	if dataDir, launcher, event, ok := hookguard.CoworkArgv(args); ok {
		return hookguard.RunCowork(dataDir, launcher, event, stdin, stdout, stderr)
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
	fmt.Fprintf(stderr, "defenseclaw-hook-guard: only %q <defenseclaw-hook.exe> hook --connector claudecode, %q hook --connector codex --event <event> --hook-contract <contract>, %q <event> hook --connector devin, or %q with DefenseClaw hook paths is accepted\n",
		hookguard.Subcommand, hookguard.SiblingSubcommand, hookguard.DevinSubcommand, hookguard.CoworkSubcommand)
	return 2
}
