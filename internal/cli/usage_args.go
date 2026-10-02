// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// usageArgsExempt lists the command trees whose positional-argument handling
// stays cobra's own: agent hooks and the notify hook have exit-status
// contracts of their own (rc 2 blocks an agent's tool call), and the
// enterprise lifecycle leaves are driven by deployment tooling.
var usageArgsExempt = []string{"enterprise", "hook", "notify"}

// usageTakesArgs lists the commands that read positional arguments without
// declaring an Args validator.
var usageTakesArgs = map[string]bool{
	"connector launch":    true,
	"sandbox image build": true,
}

// pendingUnknownSubcommand carries an unknown-subcommand error out of the
// help function, which cobra calls for a command group and whose result it
// cannot return. ExecuteContext reports it.
var pendingUnknownSubcommand error

var usageArgChecksInstalled bool

// inCommandTree reports whether c sits under one of the named top-level
// commands.
func inCommandTree(c *cobra.Command, names []string) bool {
	fields := strings.Fields(c.CommandPath())
	for _, f := range fields[min(1, len(fields)):] {
		for _, name := range names {
			if f == name {
				return true
			}
		}
	}
	return false
}

// usageError adds the usage line and a --help pointer to err and gives it
// exit status 2, the shape and status the Python defenseclaw CLI uses.
func usageError(c *cobra.Command, err error) error {
	use := c.UseLine()
	if c.HasAvailableSubCommands() {
		// Show the subcommand form too, as --help does (GAP-1622).
		group := c.CommandPath() + " [command]"
		if c.Runnable() {
			use += "\n       " + group
		} else {
			use = group
		}
	}
	return withExitCode(fmt.Errorf("%w\nUsage: %s\nTry '%s --help' for help.", err, use, c.CommandPath()), 2)
}

// unexpectedArgs rejects positional arguments on a command that takes none
// (GAP-1549): "status extra-arg" ran status and "watchdog bogus" started the
// foreground watchdog.
func unexpectedArgs(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	kind := "unexpected argument"
	if c.HasSubCommands() {
		kind = "unknown command"
	}
	msg := fmt.Sprintf("%s %q for %q", kind, args[0], c.CommandPath())
	if suggestions := c.SuggestionsFor(args[0]); len(suggestions) > 0 {
		msg += "\nDid you mean " + strings.Join(suggestions, " or ") + "?"
	}
	return usageError(c, fmt.Errorf("%s", msg))
}

// unknownSubcommand reports a command group invoked with a name that is none
// of its subcommands. Cobra printed the group help and exited 0 for
// "rulepack bogus" (GAP-1549).
func unknownSubcommand(c *cobra.Command) error {
	if c.Runnable() || !c.HasSubCommands() || inCommandTree(c, []string{"hook", "notify"}) {
		return nil
	}
	if f := c.Flags().Lookup("help"); f != nil && f.Changed {
		return nil
	}
	return unexpectedArgs(c, c.Flags().Args())
}

// installUsageArgChecks makes stray positional arguments a usage error on
// every gateway command that takes none, and an unknown subcommand of a
// command group a usage error instead of the group help with rc 0.
func installUsageArgChecks(root *cobra.Command) {
	if usageArgChecksInstalled {
		return
	}
	usageArgChecksInstalled = true
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			switch sub.Name() {
			case "help", "completion":
				continue
			}
			path := strings.TrimSpace(strings.TrimPrefix(sub.CommandPath(), root.CommandPath()))
			if sub.Runnable() && sub.Args == nil && !sub.DisableFlagParsing &&
				!usageTakesArgs[path] && !inCommandTree(sub, usageArgsExempt) {
				sub.Args = unexpectedArgs
			}
			walk(sub)
		}
	}
	walk(root)
	help := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if err := unknownSubcommand(cmd); err != nil {
			pendingUnknownSubcommand = err
			return
		}
		help(cmd, args)
	})
}

// isUnknownRootCommand reports cobra's own unknown top-level command error,
// which carries no exit code (it exited 1; the Python CLI exits 2).
func isUnknownRootCommand(root *cobra.Command, err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "unknown command ") &&
		strings.Contains(msg, fmt.Sprintf(" for %q", root.CommandPath()))
}
