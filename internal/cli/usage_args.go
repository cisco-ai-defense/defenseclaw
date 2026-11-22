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
	"reflect"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// usageArgsExempt lists the command trees whose positional-argument handling
// stays cobra's own: agent hooks and the notify hook have exit-status
// contracts of their own (rc 2 blocks an agent's tool call).
var usageArgsExempt = []string{"hook", "notify"}

// usageArgsExemptGroups lists command groups (paths below the root) whose
// leaves keep their own positional-argument handling: Setup and the Windows
// module drive the Windows enterprise lifecycle, whose invalid-arguments
// exit code is 1639. The rest of the enterprise tree rejects a stray
// argument like every other command (GAP-2330: "enterprise hooks status
// extra-arg" ran and exited 0).
var usageArgsExemptGroups = []string{"enterprise windows"}

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

// isCobraNoArgs reports whether a command's validator is cobra.NoArgs,
// which reports a stray argument on a leaf as an unknown command.
func isCobraNoArgs(args cobra.PositionalArgs) bool {
	return args != nil && reflect.ValueOf(args).Pointer() == reflect.ValueOf(cobra.NoArgs).Pointer()
}

// inExemptGroup reports whether the command path (below the root) is one of
// the usageArgsExemptGroups or sits under one.
func inExemptGroup(path string) bool {
	for _, group := range usageArgsExemptGroups {
		if path == group || strings.HasPrefix(path, group+" ") {
			return true
		}
	}
	return false
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
	return cliusage.UnexpectedArgs(c, c.Flags().Args())
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
			if sub.Runnable() && (sub.Args == nil || isCobraNoArgs(sub.Args)) && !sub.DisableFlagParsing &&
				!usageTakesArgs[path] && !inCommandTree(sub, usageArgsExempt) && !inExemptGroup(path) {
				sub.Args = cliusage.UnexpectedArgs
			}
			walk(sub)
		}
	}
	walk(root)
	// A mistyped top-level command gets the same error, suggestion, usage
	// and --help lines as a mistyped subcommand, not the raw cobra "Did you
	// mean this?" block (GAP-2374). cobra already rejects every positional
	// argument on the root, so only the message changes.
	if root.Args == nil {
		root.Args = cliusage.UnexpectedArgs
	}
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

// argsSetLongFlag reports whether args, read the way pflag reads them with
// the flags of fs, set the flag name before the "--" terminator. A token
// that is another flag's value (--config --trust-anchors) or follows the
// terminator does not set it. pflag stops at its first error; this keeps
// reading, and an unknown or malformed flag takes no value (as pflag's
// unknown-flag allow-list does for a dash token), so a flag after the bad
// one still counts.
func argsSetLongFlag(fs *pflag.FlagSet, args []string, name string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		if arg == "--" {
			return false
		}
		if long, ok := strings.CutPrefix(arg, "--"); ok {
			flagName, _, inline := strings.Cut(long, "=")
			if flagName == "" || flagName[0] == '-' {
				continue
			}
			flag := fs.Lookup(flagName)
			if flag == nil {
				continue
			}
			if flag.Name == name {
				return true
			}
			if !inline && flag.NoOptDefVal == "" {
				i++
			}
			continue
		}
		shorts := arg[1:]
		if strings.HasPrefix(shorts, "test.") {
			continue
		}
		for len(shorts) > 0 {
			flag := fs.ShorthandLookup(shorts[:1])
			if flag == nil {
				break
			}
			if flag.Name == name {
				return true
			}
			if len(shorts) > 2 && shorts[1] == '=' {
				break
			}
			if flag.NoOptDefVal == "" {
				if len(shorts) == 1 {
					i++
				}
				break
			}
			shorts = shorts[1:]
		}
	}
	return false
}
