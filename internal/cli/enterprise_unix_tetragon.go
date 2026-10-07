// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// unixTetragonOptions are the flags of `enterprise linux tetragon <action>`.
type unixTetragonOptions struct {
	pauseFor    time.Duration
	untilReboot bool
	reason      string
	json        bool
}

// newUnixTetragonCommand is `enterprise linux tetragon`: the root view of the
// DefenseClaw kernel controls the managed sensor helper keeps in the host's
// Tetragon, and the break-glass pause of their enforcement. It reads the
// helper's state files and writes only the pause file; it never connects to
// Tetragon.
func newUnixTetragonCommand() *cobra.Command {
	group := &cobra.Command{
		Use:   "tetragon",
		Short: "Show DefenseClaw's kernel controls in the host's Tetragon, or pause their enforcement",
		Long: `Show what the managed sensor helper does with the host's Tetragon
(enterprise.tetragon), or pause and resume the enforcement of DefenseClaw's
kernel controls.

status prints the Tetragon the helper found, the effective mode, the
kernel_policy digest that enforce_ack approves, each DefenseClaw policy, every
enrolled user's burn-in and would-block hits, the agent sessions that are
observed but not enforced, any pause or operator override, and orphaned
policies. pause is the root break-glass: enforcing controls move to monitor
mode within seconds (their events stay visible) until the pause expires or
resume removes it. It survives helper and Tetragon restarts, and reboots
unless --until-reboot is given. It is a runtime action, not a config change.

These commands read the helper's state files and write only the pause file;
they never connect to Tetragon. Run as root.

Exit codes: 0 success, 1 failure, 2 invalid arguments.`,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		Args:              cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return lifecycleFlagError(cmd, fmt.Errorf("unknown action %q for %q%s", args[0], cmd.CommandPath(), didYouMean(cmd, args[0])))
			}
			return cmd.Help()
		},
	}
	group.SetFlagErrorFunc(lifecycleFlagError)
	group.AddCommand(
		newUnixTetragonActionCommand("status", "Show the kernel controls, the burn-in of each user, pauses, overrides and orphans (read-only)"),
		newUnixTetragonActionCommand("pause", "Pause kernel enforcement: the controls move to monitor mode until the pause expires (default 4h, at most 7d)"),
		newUnixTetragonActionCommand("resume", "Remove the pause; the sensor helper re-applies enterprise.tetragon"),
	)
	return group
}

func newUnixTetragonActionCommand(action, summary string) *cobra.Command {
	opts := &unixTetragonOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args:         lifecycleNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnixTetragon(cmd, action, opts)
		},
	}
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	flags := cmd.Flags()
	if action == "pause" {
		flags.Var(&pauseDurationValue{d: &opts.pauseFor}, "for", "how long to pause, such as 30m, 8h or 2d (default 4h, at most 7d)")
		flags.BoolVar(&opts.untilReboot, "until-reboot", false, "pause until the next reboot instead of for a duration")
		flags.StringVar(&opts.reason, "reason", "", "why enforcement is paused (recorded with the pause, at most 256 characters)")
	}
	flags.BoolVar(&opts.json, "json", false, "print the result as JSON")
	return cmd
}

// pauseDurationValue is --for: a Go duration, or whole days such as 2d.
type pauseDurationValue struct{ d *time.Duration }

func (v *pauseDurationValue) Set(s string) error {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return fmt.Errorf("not a number of days")
		}
		*v.d = time.Duration(n) * 24 * time.Hour
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*v.d = d
	return nil
}

func (v *pauseDurationValue) Type() string { return "duration" }

// String is "0" when unset, so --help prints no "(default 0s)".
func (v *pauseDurationValue) String() string {
	if v.d == nil || *v.d == 0 {
		return "0"
	}
	return v.d.String()
}

func (v *pauseDurationValue) flagTakes() string { return "a duration up to 7d, such as 30m, 8h or 2d" }
