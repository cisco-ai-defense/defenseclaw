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
	readyFor    string
	user        string
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
		Short: "Check, show or pause DefenseClaw's kernel controls in the host's Tetragon",
		Long: `Check whether this host is ready for a Tetragon mode, show what the managed
sensor helper does with the host's Tetragon (enterprise.tetragon), or pause and
resume the enforcement of DefenseClaw's kernel controls.

verify is the readiness check: without --ready-for it checks the mode the
config asks for; with --ready-for consume, observe or enforce it checks what
moving to that mode needs, with a copy-paste fix for each failing check. For
enforce it is the promotion guide: each enrolled user's burn-in progress and
ETA, the would-block hits and what they mean, and the enforce_ack to approve.
It exits 0 when no check fails and 1 when one does, so config management can
gate on it.

status prints the Tetragon the helper found, the effective mode, the
kernel-control digest that enforce_ack approves, each DefenseClaw policy,
every enrolled user's burn-in and hits (--user for one user), the agent
sessions that are observed but not enforced, your own Tetragon policies
(DefenseClaw reads their events and never changes them), any pause or
operator override, orphaned policies, and the next step.

pause is the root break-glass for every user on this host: enforcing controls
move to monitor mode within seconds (their events stay visible) until the
pause expires or resume removes it. It survives helper and Tetragon restarts,
and reboots unless --until-reboot is given. It is a runtime action, not a
config change.

These commands read the helper's state files and write only the pause file;
they never connect to Tetragon. Run as root:
sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux tetragon ...

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
		newUnixTetragonActionCommand("verify", "Check that this host is ready for a Tetragon mode, with a fix for each failing check (read-only)"),
		newUnixTetragonActionCommand("status", "Show the kernel controls, the burn-in of each user, your policies, pauses, overrides and orphans (read-only)"),
		newUnixTetragonActionCommand("pause", "Pause kernel enforcement for every user on this host until the pause expires (default 4h, at most 7d)"),
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
	switch action {
	case "pause":
		flags.Var(&pauseDurationValue{d: &opts.pauseFor}, "for", "how long to pause, such as 30m, 8h or 2d (default 4h, at most 7d)")
		flags.BoolVar(&opts.untilReboot, "until-reboot", false, "pause until the next reboot instead of for a duration")
		flags.StringVar(&opts.reason, "reason", "", "why enforcement is paused (recorded with the pause, at most 256 characters)")
	case "verify":
		flags.Var(&readyForValue{mode: &opts.readyFor}, "ready-for", "check what moving to this mode needs: consume, observe or enforce (default: the mode the config asks for)")
	case "status":
		flags.StringVar(&opts.user, "user", "", "show one enrolled user, by name or uid")
	}
	flags.BoolVar(&opts.json, "json", false, "print the result as JSON")
	return cmd
}

// readyForValue is --ready-for: a Tetragon mode verify can check.
type readyForValue struct{ mode *string }

func (v *readyForValue) Set(s string) error {
	switch mode := strings.ToLower(strings.TrimSpace(s)); mode {
	case "", "consume", "observe", "enforce":
		// "" is the default: the mode the config asks for.
		*v.mode = mode
		return nil
	}
	return fmt.Errorf("not consume, observe or enforce")
}

func (v *readyForValue) Type() string { return "mode" }

func (v *readyForValue) String() string {
	if v.mode == nil {
		return ""
	}
	return *v.mode
}

func (v *readyForValue) flagTakes() string { return "consume, observe or enforce" }

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
