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
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/spf13/cobra"
)

func TestUnixEnterpriseCommandTree(t *testing.T) {
	for _, group := range []string{"linux", "macos"} {
		for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "status", "verify", "uninstall"} {
			cmd, _, err := rootCmd.Find([]string{"enterprise", group, action})
			if err != nil || cmd == nil || cmd.Name() != action {
				t.Fatalf("enterprise %s %s not registered: %v", group, action, err)
			}
			if cmd.Flags().Lookup("json") == nil {
				t.Fatalf("enterprise %s %s has no --json", group, action)
			}
		}
		// Package scriptlets remove the deployment with a long lock wait.
		for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "uninstall"} {
			cmd, _, _ := rootCmd.Find([]string{"enterprise", group, action})
			if cmd.Flags().Lookup("lock-wait") == nil {
				t.Fatalf("enterprise %s %s lacks --lock-wait", group, action)
			}
		}
	}
	for _, action := range []string{"set", "status", "remove"} {
		if cmd, _, err := rootCmd.Find([]string{"enterprise", "secret", action}); err != nil || cmd.Name() != action {
			t.Fatalf("enterprise secret %s not registered: %v", action, err)
		}
	}
	set, _, _ := rootCmd.Find([]string{"enterprise", "secret", "set"})
	if set.Flags().Lookup("from-stdin") == nil || set.Flags().Lookup("name") == nil {
		t.Fatal("enterprise secret set lacks --name/--from-stdin")
	}
}

// The lifecycle help and the platform pages define exit 2 as invalid
// arguments; an unknown flag, a malformed flag value, a stray argument or an
// unknown action must use it instead of cobra's generic 1.
func TestUnixLifecycleInvalidArgumentsExitTwo(t *testing.T) {
	want := enterprisestatus.InvalidArgsExitCode(runtime.GOOS)
	for _, group := range []string{"linux", "macos"} {
		for _, action := range []string{"ensure", "status", "verify", "uninstall"} {
			cmd, _, err := rootCmd.Find([]string{"enterprise", group, action})
			if err != nil {
				t.Fatal(err)
			}
			for _, flags := range [][]string{{"--bogus"}, {"--json=maybe"}} {
				parseErr := cmd.ParseFlags(flags)
				if parseErr == nil {
					t.Fatalf("%s %s accepted %v", group, action, flags)
				}
				flagErr := cmd.FlagErrorFunc()(cmd, parseErr)
				if got := commandExitCode(flagErr); got != want {
					t.Fatalf("enterprise %s %s %v exits %d, want %d", group, action, flags, got, want)
				}
				// GAP-1943: the usage line and the --help pointer, as on every
				// other gateway command.
				if msg := flagErr.Error(); !strings.Contains(msg, "\nUsage: "+cmd.UseLine()) ||
					!strings.HasSuffix(msg, "Try '"+cmd.CommandPath()+" --help' for help.") {
					t.Fatalf("enterprise %s %s %v: %q", group, action, flags, msg)
				}
			}
			argsErr := cmd.ValidateArgs([]string{"extra"})
			if argsErr == nil || commandExitCode(argsErr) != want || !strings.Contains(argsErr.Error(), cmd.CommandPath()+" --help") {
				t.Fatalf("enterprise %s %s extra: %v exits %d, want %d", group, action, argsErr, commandExitCode(argsErr), want)
			}
		}
		groupCmd, _, err := rootCmd.Find([]string{"enterprise", group})
		if err != nil {
			t.Fatal(err)
		}
		if groupCmd.RunE == nil {
			t.Fatalf("enterprise %s bogus is not refused", group)
		}
		runErr := groupCmd.RunE(groupCmd, []string{"bogus"})
		var coded *exitCodeError
		if !errors.As(runErr, &coded) || coded.ExitCode() != want {
			t.Fatalf("enterprise %s bogus: %v", group, runErr)
		}
	}
}

// GAP-2095: enterprise secret reports a bad flag, a malformed --lock-wait, a
// stray argument and a missing --name the way enterprise linux|macos do.
func TestUnixEnterpriseSecretInvalidArgumentsExitTwo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps its own enterprise secret exit codes")
	}
	want := enterprisestatus.InvalidArgsExitCode(runtime.GOOS)
	check := func(cmd *cobra.Command, what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("enterprise secret %s %s: no error", cmd.Name(), what)
		}
		msg := err.Error()
		if got := commandExitCode(err); got != want ||
			!strings.Contains(msg, "\nUsage: "+cmd.UseLine()) ||
			!strings.HasSuffix(msg, "Try '"+cmd.CommandPath()+" --help' for help.") {
			t.Fatalf("enterprise secret %s %s: exit %d, %q", cmd.Name(), what, commandExitCode(err), msg)
		}
	}
	for _, action := range []string{"set", "status", "remove"} {
		cmd, _, err := rootCmd.Find([]string{"enterprise", "secret", action})
		if err != nil {
			t.Fatal(err)
		}
		bad := [][]string{{"--bogus"}, {"--json=maybe"}}
		if action != "status" {
			bad = append(bad, []string{"--lock-wait=banana"})
		}
		for _, flags := range bad {
			parseErr := cmd.ParseFlags(flags)
			if parseErr == nil {
				t.Fatalf("enterprise secret %s accepted %v", action, flags)
			}
			check(cmd, strings.Join(flags, " "), cmd.FlagErrorFunc()(cmd, parseErr))
		}
		if action == "set" {
			if !strings.HasPrefix(plainFlagValueError(cmd.ParseFlags([]string{"--lock-wait=banana"})), "--lock-wait takes a duration") {
				t.Fatal("--lock-wait=banana lost its plain message")
			}
		}
		check(cmd, "extra", cmd.ValidateArgs([]string{"extra"}))
		if action != "status" {
			check(cmd, "without --name", cmd.PreRunE(cmd, nil))
		}
	}
}
