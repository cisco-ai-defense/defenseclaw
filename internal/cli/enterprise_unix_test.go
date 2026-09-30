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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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
				if got := commandExitCode(cmd.FlagErrorFunc()(cmd, parseErr)); got != want {
					t.Fatalf("enterprise %s %s %v exits %d, want %d", group, action, flags, got, want)
				}
			}
			argsErr := cmd.ValidateArgs([]string{"extra"})
			if argsErr == nil || commandExitCode(argsErr) != want {
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
