// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestWindowsEnterpriseLifecycleReportsTheFatalInstallExitCode(t *testing.T) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
	})
	windowsEnterpriseScriptFinder = func(string) (string, error) {
		return "C:\\release\\libexec\\install-enterprise.ps1", nil
	}

	for name, test := range map[string]struct {
		run  func(context.Context, *cobra.Command, string, []string) error
		want int
	}{
		"installer failure": {
			run: func(context.Context, *cobra.Command, string, []string) error {
				return errors.New("Windows enterprise installer exited with code 1")
			},
			want: windowsEnterpriseFailureExitCode,
		},
		"success": {
			run: func(context.Context, *cobra.Command, string, []string) error {
				return nil
			},
			want: 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			windowsEnterpriseCommandRunner = test.run
			cmd := newWindowsEnterpriseLifecycleCommand("install")
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(nil)
			err := cmd.Execute()
			if test.want == 0 {
				if err != nil {
					t.Fatalf("install: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a failed install must not report success")
			}
			// Deployment systems read the code, so it has to survive the trip
			// out through cobra.
			if got := commandExitCode(err); got != test.want {
				t.Fatalf("exit code = %d, want %d", got, test.want)
			}
		})
	}
}
