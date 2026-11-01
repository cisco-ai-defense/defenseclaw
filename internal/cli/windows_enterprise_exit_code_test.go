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
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsEnterpriseLifecycleReportsTheFatalInstallExitCode(t *testing.T) {
	// Hermetic: the host running the test may carry a real deployment.
	stubWindowsEnterpriseDeployments(t, nil)
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

// Every exit code windowsEnterpriseFailureCodeFor returns is one the lifecycle
// result schema allows on Windows (windowsLifecycleExitCodes), including 5
// for elevation_required.
func TestWindowsEnterpriseFailureCodesAreInTheExitCodeTable(t *testing.T) {
	for code, want := range map[string]int{
		"elevation_required":              enterprisestatus.WindowsExitAccessDenied,
		"lifecycle_busy":                  enterprisestatus.WindowsExitBusy,
		"hook_calls_running":              enterprisestatus.WindowsExitBusy,
		"hook_in_use":                     enterprisestatus.WindowsExitBusy,
		"bundle_apply_failed":             enterprisestatus.WindowsExitBusy,
		"invalid_arguments":               enterprisestatus.WindowsExitInvalidArgs,
		"bundle_config_validation_failed": enterprisestatus.WindowsExitFailure,
		"anything_else":                   enterprisestatus.WindowsExitFailure,
	} {
		result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "9.9.9")
		result.AddError(code, "test")
		got := windowsEnterpriseFailureCodeFor(result)
		if got != want || !slices.Contains(windowsLifecycleExitCodes, got) {
			t.Fatalf("%s exits %d, want %d (one of %v)", code, got, want, windowsLifecycleExitCodes)
		}
	}
}
