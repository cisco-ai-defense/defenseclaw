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
	"strings"
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
		"codex_state_held":                enterprisestatus.WindowsExitBusy,
		"codex_requirements_held":         enterprisestatus.WindowsExitBusy,
		"codex_state_unsettled":           enterprisestatus.WindowsExitFailure,
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

// GAP-0803: a rollback that a program held open without delete sharing stopped
// ends the run with the held code even when the module wrapped the rollback
// text inside the failure of the run, so the MDM retries it (exit 1618).
func TestWindowsEnterpriseRollbackHeldCodeSurvivesTheWrappingFailureText(t *testing.T) {
	holder := "codex_requirements_held: notepad.exe (process id 4242, EC2AMAZ-X\\Administrator) has C:\\ProgramData\\OpenAI\\Codex\\requirements.toml, the Codex machine requirements, open without delete sharing, so the rollback could not put it back"
	for name, message := range map[string]string{
		"leading":       holder,
		"upgrade":       "Upgrade failed (Codex requirements reconcile failed: boom); rollback also failed and protected recovery state was retained: managed lifecycle/hook restore failed: " + holder,
		"ensure, rollback met a holder": "codex_requirements_held: notepad.exe (process id 4242, EC2AMAZ-X\\Administrator) has C:\\ProgramData\\OpenAI\\Codex\\requirements.toml, the Codex machine requirements, open without delete sharing, so the rollback could not put it back; the rollback left that file as it is and put everything else back, and the transaction is still pending. Next step: close that program, then run & '.\\DefenseClawSetup-Enterprise-Standalone-x64.exe' /repair; it finishes the rollback (an MDM retries exit 1618 on its own). This ensure had failed first: Codex requirements reconcile failed: boom",
		"hook, rollback met a holder":    "hook_in_use: a program that Windows did not name (it may run as SYSTEM, so no process id is available) has C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-hook.exe, the installed hook, open without delete sharing, so the rollback could not put the previous hook back; the rollback left the replacement hook in place and put everything else back, and the transaction is still pending. Next step: close that program, then run /repair",
		"state variant": "codex_state_held: a program (process id 7) has C:\\ProgramData\\OpenAI\\Codex\\.defenseclaw-managed-hooks.state, the Codex managed-hooks state, open without delete sharing, so the rollback could not put it back",
	} {
		code := windowsEnterpriseMessageCode(message, "lifecycle_error")
		if code != "codex_requirements_held" && code != "codex_state_held" && code != "hook_in_use" {
			t.Fatalf("%s: code = %q, want a held code", name, code)
		}
		result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "9.9.9")
		result.AddError(code, message)
		if got := windowsEnterpriseFailureCodeFor(result); got != enterprisestatus.WindowsExitBusy {
			t.Fatalf("%s: exit = %d, want %d", name, got, enterprisestatus.WindowsExitBusy)
		}
	}
}

// GAP-0877 review S2: a Codex writer that never settles ends the run with the
// named code even when the module wrapped it inside the failure and rollback
// text of an install, repair, ensure or upgrade, and the run still exits 1603
// (a retry of the same delivery does not get past a stopped writer).
func TestWindowsEnterpriseUnsettledCodexStateCodeSurvivesTheWrappingFailureText(t *testing.T) {
	unsettled := "codex_state_unsettled: the Codex writer transaction counter next to C:\\ProgramData\\OpenAI\\Codex\\.defenseclaw-managed-hooks.state stayed at 3 (odd: a transaction is open) for 30 seconds, so the Codex managed-hooks state could not be judged and this run stopped"
	for name, message := range map[string]string{
		"leading": unsettled,
		"upgrade": "Upgrade failed (" + unsettled + "); rolled back to the installed release",
		"repair":  "Repair failed: " + unsettled + "; the transaction was rolled back",
	} {
		code := windowsEnterpriseMessageCode(message, "lifecycle_error")
		if code != "codex_state_unsettled" {
			t.Fatalf("%s: code = %q, want codex_state_unsettled", name, code)
		}
		if got := windowsEnterpriseStderrCode([]byte(message)); !strings.Contains(got, "codex_state_unsettled:") {
			t.Fatalf("%s: stderr code = %q, want the unsettled refusal", name, got)
		}
		result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "9.9.9")
		result.AddError(code, message)
		if got := windowsEnterpriseFailureCodeFor(result); got != enterprisestatus.WindowsExitFailure {
			t.Fatalf("%s: exit = %d, want %d", name, got, enterprisestatus.WindowsExitFailure)
		}
	}
}
