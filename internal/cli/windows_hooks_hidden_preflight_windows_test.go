// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g079 review 2 R4: the eight hidden enterprise-hooks commands that g079
// review F3 routed through enterpriseHooksPlatformPreflight refuse on it
// before any protected read, so a standard user cannot use one of them as an
// oracle of a protected file. Each is given protected paths that do not
// exist, so a read before the gate would refuse with another error, and the
// Codex requirements layout resolver is a tripwire.
func TestWindowsHiddenHooksCommandsRefuseOnThePlatformPreflightFirst(t *testing.T) {
	refusal := errors.New("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
	scope := t.TempDir()
	missing := func(name string) string { return filepath.Join(scope, "protected", name) }
	savedPreflight, savedLayout := enterpriseHooksPlatformPreflight, windowsCodexRequirementsLayoutResolver
	t.Cleanup(func() {
		enterpriseHooksPlatformPreflight, windowsCodexRequirementsLayoutResolver = savedPreflight, savedLayout
	})
	calls := 0
	enterpriseHooksPlatformPreflight = func() error {
		calls++
		return refusal
	}
	windowsCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		t.Error("the Codex requirements layout was resolved before the platform preflight refused")
		return connector.WindowsCodexMachineRequirementsOptions{}, errors.New("tripwire")
	}
	// The user-state purge and the OWNER RIGHTS restore first check the
	// profile and the purge request, which are not protected reads.
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv(windowsManagedHooksPurgeUserStateEnv, "1")
	t.Setenv("DEFENSECLAW_HOME", missing("runtime"))
	quiet := func() *cobra.Command {
		command := &cobra.Command{}
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		return command
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"codex requirements", func() error { return runWindowsCodexRequirementsAction(quiet(), "inspect", false, false, "") }},
		{"target-runtime", func() error {
			return runWindowsTargetRuntimeAction(quiet(), "inspect", &windowsTargetRuntimeOptions{
				manifest: missing("targets.yaml"), request: missing("request.json"), claims: missing("claims.json"), output: missing("report.json")})
		}},
		{"namespace-root-cleanup", func() error {
			return runWindowsNamespacePurge(&windowsNamespacePurgeOptions{request: missing("request.json"), output: missing("report.json")})
		}},
		{"contract cleanup", func() error {
			return runWindowsManagedHookContractCleanup(&windowsManagedHookContractCleanupOptions{receipt: missing("receipt.json"), output: missing("report.json")})
		}},
		{"user-state purge", func() error {
			_, err := runWindowsManagedHooksUserStatePurge()
			return err
		}},
		{"OWNER RIGHTS restore", func() error {
			_, err := runWindowsManagedHooksOwnerRightsRestore()
			return err
		}},
		{"teardown", func() error {
			_, err := runWindowsManagedHooksTeardown("check", false, "", "")
			return err
		}},
		{"lifecycle snapshot", func() error {
			_, err := runWindowsManagedHooksLifecycleWithStagedRetire("capture", false)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls
			if err := tc.run(); !errors.Is(err, refusal) {
				t.Fatalf("error = %v, want the platform preflight's refusal first", err)
			}
			if calls != before+1 {
				t.Fatalf("the platform preflight ran %d times, want once", calls-before)
			}
			if entries, err := os.ReadDir(scope); err != nil || len(entries) != 0 {
				t.Fatalf("the refused command created %v (%v)", entries, err)
			}
		})
	}
}
