// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// The repair path itself (ReconcileWindowsCodexMachineRequirements) decides
// from the ownership record whether the requirements file is DefenseClaw's
// own publication: an administrator's narrowed SessionStart group survives
// every repair, and an earlier release's unedited file still has its group
// replaced at the upgrade (loop round 2 review, Windows consolidation).
func TestWindowsCodexRepairKeepsAnAdministratorNarrowedSessionStart(t *testing.T) {
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("reconcile requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	install := func(t *testing.T) WindowsCodexMachineRequirementsOptions {
		t.Helper()
		programData := t.TempDir()
		stateRoot := t.TempDir()
		policyDir := filepath.Join(programData, "OpenAI", "Codex")
		managedDir := filepath.Join(stateRoot, "bin")
		installDir := filepath.Join(stateRoot, "install")
		for _, dir := range []string{policyDir, managedDir, installDir} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		hook := filepath.Join(managedDir, "defenseclaw-hook.exe")
		if err := os.WriteFile(hook, []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
		previousProgramData, previousDir, previousFile, previousVolume := windowsCodexMachineProgramData,
			windowsCodexMachineTrustedDirCheck, windowsCodexMachineTrustedFileCheck, windowsCodexMachineVolumeCheck
		t.Cleanup(func() {
			windowsCodexMachineProgramData, windowsCodexMachineTrustedDirCheck = previousProgramData, previousDir
			windowsCodexMachineTrustedFileCheck, windowsCodexMachineVolumeCheck = previousFile, previousVolume
		})
		windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
		windowsCodexMachineTrustedDirCheck = func(string, string) error { return nil }
		windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
		windowsCodexMachineVolumeCheck = func(string) error { return nil }
		opts := WindowsCodexMachineRequirementsOptions{
			RequirementsPath:   filepath.Join(policyDir, "requirements.toml"),
			ManagedStatePath:   filepath.Join(policyDir, windowsCodexManagedStateFile),
			ManagedDir:         managedDir,
			HookBinary:         hook,
			OwnershipPath:      filepath.Join(installDir, "codex-requirements-ownership.json"),
			GatewayAddr:        "127.0.0.1:18000",
			GatewayServiceName: "DefenseClawGateway",
			CodexTargetEnabled: true,
			HookContractID:     WindowsCodexManagedHookContract(hook),
		}
		if !codexContractCertifiesCompactSessionStart(opts.HookContractID) {
			t.Skipf("contract %s renders no compact SessionStart group", opts.HookContractID)
		}
		if err := os.WriteFile(opts.RequirementsPath, []byte("allowed_sandbox_modes = [\"read-only\"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil {
			t.Fatalf("install the guard: %v", err)
		}
		return opts
	}
	shapes := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) (narrowed, compact interface{}, earlierMatcher string) {
		t.Helper()
		command := windowsCodexBoundManagedHookCommand(opts.HookBinary, "SessionStart", opts.HookContractID)
		for _, group := range codexHookGroups {
			if group.eventType == "SessionStart" {
				earlierMatcher = group.matcher
			}
		}
		return windowsCodexTestNormalized(t, windowsCodexTestGroup(earlierMatcher, windowsCodexMachineHandler(command, 30))),
			windowsCodexTestNormalized(t, windowsCodexTestGroup(codexCompactSessionStartMatcher, windowsCodexMachineHandler(command, 30))),
			earlierMatcher
	}
	// narrow cuts the compact source from the installed SessionStart group,
	// as an administrator editing the file would.
	narrow := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions, matcher string) []byte {
		t.Helper()
		raw, err := os.ReadFile(opts.RequirementsPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := parseWindowsCodexRequirements(raw)
		if err != nil {
			t.Fatal(err)
		}
		groups := cfg["hooks"].(map[string]interface{})["SessionStart"].([]interface{})
		if len(groups) != 1 {
			t.Fatalf("fixture: %d SessionStart groups", len(groups))
		}
		groups[0].(map[string]interface{})["matcher"] = matcher
		edited, err := toml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opts.RequirementsPath, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		return edited
	}
	counts := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions, narrowed, compact interface{}) (int, int) {
		t.Helper()
		raw, err := os.ReadFile(opts.RequirementsPath)
		if err != nil {
			t.Fatal(err)
		}
		return windowsCodexTestCountGroup(t, raw, "SessionStart", narrowed), windowsCodexTestCountGroup(t, raw, "SessionStart", compact)
	}

	t.Run("an administrator's narrowed group survives every repair", func(t *testing.T) {
		opts := install(t)
		narrowed, compact, matcher := shapes(t, opts)
		narrow(t, opts, matcher)
		for repair := 1; repair <= 3; repair++ {
			report, err := ReconcileWindowsCodexMachineRequirements(opts)
			if err != nil || !report.OK {
				t.Fatalf("repair %d: %+v err=%v", repair, report, err)
			}
			if n, c := counts(t, opts, narrowed, compact); n != 1 || c != 1 {
				t.Fatalf("repair %d left %d narrowed and %d compact groups, want 1 and 1", repair, n, c)
			}
			if repair > 1 && report.Changed {
				t.Fatalf("repair %d of a healthy guard changed it: %+v", repair, report)
			}
		}
		if _, err := VerifyWindowsCodexMachineRequirements(opts); err != nil {
			t.Fatalf("the repaired guard does not verify: %v", err)
		}
	})

	t.Run("an earlier release's unedited group is replaced at the upgrade", func(t *testing.T) {
		opts := install(t)
		narrowed, compact, matcher := shapes(t, opts)
		// The file as a release before the compact matcher published it:
		// the ownership record and the runtime state name its hash.
		earlier := narrow(t, opts, matcher)
		raw, err := os.ReadFile(opts.OwnershipPath)
		if err != nil {
			t.Fatal(err)
		}
		state, err := parseWindowsCodexMachineOwnership(raw)
		if err != nil {
			t.Fatal(err)
		}
		state.PostimageSHA256 = windowsCodexMachineHash(earlier)
		body, err := marshalWindowsCodexMachineOwnership(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opts.OwnershipPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		runtimeRaw, err := os.ReadFile(opts.ManagedStatePath)
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := parseWindowsCodexManagedRuntimeState(runtimeRaw)
		if err != nil {
			t.Fatal(err)
		}
		runtime.RequirementsSHA256 = state.PostimageSHA256
		if body, err = marshalWindowsCodexManagedRuntimeState(runtime); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opts.ManagedStatePath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
			t.Fatalf("upgrade: %+v err=%v", report, err)
		}
		if n, c := counts(t, opts, narrowed, compact); n != 0 || c != 1 {
			t.Fatalf("the upgrade left %d earlier and %d compact groups, want 0 and 1", n, c)
		}
	})
}
