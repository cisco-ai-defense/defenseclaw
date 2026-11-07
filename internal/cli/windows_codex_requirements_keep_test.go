// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Only the uninstall keeps a link at the Codex machine-policy folder
// (GAP-0773). These rows pin which caller gets which removal.

func sameFunc(a, b any) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// The reconcile that turns Codex off calls connector.RemoveWindowsCodexMachineRequirements
// itself, so no cli variable names it: TestWindowsCodexMachineNonTeardownRemovalsRefuseALink
// (internal/gateway/connector) drives it over a real junction.
func TestWindowsCodexRemovalWiringKeepsALinkForTheUninstallOnly(t *testing.T) {
	strict := connector.RemoveWindowsCodexMachineRequirements
	teardown := connector.RemoveWindowsCodexMachineRequirementsForTeardown
	for name, got := range map[string]any{
		"hidden remove action": windowsCodexRequirementsRemover,
		"guardian remover":     enterpriseHookCodexRequirementsRemover,
	} {
		if !sameFunc(got, strict) {
			t.Errorf("%s is not the strict removal", name)
		}
	}
	for name, got := range map[string]any{
		"hidden remove --uninstall": windowsCodexRequirementsTeardownRemover,
		"teardown removal":          windowsManagedHooksTeardownCodexRemover,
	} {
		if !sameFunc(got, teardown) {
			t.Errorf("%s is not the uninstall removal", name)
		}
	}
}

// The hidden remove action keeps a link only with --uninstall, which no other
// action has.
func TestWindowsCodexRequirementsRemoveUninstallFlag(t *testing.T) {
	savedPreflight, savedLayout := enterpriseHooksPlatformPreflight, windowsCodexRequirementsLayoutResolver
	savedStrict, savedTeardown := windowsCodexRequirementsRemover, windowsCodexRequirementsTeardownRemover
	t.Cleanup(func() {
		enterpriseHooksPlatformPreflight, windowsCodexRequirementsLayoutResolver = savedPreflight, savedLayout
		windowsCodexRequirementsRemover, windowsCodexRequirementsTeardownRemover = savedStrict, savedTeardown
	})
	enterpriseHooksPlatformPreflight = func() error { return nil }
	windowsCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		return connector.WindowsCodexMachineRequirementsOptions{}, nil
	}
	var called []string
	windowsCodexRequirementsRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
		called = append(called, "strict")
		return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
	}
	windowsCodexRequirementsTeardownRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
		called = append(called, "teardown")
		return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
	}
	run := func(args ...string) error {
		command := newWindowsCodexRequirementsCommand()
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		return command.Execute()
	}
	if err := run("remove", "--json"); err != nil {
		t.Fatal(err)
	}
	if err := run("remove", "--json", "--uninstall"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(called, ",") != "strict,teardown" {
		t.Fatalf("remove ran %v, want the strict removal, then the uninstall removal with --uninstall", called)
	}
	for _, action := range []string{"inspect", "reconcile", "verify"} {
		if err := run(action, "--json", "--uninstall"); err == nil {
			t.Errorf("%s accepted --uninstall", action)
		}
	}
}

// A link at the Codex folder with DefenseClaw-named files behind it makes
// every caller but the uninstall refuse on the link: the hidden remove action,
// the guardian remover and the reconcile with Codex disabled. None reports a
// removed state or a binary that is safe to remove, and nothing behind the
// link changes.
func TestWindowsCodexRemovalsOtherThanTheUninstallsRefuseALink(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the Codex removal requires an elevated Administrator or LocalSystem token")
	}
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "codex-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	decoys := map[string]string{}
	for _, name := range []string{
		".defenseclaw-managed-hooks.lock", ".defenseclaw-managed-hooks.state", "requirements.toml",
	} {
		decoys[name] = "decoy " + name
		if err := os.WriteFile(filepath.Join(target, name), []byte(decoys[name]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vendor := filepath.Join(root, "OpenAI")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(vendor, "Codex")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	hook := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	opts := connector.WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   filepath.Join(junction, "requirements.toml"),
		ManagedStatePath:   filepath.Join(junction, ".defenseclaw-managed-hooks.state"),
		ManagedDir:         filepath.Dir(hook),
		HookBinary:         hook,
		OwnershipPath:      filepath.Join(root, "codex-requirements-ownership.json"),
		GatewayAddr:        "127.0.0.1:18000",
		GatewayServiceName: "DefenseClawGateway",
		HookContractID:     connector.WindowsCodexManagedHookContract(hook),
	}
	disabled := opts
	disabled.CodexTargetEnabled = false
	for _, tc := range []struct {
		name string
		run  func() (connector.WindowsCodexMachineRequirementsReport, error)
	}{
		{"hidden remove action", func() (connector.WindowsCodexMachineRequirementsReport, error) {
			return windowsCodexRequirementsRemover(opts)
		}},
		{"guardian remover", func() (connector.WindowsCodexMachineRequirementsReport, error) {
			return enterpriseHookCodexRequirementsRemover(opts)
		}},
		{"reconcile with Codex disabled", func() (connector.WindowsCodexMachineRequirementsReport, error) {
			return windowsCodexRequirementsReconciler(disabled)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.run()
			if err == nil {
				t.Fatalf("a link at the Codex folder was not refused: %+v", report)
			}
			if report.OK || report.SafeToRemoveBinary || report.ManagedStateRemovedOrAbsent ||
				report.LinkKept != "" || strings.Contains(report.Disposition, "link_kept") {
				t.Fatalf("a refused removal reported success: %+v", report)
			}
			for name, want := range decoys {
				got, readErr := os.ReadFile(filepath.Join(target, name))
				if readErr != nil || !bytes.Equal(got, []byte(want)) {
					t.Fatalf("%s behind the link changed: %q, %v", name, got, readErr)
				}
			}
			entries, _ := os.ReadDir(target)
			if len(entries) != len(decoys) {
				t.Fatalf("the folder behind the link now holds %d entries, want %d", len(entries), len(decoys))
			}
		})
	}
}

// The uninstall Codex removal may go on after a kept link only when the
// report names the link; any other report needs OK and SafeToRemoveBinary, and
// none may leave a reference to the owned binary tree.
func TestWindowsManagedHooksTeardownAcceptsAKeptLinkOnlyByName(t *testing.T) {
	const link = `C:\ProgramData\OpenAI\Codex`
	for _, tc := range []struct {
		name   string
		report connector.WindowsCodexMachineRequirementsReport
		want   bool
	}{
		{"kept link, named", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "link_kept", LinkKept: link}, true},
		{"kept link, not named", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "link_kept"}, false},
		{"kept link, not OK", connector.WindowsCodexMachineRequirementsReport{
			Disposition: "link_kept", LinkKept: link}, false},
		{"kept link, a reference survives", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "link_kept", LinkKept: link, SurvivingOwnedPathReferences: 1}, false},
		{"ordinary report, not safe to remove the binary", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "removed"}, false},
		{"ordinary report, safe", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "removed", SafeToRemoveBinary: true}, true},
		{"ordinary report, safe, a reference survives", connector.WindowsCodexMachineRequirementsReport{
			OK: true, Disposition: "removed", SafeToRemoveBinary: true, SurvivingOwnedPathReferences: 2}, false},
		{"not OK", connector.WindowsCodexMachineRequirementsReport{SafeToRemoveBinary: true}, false},
	} {
		if got := windowsManagedHooksTeardownCodexRemovalClean(tc.report); got != tc.want {
			t.Errorf("%s: accepted = %v, want %v", tc.name, got, tc.want)
		}
	}
}
