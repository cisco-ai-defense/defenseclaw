// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// rel-1-0-3 GAP-0328: on a managed Windows computer `defenseclaw tui` was
// "unknown command" with the generic usage and exit 2. The TUI is part of the
// per-user CLI, which a managed computer does not install, so the command
// answers that and names the administrator's checks, with exit 3 like the
// other managed answers.
func TestManagedWindowsTUISaysItIsNotInstalledAndNamesTheNextStep(t *testing.T) {
	restoreHost, restoreCLI := managedHostWindowsStandalone, managedWindowsAdminCLI
	t.Cleanup(func() { managedHostWindowsStandalone, managedWindowsAdminCLI = restoreHost, restoreCLI })
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	managedWindowsAdminCLI = func() string { return `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe` }
	root := &cobra.Command{Use: "defenseclaw", PersistentPreRunE: rootPersistentPreRunE}
	addManagedWindowsSetupAnswer(root)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"tui"})
	err := root.Execute()
	if commandExitCode(err) != 3 || err == nil {
		t.Fatalf("tui on a managed Windows computer: exit %d, %v", commandExitCode(err), err)
	}
	for _, want := range []string{
		"managed by your organization",
		"the DefenseClaw TUI is not installed on this computer",
		"enterprise windows status --profile standalone",
		"enterprise policy show --user ",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("tui answer %q lacks %q", err.Error(), want)
		}
	}
	if !strings.HasSuffix(err.Error(), "Nothing was changed.") || strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("tui answer %q", err.Error())
	}
	var out strings.Builder
	root.SetOut(&out)
	root.SetArgs([]string{"tui", "--help"})
	if err := root.Execute(); err != nil || !strings.Contains(out.String(), "Usage:") ||
		!strings.Contains(out.String(), "TUI is not installed") {
		t.Fatalf("tui --help: err %v, output %q", err, out.String())
	}
}
