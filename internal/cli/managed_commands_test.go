// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedCommandsGoldenPath is the table the documentation generator
// (scripts/gen_managed_commands_docs.py) turns into the managed-commands page.
var managedCommandsGoldenPath = filepath.Join("testdata", "managed_commands.json")

// TestManagedCommandsGolden pins the table the docs page is generated from.
// Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1 after an intended change, then
// run scripts/gen_managed_commands_docs.py.
func TestManagedCommandsGolden(t *testing.T) {
	var got bytes.Buffer
	encoder := json.NewEncoder(&got)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(buildManagedCommandsDoc()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(managedCommandsGoldenPath, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(managedCommandsGoldenPath)
	if err != nil {
		t.Fatalf("read %s (DEFENSECLAW_UPDATE_GOLDEN=1 writes it): %v", managedCommandsGoldenPath, err)
	}
	// A Windows checkout gives the golden CRLF line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("the managed command table changed; regenerate %s with DEFENSECLAW_UPDATE_GOLDEN=1, then run scripts/gen_managed_commands_docs.py", managedCommandsGoldenPath)
	}
}

// The launcher decides from the table. The ordinary commands a user runs stay
// offered; everything else, and a near variant of an offered command, is
// refused.
func TestLauncherOffersWhatTheTableListsAndNothingElse(t *testing.T) {
	offered := [][]string{
		nil,
		{"-h"}, {"--help"}, {"--version"},
		{"help"}, {"help", "sandbox"}, {"help", "status"}, {"help", "--help"}, {"help", "-h"},
		{"status"}, {"status", "--json"},
		{"sandbox"}, {"sandbox", "run", "claude"}, {"sandbox", "policy", "explain"},
		{"guardrail", "profile", "explain"}, {"guardrail", "profile", "explain", "--json"},
	}
	for _, args := range offered {
		if !launcherOffers(args) {
			t.Errorf("launcher refuses %q", args)
		}
	}
	refused := [][]string{
		{"doctor"}, {"alerts"}, {"tui"}, {"upgrade"}, {"rollback"}, {"setup"},
		{"config", "set", "x", "y"}, {"skill", "list"}, {"mcp", "list"}, {"plugin", "list"}, {"tool", "block", "x"},
		{"policy", "show"}, {"audit", "export"}, {"enterprise", "linux", "status"},
		{"guardrail"}, {"guardrail", "status"}, {"guardrail", "profile"}, {"guardrail", "profile", "show"},
		{"help", "doctor"}, {"help", "guardrail"}, {"sandboxes"}, {"statuses"}, {"--versions"}, {""},
	}
	for _, args := range refused {
		if launcherOffers(args) {
			t.Errorf("launcher offers %q", args)
		}
	}
}

// Each row's launcher cell is what launcherOffers answers for the row's own
// arguments, and a row with no launcher pattern is refused for every probe.
func TestManagedCommandCellsAgreeWithTheLauncher(t *testing.T) {
	for _, row := range buildManagedCommandsDoc().Commands {
		if row.Linux != row.MacOS {
			t.Errorf("%s: the launcher is one binary on Linux and macOS, but the cells differ: %s, %s", row.Command, row.Linux, row.MacOS)
		}
	}
	for _, command := range managedCommands {
		for _, pattern := range command.Launcher {
			if !launcherOffers(pattern.words) {
				t.Errorf("%s: the launcher refuses its own pattern %q", command.Command, pattern.words)
			}
		}
		if len(command.Launcher) == 0 {
			for _, probe := range command.Probes {
				if launcherOffers(probe) {
					t.Errorf("%s: the launcher runs %q but the row lists no launcher pattern", command.Command, probe)
				}
			}
		}
	}
}

// The Windows column is read from the binary: the commands the managed
// Windows install answers instead of running are exactly the rows marked
// Refused, and every other value matches what the command tree and the
// elevation check do.
func TestManagedCommandsMatchTheWindowsBinary(t *testing.T) {
	restoreHost, restoreAdmin, restoreCaller := managedHostWindowsStandalone, auditExportManagedHost, auditExportCallerIsAdministrator
	t.Cleanup(func() {
		managedHostWindowsStandalone, auditExportManagedHost, auditExportCallerIsAdministrator = restoreHost, restoreAdmin, restoreCaller
	})
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	auditExportManagedHost = func() bool { return true }
	auditExportCallerIsAdministrator = func() bool { return false }
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv("DEFENSECLAW_HOME", "")

	// The installed binary's root: the commands it serves are not answered.
	answers := &cobra.Command{Use: "defenseclaw"}
	served := map[string]bool{}
	for _, command := range rootCmd.Commands() {
		served[command.Name()] = true
		answers.AddCommand(&cobra.Command{Use: command.Name()})
	}
	addManagedWindowsSetupAnswer(answers)
	answered := map[string]bool{}
	for _, command := range answers.Commands() {
		if !served[command.Name()] {
			answered[command.Name()] = true
		}
	}
	// config set and unset are answered on the real config command.
	for _, verb := range []string{"set", "unset"} {
		child, _, err := configCmd.Find([]string{verb})
		if err != nil || child == configCmd || !child.Hidden {
			t.Fatalf("config %s has no managed answer: %v", verb, err)
		}
	}

	wantAnswered := map[string]bool{}
	for _, command := range managedCommands {
		for _, probe := range command.Probes {
			real, _, err := rootCmd.Find(probe)
			installed := err == nil && real != rootCmd && real.Name() == probe[len(probe)-1]
			switch command.Windows {
			case managedRefused:
				if probe[0] != "config" {
					wantAnswered[probe[0]] = true
				}
				if probe[0] != "config" && !answered[probe[0]] {
					t.Errorf("%s: marked Refused but the managed Windows binary has no answer for %q", command.Command, probe[0])
				}
			case managedOffered:
				if !installed || answered[probe[0]] {
					t.Errorf("%s: marked Offered but %q is %s", command.Command, probe, map[bool]string{true: "answered, not run", false: "not in the command tree"}[answered[probe[0]]])
				}
			case managedUnsupported:
				if !installed || sandboxHostRefusal("windows", "amd64", false) == nil {
					t.Errorf("%s: marked Not supported but sandboxes run on Windows", command.Command)
				}
			case managedAdminOnly:
				cmd := real
				var err error
				if probe[0] == "policy" {
					err = policyConfigOnlyPreRunE(cmd, nil)
				} else {
					err = prepareManagedAuditExportEnvironment()
				}
				if !installed || err == nil || commandExitCode(err) != enterprisestatus.WindowsExitAccessDenied {
					t.Errorf("%s: marked Administrators only but a standard account gets %v", command.Command, err)
				}
			default:
				t.Errorf("%s: unknown availability %q", command.Command, command.Windows)
			}
		}
	}
	var gotNames, wantNames []string
	for name := range answered {
		gotNames = append(gotNames, name)
	}
	for name := range wantAnswered {
		wantNames = append(wantNames, name)
	}
	sort.Strings(gotNames)
	sort.Strings(wantNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("the managed Windows binary answers %v; the table marks %v Refused: add the missing row or answer", gotNames, wantNames)
	}
}

// Every row names a command the per-user claim can be checked against
// (cli/tests/test_managed_commands_table.py reads the same file).
func TestManagedCommandRowsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, command := range managedCommands {
		if seen[command.Command] || strings.TrimSpace(command.Note) == "" {
			t.Errorf("row %q is duplicated or has no note", command.Command)
		}
		seen[command.Command] = true
	}
}
