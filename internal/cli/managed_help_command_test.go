// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0830: the command table lists `defenseclaw help` and `help <command>` as
// Offered on a managed Windows computer, next to --help and --version. Cobra
// runs the generated help command through the root pre-run, so a standard
// user with no per-user config got the managed refusal. Every help request
// the table's own help row lists now prints help and exits 0.
func TestManagedWindowsHelpCommandRunsWithoutPerUserConfig(t *testing.T) {
	previous := managedHostWindowsStandalone
	t.Cleanup(func() { managedHostWindowsStandalone = previous })
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())

	// Printing help on a managed computer rewrites the tree's help text for
	// the rest of the process (applyManagedHostHelp); put it back.
	restoreText := snapshotCommandHelpText(rootCmd)
	t.Cleanup(restoreText)

	var requests [][]string
	for _, command := range managedCommands {
		if command.Windows != managedOffered || len(command.Probes) != 0 {
			continue
		}
		for _, pattern := range command.Launcher {
			if len(pattern.words) > 0 && pattern.words[0] == "help" {
				requests = append(requests, pattern.words)
			}
		}
	}
	if len(requests) == 0 {
		t.Fatal("the command table lists no help request")
	}

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
	for _, args := range requests {
		out.Reset()
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if !strings.Contains(out.String(), "Usage:") || strings.Contains(out.String(), "managed by your organization") {
			t.Errorf("%v: printed %q, want the help text", args, out.String())
		}
	}
}

// The bootstrap skip is for the help command cobra adds to the root, not for
// any command that shares its name or any other command.
func TestDaemonBootstrapSkipCoversOnlyTheRootHelpCommand(t *testing.T) {
	root := &cobra.Command{Use: "defenseclaw"}
	help := &cobra.Command{Use: "help"}
	status := &cobra.Command{Use: "status"}
	nested := &cobra.Command{Use: "help"}
	group := &cobra.Command{Use: "group"}
	annotated := &cobra.Command{Use: "scrub", Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"}}
	root.AddCommand(help, status, group, annotated)
	group.AddCommand(nested)
	for cmd, want := range map[*cobra.Command]bool{help: true, annotated: true, status: false, nested: false, root: false, nil: false} {
		if got := skipsDaemonBootstrap(cmd); got != want {
			name := "<nil>"
			if cmd != nil {
				name = cmd.CommandPath()
			}
			t.Errorf("skipsDaemonBootstrap(%s) = %v, want %v", name, got, want)
		}
	}
}

// snapshotCommandHelpText records the help text, visibility and flag usage of
// every command under root and returns a function that puts them back.
func snapshotCommandHelpText(root *cobra.Command) (restore func()) {
	var undo []func()
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		short, long, hidden := c.Short, c.Long, c.Hidden
		undo = append(undo, func() { c.Short, c.Long, c.Hidden = short, long, hidden })
		for _, set := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			set.VisitAll(func(f *pflag.Flag) {
				usage := f.Usage
				undo = append(undo, func() { f.Usage = usage })
			})
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return func() {
		for _, f := range undo {
			f()
		}
	}
}
