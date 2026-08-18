// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSandboxCommandsRejectWindowsBeforeRunEOrExec(t *testing.T) {
	originalHostOS := sandboxHostOS
	originalExecCommand := sandboxExecCommand
	sandboxHostOS = func() string { return "windows" }
	execCalls := 0
	sandboxExecCommand = func(name string, args ...string) *exec.Cmd {
		execCalls++
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	t.Cleanup(func() {
		sandboxHostOS = originalHostOS
		sandboxExecCommand = originalExecCommand
	})

	tests := []struct {
		name string
		args []string
		run  func(*cobra.Command, []string) error
	}{
		{name: "start", run: sandboxStartCmd.RunE},
		{name: "stop", run: sandboxStopCmd.RunE},
		{name: "restart", run: sandboxRestartCmd.RunE},
		{name: "status", run: sandboxStatusCmd.RunE},
		{name: "exec", args: []string{"printf", "ok"}, run: sandboxExecCmd.RunE},
		{name: "shell", run: sandboxShellCmd.RunE},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runCalls := 0
			root := &cobra.Command{Use: "defenseclaw-gateway", SilenceErrors: true, SilenceUsage: true}
			group := &cobra.Command{Use: "sandbox", PersistentPreRunE: runSandboxPersistentPreRunE}
			child := &cobra.Command{
				Use: test.name,
				RunE: func(cmd *cobra.Command, args []string) error {
					runCalls++
					return test.run(cmd, args)
				},
			}
			group.AddCommand(child)
			root.AddCommand(group)
			root.SetArgs(append([]string{"sandbox", test.name}, test.args...))

			err := root.Execute()
			if err == nil {
				t.Fatal("Windows sandbox command returned empty success")
			}
			if !strings.Contains(err.Error(), "unsupported on native Windows") {
				t.Fatalf("error = %q, want native-Windows unsupported message", err)
			}
			if runCalls != 0 {
				t.Fatalf("RunE called %d times, want 0", runCalls)
			}
			if execCalls != 0 {
				t.Fatalf("subprocess executor called %d times, want 0", execCalls)
			}
		})
	}
}

func TestSandboxLinuxRunsParentHookAndExistingStatusRunE(t *testing.T) {
	originalHostOS := sandboxHostOS
	originalExecCommand := sandboxExecCommand
	originalRootHook := rootCmd.PersistentPreRunE
	sandboxHostOS = func() string { return "linux" }
	parentHookCalls := 0
	rootCmd.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		parentHookCalls++
		return nil
	}
	var commands []string
	sandboxExecCommand = func(name string, args ...string) *exec.Cmd {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return exec.Command(os.Args[0], "-test.run=^$")
	}
	t.Cleanup(func() {
		sandboxHostOS = originalHostOS
		sandboxExecCommand = originalExecCommand
		rootCmd.PersistentPreRunE = originalRootHook
	})

	root := &cobra.Command{Use: "defenseclaw-gateway", SilenceErrors: true, SilenceUsage: true}
	group := &cobra.Command{Use: "sandbox", PersistentPreRunE: runSandboxPersistentPreRunE}
	runCalls := 0
	status := &cobra.Command{
		Use: "status",
		RunE: func(cmd *cobra.Command, args []string) error {
			runCalls++
			return sandboxStatusCmd.RunE(cmd, args)
		},
	}
	group.AddCommand(status)
	root.AddCommand(group)
	root.SetArgs([]string{"sandbox", "status"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Linux status returned error: %v", err)
	}
	if parentHookCalls != 1 || runCalls != 1 {
		t.Fatalf("parent hook calls = %d, RunE calls = %d; want 1 each", parentHookCalls, runCalls)
	}
	if len(commands) != 2 || !strings.Contains(commands[0], "openshell-sandbox.service") ||
		!strings.Contains(commands[1], "defenseclaw-gateway.service") {
		t.Fatalf("status command wiring changed: %v", commands)
	}
}

func TestSandboxGroupPlatformGateCoversExpectedChildren(t *testing.T) {
	if sandboxCmd.PersistentPreRunE == nil {
		t.Fatal("sandbox group has no persistent platform gate")
	}
	want := map[string]bool{
		"start": true, "stop": true, "restart": true,
		"status": true, "exec": true, "shell": true,
	}
	for _, child := range sandboxCmd.Commands() {
		delete(want, child.Name())
	}
	if len(want) != 0 {
		t.Fatalf("sandbox children missing from command group: %v", want)
	}
}

func TestSandboxExecParsesHelpAndPreservesCommandFlags(t *testing.T) {
	if sandboxExecCmd.DisableFlagParsing {
		t.Fatal("sandbox exec must leave flag parsing enabled so --help is handled before persistent startup hooks")
	}

	sandboxExecCmd.InitDefaultHelpFlag()
	sandboxExecNetns = false
	if err := sandboxExecCmd.Flags().Set("netns", "false"); err != nil {
		t.Fatalf("reset --netns before test: %v", err)
	}
	if err := sandboxExecCmd.ParseFlags(nil); err != nil {
		t.Fatalf("reset args before test: %v", err)
	}
	t.Cleanup(func() {
		sandboxExecNetns = false
		_ = sandboxExecCmd.Flags().Set("netns", "false")
		_ = sandboxExecCmd.ParseFlags(nil)
	})

	if err := sandboxExecCmd.ParseFlags([]string{"--netns", "--", "printf", "--help"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if !sandboxExecNetns {
		t.Fatal("--netns was not parsed")
	}
	if got, want := sandboxExecCmd.Flags().Args(), []string{"printf", "--help"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("command args = %q, want %q", got, want)
	}
}
