// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandExitCode(t *testing.T) {
	cause := errors.New("install failed")
	for name, test := range map[string]struct {
		err  error
		want int
	}{
		"plain failure":   {err: cause, want: 1},
		"labelled":        {err: withExitCode(cause, 1603), want: 1603},
		"labelled deeper": {err: fmt.Errorf("context: %w", withExitCode(cause, 1603)), want: 1603},
		// The first code wins: an outer default must not overwrite the code an
		// inner failure deliberately chose.
		"already labelled": {err: withExitCode(withExitCode(cause, 3010), 1603), want: 3010},
	} {
		t.Run(name, func(t *testing.T) {
			if got := commandExitCode(test.err); got != test.want {
				t.Fatalf("commandExitCode = %d, want %d", got, test.want)
			}
			if !errors.Is(test.err, cause) {
				t.Fatal("labelling a failure must preserve its cause")
			}
		})
	}
}

func TestWithExitCodeKeepsSuccessUnlabelled(t *testing.T) {
	if err := withExitCode(nil, 1603); err != nil {
		t.Fatalf("withExitCode(nil) = %v, want nil", err)
	}
	if got := commandExitCode(nil); got != 1 {
		t.Fatalf("commandExitCode(nil) = %d, want the generic failure result", got)
	}
}

// GAP-1405: an unknown flag on a gateway command is a usage error (rc 2)
// with the usage line and a --help pointer; hook trees keep their own codes.
func TestUnknownFlagIsAUsageError(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	parseErr := cmd.ParseFlags([]string{"--bogus"})
	if parseErr == nil {
		t.Fatal("status accepted --bogus")
	}
	got := cmd.FlagErrorFunc()(cmd, parseErr)
	if commandExitCode(got) != 2 {
		t.Fatalf("exit = %d, want 2", commandExitCode(got))
	}
	if !strings.Contains(got.Error(), "Usage: ") || !strings.Contains(got.Error(), "status --help") {
		t.Fatalf("missing usage/help pointer: %v", got)
	}
	root, hook := &cobra.Command{Use: "defenseclaw-gateway"}, &cobra.Command{Use: "hook"}
	root.AddCommand(hook)
	if out := usageFlagError(hook, parseErr); out != parseErr {
		t.Fatalf("hook tree must keep its own flag error, got %v", out)
	}
}

// GAP-1644: run by "defenseclaw audit export", a usage error names the
// command the user typed, not the gateway binary.
func TestDelegatedUsageErrorNamesTheTypedCommand(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"audit", "export"})
	if err != nil {
		t.Fatal(err)
	}
	parseErr := cmd.ParseFlags([]string{"--bogus"})
	if parseErr == nil {
		t.Fatal("audit export accepted --bogus")
	}
	t.Setenv(delegatedFromEnv, "defenseclaw")
	got := cmd.FlagErrorFunc()(cmd, parseErr)
	if commandExitCode(got) != 2 || !errors.Is(got, parseErr) {
		t.Fatalf("exit = %d, err = %v", commandExitCode(got), got)
	}
	if strings.Contains(got.Error(), "defenseclaw-gateway") ||
		!strings.Contains(got.Error(), "Try 'defenseclaw audit export --help'") {
		t.Fatalf("usage must name defenseclaw audit export: %v", got)
	}
	t.Setenv(delegatedFromEnv, "")
	if got := cmd.FlagErrorFunc()(cmd, parseErr); !strings.Contains(got.Error(), "defenseclaw-gateway audit export --help") {
		t.Fatalf("direct run must name the gateway: %v", got)
	}
}

// GAP-1549: a stray argument or an unknown subcommand is a usage error with
// rc 2; hook trees keep cobra's own handling, and enterprise hooks status
// rejects one too (GAP-2330).
func TestStrayArgumentsAreUsageErrors(t *testing.T) {
	installUsageArgChecks(rootCmd)
	for _, path := range [][]string{{"status"}, {"watchdog"}, {"policy", "show"}, {"enterprise", "hooks", "status"}} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		got := cmd.ValidateArgs([]string{"bogus"})
		if commandExitCode(got) != 2 || !strings.Contains(fmt.Sprint(got), "Usage: ") {
			t.Fatalf("%v bogus: rc %d, %v", path, commandExitCode(got), got)
		}
		if err := cmd.ValidateArgs(nil); err != nil {
			t.Fatalf("%v without arguments: %v", path, err)
		}
	}
	for _, path := range [][]string{{"connector", "launch"}} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.ValidateArgs([]string{"x"}); err != nil {
			t.Fatalf("%v must keep accepting arguments: %v", path, err)
		}
	}

	var stderr strings.Builder
	rootCmd.SetErr(&stderr)
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetErr(nil) })
	rootCmd.SetArgs([]string{"rulepack", "bogus"})
	if rc := ExecuteContext(context.Background()); rc != 2 {
		t.Fatalf("rulepack bogus: rc %d, want 2", rc)
	}
	want := "unknown command \"bogus\" for \"defenseclaw-gateway rulepack\""
	if !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "rulepack --help") {
		t.Fatalf("rulepack bogus stderr = %q", stderr.String())
	}
	stderr.Reset()
	rootCmd.SetArgs([]string{"bogus-cmd"})
	if rc := ExecuteContext(context.Background()); rc != 2 {
		t.Fatalf("bogus-cmd: rc %d, want 2 (%s)", rc, stderr.String())
	}
}
