// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// GAP-1989: a malformed typed flag value names what the flag takes, not
// pflag's strconv parser text; usage errors keep rc 2 and exempt trees keep
// their own exit status.
func TestBadFlagValueNamesWhatTheFlagTakes(t *testing.T) {
	root := &cobra.Command{Use: "defenseclaw-gateway"}
	status := &cobra.Command{Use: "status", RunE: func(*cobra.Command, []string) error { return nil }}
	enterprise := &cobra.Command{Use: "enterprise"}
	enterpriseStatus := &cobra.Command{Use: "status", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(status, enterprise)
	enterprise.AddCommand(enterpriseStatus)
	for _, c := range []*cobra.Command{status, enterpriseStatus} {
		c.Flags().Bool("json", false, "")
		c.Flags().Int("limit", 0, "")
	}
	cases := map[string]string{
		"--json=maybe": `--json takes true or false, not "maybe"`,
		"--limit=ten":  `--limit takes a whole number, not "ten"`,
	}
	for arg, want := range cases {
		parseErr := status.ParseFlags([]string{arg})
		if parseErr == nil {
			t.Fatalf("%s parsed", arg)
		}
		got := usageFlagError(status, parseErr)
		if commandExitCode(got) != 2 || !errors.Is(got, parseErr) {
			t.Fatalf("%s: exit = %d, err = %v", arg, commandExitCode(got), got)
		}
		if !strings.HasPrefix(got.Error(), want+"\nUsage: ") || strings.Contains(got.Error(), "strconv") {
			t.Errorf("%s: error %q, want it to start with %q", arg, got.Error(), want)
		}
		parseErr = enterpriseStatus.ParseFlags([]string{arg})
		got = usageFlagError(enterpriseStatus, parseErr)
		if got.Error() != want || commandExitCode(got) != 1 || !errors.Is(got, parseErr) {
			t.Errorf("%s in an exempt tree: %q (exit %d), want %q with its own exit status", arg, got, commandExitCode(got), want)
		}
	}
}

// GAP-2189: run by its absolute path (the enterprise rpm puts nothing on
// PATH), a usage error names that path, so the hint runs as typed.
func TestUsageMessageNamesTheInvokedPath(t *testing.T) {
	previous := invokedGatewayPath
	t.Cleanup(func() { invokedGatewayPath = previous })
	invokedGatewayPath = func(string) string { return "/opt/defenseclaw/bin/defenseclaw-gateway" }
	root := &cobra.Command{Use: "defenseclaw-gateway"}
	set := &cobra.Command{Use: "set", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(set)
	got := usageMessage(set, errors.New("bad flag"))
	want := "bad flag\nUsage: /opt/defenseclaw/bin/defenseclaw-gateway set\n" +
		"Try '/opt/defenseclaw/bin/defenseclaw-gateway set --help' for help."
	if got != want {
		t.Errorf("usage message = %q, want %q", got, want)
	}
	t.Setenv(delegatedFromEnv, "defenseclaw")
	if got := usageMessage(set, errors.New("bad flag")); !strings.Contains(got, "Try 'defenseclaw set --help'") {
		t.Errorf("delegated usage message = %q, want the defenseclaw command", got)
	}
}
