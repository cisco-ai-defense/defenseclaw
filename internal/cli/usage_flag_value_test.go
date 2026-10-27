// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	// GAP-2240: the unknown-action hint of a lifecycle group too.
	for _, group := range []string{"linux", "macos"} {
		groupCmd, _, err := rootCmd.Find([]string{"enterprise", group})
		if err != nil || groupCmd.RunE == nil {
			t.Fatalf("enterprise %s: %v", group, err)
		}
		want := "Try '/opt/defenseclaw/bin/defenseclaw-gateway enterprise " + group + " --help' for help."
		if got := groupCmd.RunE(groupCmd, []string{"frobnicate"}); got == nil || !strings.Contains(got.Error(), want) {
			t.Errorf("enterprise %s frobnicate: %v, want %q", group, got, want)
		}
	}
	t.Setenv(delegatedFromEnv, "defenseclaw")
	if got := usageMessage(set, errors.New("bad flag")); !strings.Contains(got, "Try 'defenseclaw set --help'") {
		t.Errorf("delegated usage message = %q, want the defenseclaw command", got)
	}
}

// GAP-2232: run by a relative path (./defenseclaw-gateway from
// /opt/defenseclaw/bin), the hint names the absolute path, which runs from
// any directory; a bare name found on PATH stays bare.
func TestInvokedGatewayPathResolvesARelativeInvocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps its own hints (GAP-1183)")
	}
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	t.Chdir(t.TempDir())
	want, err := filepath.Abs("defenseclaw-gateway")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"./defenseclaw-gateway":                    want,
		"defenseclaw-gateway":                      "",
		"/opt/defenseclaw/bin/defenseclaw-gateway": "/opt/defenseclaw/bin/defenseclaw-gateway",
		"./other-binary":                           "",
	}
	for arg0, expect := range cases {
		os.Args = []string{arg0}
		if got := invokedGatewayPath("defenseclaw-gateway"); got != expect {
			t.Errorf("os.Args[0] = %q: invoked path %q, want %q", arg0, got, expect)
		}
	}
}

// W4b2 review: a raw-argument scan for a flag cobra did not reach reads the
// arguments with pflag's arity. "--config --trust-anchors --unknown" sets
// --config to "--trust-anchors"; before, the scan counted it as an anchor
// request and audited a refused trust-anchor change. Where pflag parses the
// line, its own Changed is the oracle.
func TestArgsSetLongFlagReadsFlagArity(t *testing.T) {
	newSet := func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("ensure", pflag.ContinueOnError)
		fs.SetOutput(&strings.Builder{})
		for _, name := range []string{"config", "bundle", "profile"} {
			fs.String(name, "", "")
		}
		fs.StringP("trust-anchors", "t", "", "")
		fs.StringP("output", "o", "", "")
		fs.BoolP("verbose", "v", false, "")
		fs.Bool("json", false, "")
		fs.StringArray("allowed-signer", nil, "")
		fs.String("color", "", "")
		fs.Lookup("color").NoOptDefVal = "auto"
		return fs
	}
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--trust-anchors", "a.json"}, true},
		{[]string{"--trust-anchors=a.json"}, true},
		{[]string{"--trust-anchors=a.json", "extra"}, true},
		{[]string{"--config", "--trust-anchors"}, false},
		{[]string{"--config", "--trust-anchors", "--json"}, false},
		{[]string{"--bundle", "--trust-anchors", "extra"}, false},
		{[]string{"--allowed-signer", "--trust-anchors"}, false},
		{[]string{"enterprise", "windows", "ensure", "--profile", "standalone", "--config", "--trust-anchors"}, false},
		{[]string{"--config=c.yaml", "--trust-anchors", "a.json"}, true},
		{[]string{"--json", "--trust-anchors", "a.json"}, true},
		{[]string{"--color", "--trust-anchors", "a.json"}, true},
		{[]string{"--config", "--", "--trust-anchors", "a.json"}, true},
		{[]string{"--", "--trust-anchors", "a.json"}, false},
		{[]string{"-", "--trust-anchors", "a.json"}, true},
		{[]string{"-o", "--trust-anchors"}, false},
		{[]string{"-vo", "--trust-anchors"}, false},
		{[]string{"-ovalue", "--trust-anchors", "a.json"}, true},
		{[]string{"-o=x", "--trust-anchors", "a.json"}, true},
		{[]string{"-vt", "a.json"}, true},
		{[]string{"-ot", "a.json"}, false},
		// pflag rejects these; the scan reads past the error.
		{[]string{"--profile", "standalone", "--config", "--trust-anchors", "--unknown"}, false},
		{[]string{"--unknown", "--config", "--trust-anchors", "--unknown"}, false},
		{[]string{"--unknown", "--trust-anchors=a.json"}, true},
		{[]string{"--unknown", "--config", "--", "--trust-anchors=a.json"}, true},
		{[]string{"--unknown", "--", "--trust-anchors", "a.json"}, false},
		{[]string{"-x", "--trust-anchors", "a.json"}, true},
		{[]string{"--=x", "--trust-anchors", "a.json"}, true},
		{[]string{"---trust-anchors", "a.json"}, false},
		{[]string{"--trust-anchors"}, true},
		{[]string{"--config"}, false},
	} {
		if got := argsSetLongFlag(newSet(), tc.args, "trust-anchors"); got != tc.want {
			t.Errorf("argsSetLongFlag(%q) = %v, want %v", tc.args, got, tc.want)
		}
		fs := newSet()
		if fs.Parse(tc.args) == nil && fs.Changed("trust-anchors") != tc.want {
			t.Errorf("pflag sets --trust-anchors from %q: %v, case says %v", tc.args, fs.Changed("trust-anchors"), tc.want)
		}
	}
}
