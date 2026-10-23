// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLaunchAgentLabelCarriesTheGatewayTag(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := LaunchAgentLabel(SandboxAgentBase, digest); got != SandboxAgentBase+".0123456789ab" {
		t.Fatalf("LaunchAgentLabel = %q", got)
	}
	for _, digest := range []string{"", "0123", "0123456789AB" + "cdef", "not-a-hex-digest"} {
		if got := LaunchAgentLabel(SandboxAgentBase, digest); got != SandboxAgentBase {
			t.Errorf("LaunchAgentLabel(%q) = %q, want the bare base", digest, got)
		}
	}
	for label, want := range map[string]bool{
		SandboxAgentBase:                       true,
		SandboxAgentBase + ".0123456789ab":     true,
		SandboxAgentBase + ".0123456789a":      false,
		SandboxAgentBase + ".0123456789abc":    false,
		SandboxAgentBase + ".0123456789AB":     false,
		GatewayAgentBase + ".0123456789ab":     false,
		"com.cisco.defenseclaw.gateway":        false,
		SandboxAgentBase + "x.0123456789ab":    false,
		SandboxAgentBase + ".0123456789ab.old": false,
	} {
		if got := IsLaunchAgentLabel(SandboxAgentBase, label); got != want {
			t.Errorf("IsLaunchAgentLabel(%q) = %v, want %v", label, got, want)
		}
	}
}

func TestLaunchAgentLabelsInReadsTheDomainServices(t *testing.T) {
	listing := []byte("user/501 = {\n\ttype = user\n\tservices = {\n" +
		"\t\t       0      -\tcom.apple.Finder\n" +
		"\t\t       0     -9\tcom.cisco.defenseclaw.sandbox\n" +
		"\t\t     812      0\tcom.cisco.defenseclaw.sandbox.0123456789ab\n" +
		"\t\t       0      -\tcom.cisco.defenseclaw.openshell-gateway.aaaaaaaaaaaa\n" +
		"\t}\n}\n")
	if got, want := LaunchAgentLabelsIn(listing, SandboxAgentBase), []string{SandboxAgentBase, SandboxAgentBase + ".0123456789ab"}; !slices.Equal(got, want) {
		t.Fatalf("sandbox labels = %v, want %v", got, want)
	}
	if got, want := LaunchAgentLabelsIn(listing, GatewayAgentBase), []string{GatewayAgentBase + ".aaaaaaaaaaaa"}; !slices.Equal(got, want) {
		t.Fatalf("gateway labels = %v, want %v", got, want)
	}
}

// FindLaunchAgent names the tagged plist an upgrade installed, not the bare
// one 1.0.0 to 1.0.3 left (GAP-0206).
func TestFindLaunchAgentPrefersTheNewestTaggedPlist(t *testing.T) {
	dir := t.TempDir()
	if label, plist := FindLaunchAgent(dir, SandboxAgentBase); label != SandboxAgentBase || plist != filepath.Join(dir, SandboxAgentBase+".plist") {
		t.Fatalf("empty folder: %q %q", label, plist)
	}
	write := func(name string, at time.Time) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("<plist/>"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	write(SandboxAgentBase+".plist", now)
	write(SandboxAgentBase+".aaaaaaaaaaaa.plist", now.Add(-time.Hour))
	write(SandboxAgentBase+".bbbbbbbbbbbb.plist", now.Add(-time.Minute))
	write(GatewayAgentBase+".cccccccccccc.plist", now)
	if label, plist := FindLaunchAgent(dir, SandboxAgentBase); label != SandboxAgentBase+".bbbbbbbbbbbb" || plist != filepath.Join(dir, label+".plist") {
		t.Fatalf("FindLaunchAgent = %q %q", label, plist)
	}
	if label, _ := FindLaunchAgent(dir, GatewayAgentBase); label != GatewayAgentBase+".cccccccccccc" {
		t.Fatalf("gateway label = %q", label)
	}
}

type launchAgentPrintRunner map[string]string

func (r launchAgentPrintRunner) Output(_ context.Context, cmd Command) ([]byte, error) {
	line := cmd.Name + " " + strings.Join(cmd.Args, " ")
	if out, ok := r[line]; ok {
		return []byte(out), nil
	}
	return []byte("Could not find service"), errors.New("exit status 113")
}

func (r launchAgentPrintRunner) Run(ctx context.Context, cmd Command) error {
	_, err := r.Output(ctx, cmd)
	return err
}

// The doctor reads the job of the installed, tagged label, which is the one
// the sandbox daemon starts (GAP-0206).
func TestManagedLaunchAgentCheckReadsTheTaggedLabel(t *testing.T) {
	dir := t.TempDir()
	tagged := GatewayAgentBase + ".0123456789ab"
	if err := os.WriteFile(filepath.Join(dir, tagged+".plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := managedLaunchAgentsDir
	managedLaunchAgentsDir = dir
	t.Cleanup(func() { managedLaunchAgentsDir = old })
	d := &Doctor{Managed: true, GOOS: "darwin", Geteuid: func() int { return 503 }, Runner: launchAgentPrintRunner{
		"launchctl print gui/503/" + GatewayAgentBase: "state = not running\nlast exit reason = OS_REASON_CODESIGNING\n",
		"launchctl print gui/503/" + tagged:           "state = running\n",
	}}
	c := d.ManagedLaunchAgentCheck(context.Background())
	if c == nil || c.Status != StatusPass || !strings.Contains(c.Detail, tagged+" is running") {
		t.Fatalf("check = %+v", c)
	}
}
