//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestSetCommandNameAcceptsOnlyReleaseOwnedNames(t *testing.T) {
	original := rootCmd.Use
	t.Cleanup(func() { rootCmd.Use = original })

	SetCommandName("defenseclaw")
	if rootCmd.Use != "defenseclaw" {
		t.Fatalf("root command name = %q, want defenseclaw", rootCmd.Use)
	}
	SetCommandName("attacker-controlled-name")
	if rootCmd.Use != "defenseclaw" {
		t.Fatalf("invalid command name changed root Use to %q", rootCmd.Use)
	}
	SetCommandName("defenseclaw-gateway")
	if rootCmd.Use != "defenseclaw-gateway" {
		t.Fatalf("root command name = %q, want defenseclaw-gateway", rootCmd.Use)
	}
}

func TestEnterpriseWindowsCommandPathTracksExactReleaseExecutableName(t *testing.T) {
	original := rootCmd.Use
	t.Cleanup(func() { rootCmd.Use = original })

	command, _, err := rootCmd.Find([]string{"enterprise", "windows"})
	if err != nil {
		t.Fatal(err)
	}
	SetCommandName("defenseclaw")
	if got := command.CommandPath(); got != "defenseclaw enterprise windows" {
		t.Fatalf("CLI command path = %q", got)
	}
	SetCommandName("defenseclaw-gateway")
	if got := command.CommandPath(); got != "defenseclaw-gateway enterprise windows" {
		t.Fatalf("gateway command path = %q", got)
	}
}
