// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Kiro CLI for macOS installs as Kiro CLI.app with kiro-cli in
// Contents/MacOS and no link in a bin directory until the user runs the
// app's shell setup (a fresh install has exactly that layout). Discovery
// looked only in bin directories, so the macOS guardian never enrolled Kiro.
func TestDiscoverUnixAgentVersionFindsTheKiroCLIAppBundle(t *testing.T) {
	origPrefixes, origGOOS := machinePrefixes, unixAgentAppBundleGOOS
	machinePrefixes = func() []string { return nil }
	unixAgentAppBundleGOOS = "darwin"
	t.Cleanup(func() { machinePrefixes, unixAgentAppBundleGOOS = origPrefixes, origGOOS })

	home := t.TempDir()
	binary := filepath.Join(home, "Applications", "Kiro CLI.app", "Contents", "MacOS", "kiro-cli")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho kiro-cli 2.24.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, reason := DiscoverUnixAgentVersion(context.Background(), home, "kiro", true); got != "2.24.1" {
		t.Fatalf("kiro version = %q (%s), want 2.24.1 from the app bundle", got, reason)
	}

	// Other OSes have no app bundles.
	unixAgentAppBundleGOOS = "linux"
	if got, _ := DiscoverUnixAgentVersion(context.Background(), home, "kiro", true); got != "" {
		t.Fatalf("linux discovery read the macOS app bundle: %q", got)
	}
}
