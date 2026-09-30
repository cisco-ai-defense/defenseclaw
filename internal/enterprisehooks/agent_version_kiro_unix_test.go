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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

// A user with only the Kiro IDE was never enrolled: discovery looked for
// kiro-cli alone. The IDE's version is read from the product.json its
// packages ship (never by running it); at or above 1.0.182, the first build
// that reads the global ~/.kiro/hooks file, it enrolls the user at a marked
// version that the IDE floor, not kiro-cli's, admits. An older IDE is
// reported and a kiro-cli row stays.
func TestKiroIDEIsDiscoveredAndHeldToItsGlobalHooksFloor(t *testing.T) {
	origGOOS := unixAgentAppBundleGOOS
	unixAgentAppBundleGOOS = "darwin"
	t.Cleanup(func() { unixAgentAppBundleGOOS = origGOOS })
	home := t.TempDir()
	product := filepath.Join(home, "Applications", "Kiro.app", "Contents", "Resources", "app", "product.json")
	if err := os.MkdirAll(filepath.Dir(product), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(product, []byte(`{"nameShort":"Kiro","applicationName":"kiro","version":"1.2.4"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, at := DiscoverUnixKiroIDEVersion(home); got != "1.2.4" || at != product {
		t.Fatalf("Kiro IDE version = %q at %q, want 1.2.4 at %s", got, at, product)
	}

	versions := map[string]string{KiroIDEDiscoveryKey: "1.2.4"}
	reasons := map[string]string{"kiro": "no kiro installation found for this user"}
	if report := applyKiroIDESurface("alice", 501, versions, reasons); len(report) != 0 || versions["kiro"] != "1.2.4"+KiroIDEVersionSuffix || reasons["kiro"] != "" {
		t.Fatalf("IDE-only user: report=%v versions=%v reasons=%v", report, versions, reasons)
	}
	if admitted, reason := standaloneNotGatedVersionAdmitted(connector.ResolveHookContract("kiro", versions["kiro"])); !admitted {
		t.Fatalf("Kiro IDE 1.2.4 row refused by the floor: %s", reason)
	}
	if admitted, reason := standaloneNotGatedVersionAdmitted(connector.ResolveHookContract("kiro", "1.0.181"+KiroIDEVersionSuffix)); admitted || !strings.Contains(reason, "Kiro IDE") {
		t.Fatalf("Kiro IDE 1.0.181 row: admitted=%v reason=%q, want refused naming the IDE", admitted, reason)
	}

	versions = map[string]string{"kiro": "2.24.1", KiroIDEDiscoveryKey: "1.0.181"}
	report := applyKiroIDESurface("alice", 501, versions, nil)
	if len(report) != 1 || report[0].Code != UnprotectedCodeKiroIDEBelowGlobalHooksFloor || versions["kiro"] != "2.24.1" || versions[KiroIDEDiscoveryKey] != "" {
		t.Fatalf("old IDE next to kiro-cli: report=%v versions=%v", report, versions)
	}
}
