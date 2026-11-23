// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestManagedScanReportsEveryAgentInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows bin folders are not listed by the gateway")
	}
	base := t.TempDir()
	home, other, machine := filepath.Join(base, "home", "alice"), filepath.Join(base, "home", "bob", "bin"), filepath.Join(base, "opt", "bin")
	restore := agentBinaryDirs
	t.Cleanup(func() { agentBinaryDirs = restore })
	agentBinaryDirs = func(h string) []string { return []string{filepath.Join(h, ".local", "bin"), machine, other} }
	for _, path := range []string{filepath.Join(home, ".local", "bin", "dc-test-agent"), filepath.Join(machine, "dc-test-agent"), filepath.Join(other, "dc-test-agent")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeSkillFiles(t, machine, map[string]string{"agent": "the generic name is not searched"})

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
		HomeDirs: []string{home}, ManagedEnterprise: true, SecureClient: true,
	}, []AISignature{{ID: "codex", Category: SignalSupportedConnector, SupportedConnector: "codex", BinaryNames: []string{"dc-test-agent", "agent"}}})
	cleanupPreparedDiscoveryService(t, svc)
	var locations []string
	for _, signal := range svc.detectBinaries() {
		locations = append(locations, signal.Location)
	}
	slices.Sort(locations)
	// Neither another account nor an unknown machine prefix exports an
	// absolute location. Both installs are still independently reported.
	if want := []string{"", "", "~/.local/bin/dc-test-agent"}; !slices.Equal(locations, want) {
		t.Fatalf("installs = %q, want %q", locations, want)
	}
	// A home at the top of the file system, such as /root, does not hide a
	// confirmed system binary location.
	svc.opts.HomeDirs = append(svc.opts.HomeDirs, filepath.VolumeName(base)+string(filepath.Separator)+"root")
	if location := svc.installLocation("/usr/local/bin/dc-test-agent"); location != "/usr/local/bin/dc-test-agent" {
		t.Fatalf("with /root scanned, location = %q", location)
	}
	if location := svc.installLocation(filepath.Join(base, "unscanned-accounts", "carol", "bin", "dc-test-agent")); location != "" {
		t.Fatalf("unscanned account location = %q", location)
	}
	// A per-user scan sends no location.
	user := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data2"), HomeDir: home}, nil)
	cleanupPreparedDiscoveryService(t, user)
	if location := user.installLocation(filepath.Join(machine, "dc-test-agent")); location != "" {
		t.Fatalf("per-user scan location = %q", location)
	}
}

func TestUserScanReportBoundsTheInstallLocation(t *testing.T) {
	validate := func(location string) error {
		sig := AISignal{SignatureID: "codex", Name: "Codex", Product: "Codex", Category: SignalAICLI, Detector: "binary",
			State: "new", Fingerprint: hashValue("fp"), Location: location}
		return ValidateUserScanReport(AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "scan-1"}, Signals: []AISignal{sig}},
			[]AISignature{{ID: "codex", Name: "Codex"}})
	}
	for _, location := range []string{"", "~/.local/bin/codex", filepath.Join(t.TempDir(), "codex")} {
		if err := validate(location); err != nil {
			t.Errorf("%q: %v", location, err)
		}
	}
	for _, location := range []string{"codex", "~/bin/codex\n", "~/" + strings.Repeat("a", maxSkillLocation)} {
		if validate(location) == nil {
			t.Errorf("%q was accepted", location)
		}
	}
}
