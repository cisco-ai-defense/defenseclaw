// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"slices"
	"testing"
)

// rel-1-0-6:GAP-0796: the owned paths are the layout's path fields, found by
// shape, so the services, the secrets and the guardian state are in them
// and the account names and the API address are not.
func TestStandaloneLayoutOwnedPathsAreItsPathFields(t *testing.T) {
	for goos, want := range map[string][]string{
		"linux": {"/opt/defenseclaw/bin", "/etc/defenseclaw/config.yaml", "/etc/defenseclaw/secrets",
			"/var/lib/defenseclaw", "/var/lib/defenseclaw-hook-guardian", "/var/log/defenseclaw", "/run/defenseclaw-hook"},
		"darwin": {"/opt/cisco/defenseclaw/bin", "/opt/cisco/defenseclaw/etc/config.yaml", "/opt/cisco/defenseclaw/etc/secrets",
			"/opt/cisco/defenseclaw/runtime", "/Library/Logs/Cisco/DefenseClaw", "/var/run/defenseclaw-sensor"},
	} {
		layout, err := StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		owned := layout.OwnedPaths()
		for _, path := range want {
			if !slices.Contains(owned, path) {
				t.Errorf("%s: %s is not an owned path: %v", goos, path, owned)
			}
		}
		for _, other := range []string{layout.GOOS, layout.ServiceUser, layout.ServiceGroup, layout.APIAddr, ""} {
			if slices.Contains(owned, other) {
				t.Errorf("%s: %q is not a path but is owned", goos, other)
			}
		}
	}
}

func TestStandaloneWindowsOwnFoldersAreTheLayoutRoots(t *testing.T) {
	got := StandaloneWindowsOwnFolders()
	slices.Sort(got)
	want := []string{`Cisco\DefenseClaw`, `Cisco\DefenseClaw-HookRuntime`, `Cisco\DefenseClaw-ScannerRuntime`}
	if !slices.Equal(got, want) {
		t.Fatalf("own folders = %v, want %v", got, want)
	}
}
