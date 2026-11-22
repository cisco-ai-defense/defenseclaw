// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"slices"
	"strings"
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
	for _, roots := range [][2]string{
		{`C:\Program Files`, `C:\ProgramData`},
		{`D:\Applications`, `E:\CompanyData\`},
		// One root below the other: the folders between them are not owned.
		{`D:\Applications`, `D:\Applications\Data`},
		{`D:\Applications\Data`, `D:\Applications`},
	} {
		programFiles, programData := strings.TrimRight(roots[0], `\`), strings.TrimRight(roots[1], `\`)
		got := StandaloneWindowsOwnFolders(roots[0], roots[1])
		slices.Sort(got)
		want := []string{
			programFiles + `\Cisco\DefenseClaw`,
			programData + `\Cisco\DefenseClaw`,
			programData + `\Cisco\DefenseClaw-HookRuntime`,
			programData + `\Cisco\DefenseClaw-RulePacks`,
			programData + `\Cisco\DefenseClaw-ScannerRuntime`,
		}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("own folders under %v = %v, want %v", roots, got, want)
		}
	}
	if got := StandaloneWindowsOwnFolders(`relative`, `C:\ProgramData`); got != nil {
		t.Errorf("a root that is not an absolute drive path has own folders: %v", got)
	}
}
