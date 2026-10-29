// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "testing"

// GAP-1516: prerelease versions follow semver precedence. rc.10 is newer than
// rc.4 (numeric identifiers compare as numbers), a release is newer than its
// prereleases, and an alphanumeric identifier sorts above a numeric one.
func TestWindowsEnterpriseVersionsCompareSemverPrereleases(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        int
	}{
		{"1.0.4-rc.10", "1.0.4-rc.4", 1},
		{"1.0.4-rc.4", "1.0.4-rc.10", -1},
		{"1.0.4-rc.10", "1.0.4-rc.10", 0},
		{"1.0.4", "1.0.4-rc.10", 1},
		{"1.0.4-rc.11", "1.0.4", -1},
		{"1.0.4-rc.1", "1.0.4-rc.1.1", -1},
		{"1.0.4-rc.1", "1.0.4-rc.beta", -1},
		{"1.0.5-dev.win-managed", "1.0.5-dev.mgmt", 1},
		{"1.0.5-dev.win-managed", "1.0.4", 1},
	} {
		if got := compareWindowsEnterpriseVersions(tc.left, tc.right); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}
