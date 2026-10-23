// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"strings"
)

// inventoryDACLGrantTargets returns the profiles the gateway service is
// granted inventory read access to: one target per profile, the first
// enabled row of each, in manifest order. A profile whose rows are all
// disabled gets no new grant (GAP-1193); the helpers that pick the guardian
// owned dotdirs and the enrolled connectors skip disabled rows the same way.
func inventoryDACLGrantTargets(manifest Manifest) []ManifestTarget {
	var out []ManifestTarget
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if strings.TrimSpace(target.UserHome) == "" || home == "." {
			continue
		}
		key := strings.ToLower(home)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	return out
}
