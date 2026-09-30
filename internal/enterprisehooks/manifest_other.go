//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"strings"
)

func validateManifestPlatformTarget(index int, target ManifestTarget) error {
	// Standalone Unix manifests defer rows whose home does not exist or is
	// locked yet. Other Unix manifests (Secure Client macOS) keep rejecting
	// the Windows-only bit.
	if target.Deferred && !StandaloneUnix() {
		return fmt.Errorf(
			"enterprise hooks: target %d uses Windows-only deferred enrollment",
			index,
		)
	}
	return nil
}

func canonicalManifestTargetSID(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}
