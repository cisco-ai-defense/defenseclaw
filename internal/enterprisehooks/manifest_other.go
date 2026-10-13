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
			"enterprise hooks: target %d is deferred (its home was not available), which only a standalone deployment records",
			index,
		)
	}
	return nil
}

// LoadStandaloneManifest is LoadManifest under the standalone Unix rules,
// whatever profile this process serves: the Linux and macOS lifecycle reads
// the standalone targets.yaml, whose deferred rows (a home that is not
// available yet, or was removed with its deleted account) failed every
// verify with a manifest error (GAP-0692).
func LoadStandaloneManifest(path string) (Manifest, error) {
	manifest, _, err := LoadStandaloneManifestWithSHA256(path)
	return manifest, err
}

// LoadStandaloneManifestWithSHA256 is LoadManifestWithSHA256 under the
// standalone Unix rules (LoadStandaloneManifest).
func LoadStandaloneManifestWithSHA256(path string) (Manifest, string, error) {
	return loadManifestWithSHA256(path, func(int, ManifestTarget) error { return nil })
}

func canonicalManifestTargetSID(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}
