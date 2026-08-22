//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "strings"

func validateManifestPlatformTarget(_ int, _ ManifestTarget) error {
	return nil
}

func canonicalManifestTargetSID(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}
