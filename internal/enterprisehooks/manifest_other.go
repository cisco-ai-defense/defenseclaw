//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"strings"
)

func validateManifestPlatformTarget(index int, target ManifestTarget) error {
	if target.Deferred {
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
