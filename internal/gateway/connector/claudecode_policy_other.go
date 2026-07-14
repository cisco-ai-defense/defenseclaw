//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

// File-based policy is inspected by the common resolver. Native Windows MDM
// policy has a registry implementation; other hosts currently expose no
// additional machine-readable OS policy through the DefenseClaw process.
func loadClaudeCodeOSManagedSettings() (claudeCodeOSManagedSources, error) {
	return claudeCodeOSManagedSources{}, nil
}
