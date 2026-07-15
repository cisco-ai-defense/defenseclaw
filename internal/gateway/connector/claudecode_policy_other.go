//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

func claudeCodePlatformManagedSettingsRoot() (string, error) {
	return "/etc/claude-code", nil
}

// File-based policy is inspected by the common resolver. Native Windows MDM
// policy has registry and managed-preferences implementations; other hosts expose no
// additional machine-readable OS policy through the DefenseClaw process.
func loadClaudeCodeOSManagedSettings() (claudeCodeOSManagedSources, error) {
	return claudeCodeOSManagedSources{}, nil
}
