//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validateManifestPlatformTarget(index int, target ManifestTarget) error {
	home := strings.TrimSpace(target.UserHome)
	if home == "" {
		return fmt.Errorf("enterprise hooks: Windows target %d requires explicit user_home", index)
	}
	if !filepath.IsAbs(home) {
		return fmt.Errorf("enterprise hooks: Windows target %d user_home must be absolute", index)
	}
	rawSID := strings.TrimSpace(target.SID)
	if rawSID == "" {
		return fmt.Errorf("enterprise hooks: Windows target %d requires explicit sid", index)
	}
	sid, err := windows.StringToSid(rawSID)
	if err != nil {
		return fmt.Errorf("enterprise hooks: Windows target %d has invalid sid: %w", index, err)
	}
	if windowsEnterpriseSystemIdentity(sid) {
		return fmt.Errorf("enterprise hooks: Windows target %d sid %s is not an interactive user", index, sid)
	}
	if strings.TrimSpace(target.AgentVersion) == "" {
		return fmt.Errorf("enterprise hooks: Windows target %d requires explicit agent_version", index)
	}
	if err := requireWindowsEnterpriseManagedAgentVersion(
		target.Connector,
		target.AgentVersion,
	); err != nil {
		return fmt.Errorf("enterprise hooks: Windows target %d: %w", index, err)
	}
	return nil
}

func canonicalManifestTargetSID(raw string) string {
	sid, err := windows.StringToSid(strings.TrimSpace(raw))
	if err != nil || sid == nil {
		// Validation runs immediately before key construction, so this is only
		// a defensive deterministic fallback for direct internal callers.
		return strings.ToUpper(strings.TrimSpace(raw))
	}
	return strings.ToUpper(sid.String())
}
