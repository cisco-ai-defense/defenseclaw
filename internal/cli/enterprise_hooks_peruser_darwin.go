//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookUserUnit names a target user in resilience markers.
func enterpriseHookUserUnit(target enterprisehooks.ManifestTarget, home string) string {
	name := strings.TrimSpace(target.User)
	if name == "" {
		name = filepath.Base(filepath.Clean(strings.TrimSpace(home)))
	}
	return "user:" + name
}

// repairEnterpriseHookUserTargetPlatform repairs the target user's
// DefenseClaw objects and agent configs as root, before the euid drop and
// before Verify or Install validate them. Managed mode only.
func repairEnterpriseHookUserTargetPlatform(
	target enterprisehooks.ManifestTarget,
	opts enterprisehooks.InstallOptions,
) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	return enterprisehooks.RepairUserTarget(opts, enterpriseHookUserUnit(target, opts.UserHome))
}

// reportEnterpriseHookTargetRepairedPlatform logs a target whose hook
// registration was re-applied after Verify failed, naming the files.
func reportEnterpriseHookTargetRepairedPlatform(
	target enterprisehooks.ManifestTarget,
	result enterprisehooks.InstallResult,
) {
	path := strings.Join(result.HookConfigPaths, ",")
	if path == "" {
		path = result.UserHome
	}
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"unit":      enterpriseHookUserUnit(target, result.UserHome),
		"connector": strings.TrimSpace(result.Connector),
		"path":      path,
		"reason":    "hook registration, scripts or contract lock re-applied after verification failed",
	})
}
