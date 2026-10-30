// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsServiceLogEnv names the gateway service log the SCM host writes.
const windowsServiceLogEnv = "DEFENSECLAW_WINDOWS_SERVICE_LOG"

// AssessManagedDataPaths reads, never writes, the descriptors of the managed
// gateway's data objects and logs each drift once: accepted when no untrusted
// principal can write, boundary when one can. An object the gateway can no
// longer write (its service write entry is gone after an ACL reset) is logged
// as a degraded subsystem so the cause of a later access-denied is on record;
// the hook guardian repairs it. Only managed Windows deployments do any work.
func AssessManagedDataPaths(cfg *config.Config) []managed.CanonicalResult {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	paths := cfg.ManagedDataPaths()
	if logPath := strings.TrimSpace(os.Getenv(windowsServiceLogEnv)); logPath != "" {
		paths.LogPaths = append(paths.LogPaths, logPath)
	}
	results := managed.AssessWindowsManagedDataPaths(paths, managed.CanonicalOptions{})
	for _, result := range results {
		if result.GatewayAccessMissing {
			managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
				"subsystem": "data-store",
				"path":      result.Path,
				"reason":    "gateway service access entry is missing; awaiting guardian repair",
			})
		}
	}
	return results
}
