// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// appendWindowsMCPSpoolInventory uses the same administrator-owned records as
// MCP admission. Only fresh guardian-authorized targets can supply parents;
// nothing here opens a profile or executes a server. Missing/unreadable records
// remain partial so they cannot retire an earlier complete inventory.
func appendWindowsMCPSpoolInventory(
	cfg *config.Config,
	connectors map[string]struct{},
	appendServers func(string, string, llmEventUser, []config.MCPServerEntry),
) perConnectorMCPReadStatus {
	status := perConnectorMCPReadStatus{}
	markAllIncomplete := func() {
		for name := range connectors {
			status.markIncomplete(name)
		}
	}
	authorization, _ := readManagedGuardianAuthorization(cfg.DataDir)
	if authorization == nil {
		markAllIncomplete()
		return status
	}
	if valid, _ := managedGuardianAuthorizationCovers(*authorization, nil, true); !valid {
		markAllIncomplete()
		return status
	}
	if authorization.FailureCount > 0 || authorization.PendingCount > 0 {
		markAllIncomplete()
	}
	for _, target := range authorization.ProtectedTargets {
		name := managedGuardianTargetConnector(target)
		if _, selected := connectors[name]; !selected {
			continue
		}
		home := strings.TrimSpace(target.UserHome)
		if home == "" && target.Result != nil {
			home = strings.TrimSpace(target.Result.UserHome)
		}
		sid := strings.ToUpper(strings.TrimSpace(target.SID))
		dir := enrolledMCPSpoolDir(cfg, name)
		if home == "" || !filepath.IsAbs(home) || sid == "" || dir == "" {
			status.markIncomplete(name)
			continue
		}
		if err := enterprisehooks.ReadMCPInventoryPublication(dir, validateManagedGuardianAuthorization); err != nil {
			status.markIncomplete(name)
			continue
		}
		servers, unreadable := enrolledSpoolMCPServers(dir, name, sid)
		if unreadable != nil || enterprisehooks.ReadMCPInventoryPublication(dir, validateManagedGuardianAuthorization) != nil {
			status.markIncomplete(name)
			continue
		}
		appendServers(name, filepath.Clean(home), llmEventUser{
			ID: sid, IDKind: useridentity.KindWindowsSID, Name: sanitizeLLMEventUser(target.User),
		}, servers)
	}
	return status
}
