// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedHookFailMode is the fail mode the managed hook renderer writes into
// connector's hooks for cfg, on every OS: the mode cfg resolves
// (cfg.EffectiveHookFailModeForConnector: an explicit open or closed wins,
// unset is closed, and open under Secure Client, #1163), and under Secure
// Client only, closed lowered to open for an agent that cannot fail closed
// (renderedHookFailModeFor), so status reports that value and never derives
// one from the raw config (GAP-0001). The profile is the one cfg resolved
// (its enterprise.profile, the service pin or the per-OS default), not the
// caller's process pin (GAP-0014).
func ManagedHookFailMode(cfg *config.Config, connector string) string {
	return renderedHookFailModeFor(cfg, connector, cfg.EffectiveHookFailModeForConnector(connector))
}

// ManagedStatusHookFailMode is the effective_hook_fail_mode status and verify
// report for connector on goos: ManagedHookFailMode, except that a connector
// DefenseClaw reaches through the per-user route (not vendor machine policy)
// of a standalone install whose hook or plugin there blocks a gateway outage
// whatever the administrator set reads closed, the mode it operates in
// (connector.ManagedPerUserRouteOutageClosed). Without that, the managed Amp
// plugin, and OpenCode or Copilot with their machine policy off, reported the
// administrator's open while blocking every outage (GAP-0465).
func ManagedStatusHookFailMode(cfg *config.Config, name, goos string, machinePolicy bool) string {
	mode := ManagedHookFailMode(cfg, name)
	if mode == "open" && !machinePolicy && managed.IsManagedEnterprise(cfg.DeploymentMode) && !cfg.SecureClientIntegration() &&
		connector.ManagedPerUserRouteOutageClosed(name, goos) {
		return "closed"
	}
	return mode
}
