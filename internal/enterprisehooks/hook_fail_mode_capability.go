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

// renderedHookFailModeFor is mode as the managed hook renderer writes it into
// the hooks of the registry connector named name for cfg
// (connector.CapableHookFailMode), so what status, verify and the runtime
// records say is what the hook does (GAP-0001). Outside Secure Client every
// connector keeps the mode the administrator's config resolved: its hooks
// block a call they cannot check through the native deny. Under Secure Client
// closed becomes open for an agent that cannot fail closed (Hermes and Copilot
// never block on a hook error or timeout). A name the registry does not know
// keeps mode.
func renderedHookFailModeFor(cfg *config.Config, name, mode string) string {
	if mode != "closed" || (cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) && !cfg.SecureClientIntegration()) {
		return mode
	}
	conn, ok := connector.NewDefaultRegistry().Get(name)
	if !ok {
		return mode
	}
	// A managed render without the standalone socket or binary is the Secure
	// Client profile's (connector.shellHookSecureClientProfile).
	return connector.CapableHookFailMode(connector.SetupOpts{ManagedEnterprise: true}, conn, mode)
}
