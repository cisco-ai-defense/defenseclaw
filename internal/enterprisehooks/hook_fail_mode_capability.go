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

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector"

// renderedHookFailMode is mode as the hook renderer writes it into conn's
// hooks (connector resolveConnectorHookRender): closed becomes open when the
// agent cannot fail closed (Hermes and Copilot never block on a hook error
// or timeout), so what status, verify and the runtime records say is what
// the hook does (GAP-0001).
func renderedHookFailMode(conn connector.Connector, opts connector.SetupOpts, mode string) string {
	if mode != "closed" {
		return mode
	}
	if provider, ok := conn.(connector.HookCapabilityProvider); ok && !provider.HookCapabilities(opts).SupportsFailClosed {
		return "open"
	}
	return mode
}

// renderedHookFailModeFor is renderedHookFailMode for the registry
// connector named name; a name the registry does not know keeps mode.
func renderedHookFailModeFor(name, mode string) string {
	conn, ok := connector.NewDefaultRegistry().Get(name)
	if !ok {
		return mode
	}
	return renderedHookFailMode(conn, connector.SetupOpts{}, mode)
}
