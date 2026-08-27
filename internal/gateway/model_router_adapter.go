// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// NewRemoteModelRouter creates a ModelRouter pointing at the given SR endpoint
// and resolves classifier aliases against gateway-owned backend configuration.
func NewRemoteModelRouter(endpoint string, timeoutMs int, backends []ModelRouterBackend, dotenvPath string) ModelRouter {
	return NewConfiguredRemoteRouterClient(endpoint, timeoutMs, backends, dotenvPath)
}
