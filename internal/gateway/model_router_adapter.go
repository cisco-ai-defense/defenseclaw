// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// NewSemanticModelRouter is called by the sidecar at startup.
// Returns nil — routing is handled entirely by the managed SR sidecar
// via RemoteRouterClient (wired in sidecar.go via the orchestrator).
func NewSemanticModelRouter(cfg config.RoutingConfig) (ModelRouter, error) {
	return nil, nil
}

// NewRemoteModelRouter creates a ModelRouter pointing at the given SR endpoint.
func NewRemoteModelRouter(endpoint string, timeoutMs int) ModelRouter {
	return NewRemoteRouterClient(endpoint, timeoutMs)
}
