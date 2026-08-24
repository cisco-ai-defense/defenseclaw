// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// NewRemoteModelRouter creates a ModelRouter pointing at the given SR endpoint.
func NewRemoteModelRouter(endpoint string, timeoutMs int) ModelRouter {
	return NewRemoteRouterClient(endpoint, timeoutMs)
}
