// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"time"
)

// watchdogPeerClient binds both the unauthenticated health probe and the
// authenticated recovery post to the configured per-user gateway socket.
func watchdogPeerClient(rawURL string, timeout time.Duration) (*http.Client, error) {
	return gatewayPeerClientForURL(nil, rawURL, timeout)
}
