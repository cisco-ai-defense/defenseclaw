// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// watchdogPeerClient binds per-user health and recovery requests to the
// connected peer, while retaining the configured managed service transport.
func watchdogPeerClient(cfg *config.Config, rawURL string, timeout time.Duration) (*http.Client, error) {
	return gatewayPeerClientForURL(cfg, rawURL, timeout)
}

func newWatchdogAPIRecoveryRecorder(cfg *config.Config, rawURL, token string) (*watchdogAPIRecoveryRecorder, error) {
	client, err := watchdogPeerClient(cfg, rawURL, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &watchdogAPIRecoveryRecorder{client: client, url: rawURL, token: token}, nil
}
