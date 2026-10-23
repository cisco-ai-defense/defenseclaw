// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"

// managedGatewayPeer is the account that may own the managed gateway's API
// socket: root, which holds it for systemd and launchd while the gateway
// restarts, or the gateway service account the trusted runtime descriptor
// names. Without that descriptor only root is accepted.
func managedGatewayPeer() hookexec.ManagedGatewayPeer {
	peer := hookexec.ManagedGatewayPeer{ServiceUID: -1}
	if _, descriptor, err := managedStandaloneAdminDeployment(); err == nil && descriptor != nil {
		peer.ServiceUID = descriptor.ServiceUID
	}
	return peer
}
