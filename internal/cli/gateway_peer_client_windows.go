// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedGatewayPeer is the service that must own the managed gateway's API
// socket: the running DefenseClawGateway SCM service process.
func managedGatewayPeer() hookexec.ManagedGatewayPeer {
	return hookexec.ManagedGatewayPeer{ServiceName: managed.StandaloneWindowsGatewaySvc, ServiceUID: -1}
}
