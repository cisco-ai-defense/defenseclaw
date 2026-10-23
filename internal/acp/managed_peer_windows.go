// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acp

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedGatewayPeer is the service that must own a managed gateway's
// connected socket: the running DefenseClawGateway SCM process. Replaceable
// in tests.
var managedGatewayPeer = func() hookexec.ManagedGatewayPeer {
	return hookexec.ManagedGatewayPeer{ServiceName: managed.StandaloneWindowsGatewaySvc, ServiceUID: -1}
}
