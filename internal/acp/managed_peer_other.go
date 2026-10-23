// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package acp

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedGatewayPeer is the account that may own a managed gateway's
// connected socket: root, which holds it for systemd and launchd while the
// gateway restarts, or the service account the trusted runtime descriptor
// names. Replaceable in tests.
var managedGatewayPeer = func() hookexec.ManagedGatewayPeer {
	peer := hookexec.ManagedGatewayPeer{ServiceUID: -1}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return peer
	}
	if descriptor, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath); err == nil && descriptor != nil {
		peer.ServiceUID = descriptor.ServiceUID
	}
	return peer
}
