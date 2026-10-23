// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package hookexec

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// No managed gateway runs here, so no listener can be proven to be one.
func newManagedGatewayHTTPClient(time.Duration, string, ManagedGatewayPeer) (*http.Client, error) {
	return nil, managedGatewayUnsupported()
}

func verifyManagedConnectedTuple(*net.TCPAddr, *net.TCPAddr, ManagedGatewayPeer) error {
	return managedGatewayUnsupported()
}

func managedGatewayUnsupported() error {
	return fmt.Errorf("%w: no managed gateway runs on this platform", errManagedGatewayPeerUnverified)
}
