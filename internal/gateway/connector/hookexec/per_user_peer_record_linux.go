// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import "net"

// connectedServer is the gateway address the hook connected to, once the
// connection is made. Only the Linux fresh-start proof reads it
// (gateway_fresh_start_linux.go), so it is built on Linux only.
func (r *PerUserPeerRecord) connectedServer() (*net.TCPAddr, bool) {
	if r == nil {
		return nil, false
	}
	select {
	case <-r.connected:
		return r.server, r.server != nil
	default:
		return nil, false
	}
}
