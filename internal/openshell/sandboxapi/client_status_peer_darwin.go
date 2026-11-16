//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"net"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// The macOS LaunchAgent's daemon creates the socket it serves.
func statusPeerConn(conn net.Conn, evidence *statusPeerEvidence) net.Conn {
	if cred, err := peercred.FromConn(conn); err == nil {
		evidence.record(cred.PID, cred.UID)
	}
	return conn
}
