//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import "net"

func statusPeerConn(conn net.Conn, _ *statusPeerEvidence) net.Conn { return conn }
