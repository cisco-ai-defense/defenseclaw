//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import "net"

// loopbackTCPOwnerSID: SIDs exist only on Windows.
func loopbackTCPOwnerSID(_, _ *net.TCPAddr) (string, error) { return "", ErrUnsupported }
