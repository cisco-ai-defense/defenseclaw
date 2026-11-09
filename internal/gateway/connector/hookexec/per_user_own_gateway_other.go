// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package hookexec

import (
	"context"
	"net"
)

// ownGatewayHoldsQueue is never true here: this OS proves the owner of a
// queued connection in its own socket table (Windows), or cannot (others), and
// a connection it could not prove stays an unverified peer.
func ownGatewayHoldsQueue(context.Context, *net.TCPAddr) bool { return false }

// ownerScanSupported is false here: ownGatewayHoldsQueue answers at once.
const ownerScanSupported = false
