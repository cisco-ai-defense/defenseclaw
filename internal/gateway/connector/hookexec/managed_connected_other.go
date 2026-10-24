// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package hookexec

import (
	"context"
	"errors"
	"net"
)

func verifyManagedConnectedPeer(_ context.Context, _, _ *net.TCPAddr, _ string) error {
	return errors.New("managed gateway peer verification is unavailable on this platform")
}
