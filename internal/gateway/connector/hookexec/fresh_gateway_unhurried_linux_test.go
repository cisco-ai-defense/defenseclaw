// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"testing"
	"time"
)

// unhurriedFreshGateway keeps a test that drives real processes through the
// fresh-gateway proof on the fresh side of the two clocks of the product,
// however slow the host is: the gateway start window (12 s from the process
// start) and the background read of the owner of the connection. The tests
// that pin the age limits do so through the recorded start of the record,
// which this leaves alone.
func unhurriedFreshGateway(t *testing.T) {
	t.Helper()
	window, capture := perUserFreshGatewayWindow, freshOwnerCaptureWait
	perUserFreshGatewayWindow, freshOwnerCaptureWait = 10*time.Minute, 30*time.Second
	t.Cleanup(func() { perUserFreshGatewayWindow, freshOwnerCaptureWait = window, capture })
}
