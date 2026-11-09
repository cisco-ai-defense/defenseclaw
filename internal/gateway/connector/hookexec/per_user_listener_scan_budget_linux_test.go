// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"testing"
	"time"
)

// The owner scan of a queued connection runs in the margin before the connect
// deadline. A scan that meets a thread that cannot be read for a moment waits
// unreadableThreadWindow once and then reads on, so the margin must hold that
// wait and a scan of a busy host (170 ms measured) on top of it; a scan the
// deadline cuts ends the try as an unverified peer, a block of an ordinary
// call to the own frozen gateway of the account.
func TestOwnerScanMarginHoldsTheUnreadableThreadWindowAndABusyScan(t *testing.T) {
	const busyHostScan = 250 * time.Millisecond // above the 170 ms measured
	if unansweredMargin < unreadableThreadWindow+busyHostScan {
		t.Fatalf("the owner scan margin %s does not hold the unreadable-thread window %s and a busy scan %s", unansweredMargin, unreadableThreadWindow, busyHostScan)
	}
}
