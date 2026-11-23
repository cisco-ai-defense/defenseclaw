// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "time"

// connectedPollMaxPause is the longest pause between two looks at the
// socket table while a hook waits for the gateway to accept its connection.
const connectedPollMaxPause = 20 * time.Millisecond

// nextConnectedPollPause returns the pause before the next look at the
// socket table and counts the attempt: 1 ms, then doubling up to
// connectedPollMaxPause. The gateway accepts most connections within a
// millisecond or two, and a fixed 20 ms tick made every such call wait the
// full tick (#1384); a gateway that is slow to accept is still looked at
// every 20 ms, as before.
func nextConnectedPollPause(attempt *int) time.Duration {
	pause := min(time.Millisecond<<min(*attempt, 5), connectedPollMaxPause)
	*attempt++
	return pause
}
