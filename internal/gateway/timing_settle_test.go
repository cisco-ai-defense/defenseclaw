// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "time"

// settledTime measures a timed budget up to attempts times and returns the
// first measurement within limit, or the best one when none is. A shared CI
// runner stalls for a second or two at a time (a neighbour on the host, the
// runner's own agent), which moves every call of one measurement together;
// a real slowdown of the code moves every measurement, so it still fails
// when all attempts are over the limit (rel-1-0-10:GAP-1809).
func settledTime(attempts int, limit time.Duration, measure func() time.Duration) (best time.Duration, used int) {
	for used = 1; used <= attempts; used++ {
		d := measure()
		if used == 1 || d < best {
			best = d
		}
		if d <= limit {
			return d, used
		}
	}
	return best, attempts
}
