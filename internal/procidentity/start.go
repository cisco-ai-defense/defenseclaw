// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import "time"

// StartTime is when process pid started, as the system records it, and
// whether the system says. A 1.0.2/1.0.3 install lock has no identity record;
// a lock whose pid names a process that started after the lock was made
// names a reused pid (LEAD DECISION 2026-10-26 13:58, GAP-1465).
func StartTime(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	return startTime(pid)
}
