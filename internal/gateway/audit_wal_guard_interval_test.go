// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// r108 SWEEP-100: the guard passes sooner while the hooks write fast, and
// soon after a pass that needed the writer and did not reach the end of the
// log; an idle or slow log keeps the ordinary tick.
func TestR108AuditWALGuardNextInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		pass audit.WALCheckpoint
		want any
	}{
		{"idle", audit.WALCheckpoint{}, auditWALGuardInterval},
		{"short log", audit.WALCheckpoint{LogBytes: auditWALGuardTriggerBytes / 8}, auditWALGuardInterval},
		{"fast writes, restarted", audit.WALCheckpoint{LogBytes: auditWALGuardTriggerBytes / 2, Restarted: true}, auditWALGuardBusyInterval},
		{"fast writes", audit.WALCheckpoint{LogBytes: auditWALGuardTriggerBytes/4 + 1}, auditWALGuardBusyInterval},
		{"deferred", audit.WALCheckpoint{LogBytes: auditWALGuardTriggerBytes, WriterDeferred: true}, auditWALGuardRetryInterval},
	} {
		if got := auditWALGuardNextInterval(tc.pass); got != tc.want {
			t.Errorf("%s: next pass in %v, want %v", tc.name, got, tc.want)
		}
	}
	if auditWALGuardRetryInterval >= auditWALGuardBusyInterval || auditWALGuardBusyInterval >= auditWALGuardInterval {
		t.Fatal("the guard intervals must shorten with pressure")
	}
}
