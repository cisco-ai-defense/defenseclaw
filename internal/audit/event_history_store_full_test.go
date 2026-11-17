// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"strings"
	"testing"
)

// GAP-0402: a full audit store logged only "event-history write failed
// (sqlite class=full code=13): database or disk is full", while every hook
// that needs an audit record failed closed. The line now names the full store
// as an alert, its effect and the repair; other failures are unchanged.
func TestEventHistoryWriteFailureLineAlertsOnAFullStore(t *testing.T) {
	full := eventHistoryWriteFailureLogLine(EventHistorySQLiteFull, 13, errors.New("database or disk is full"))
	for _, want := range []string{"class=full code=13", "ALERT audit_store_full", "fail closed", "max_store_mb"} {
		if !strings.Contains(full, want) {
			t.Fatalf("full-store line %q lacks %q", full, want)
		}
	}
	busy := eventHistoryWriteFailureLogLine(EventHistorySQLiteBusyLocked, 5, errors.New("database is locked"))
	if strings.Contains(busy, "audit_store_full") {
		t.Fatalf("busy line %q names a full store", busy)
	}
}
