// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"
	"time"
)

// The admission state reads one clock for every time it records: the time
// an asset's state was first set, and when an issue is due again
// (rel-1-0-6:GAP-0258 review, info 4).
func TestAdmissionStateRecordsTimesFromItsClock(t *testing.T) {
	s := newAdmissionState(t.TempDir(), func(p string) string { return p })
	clock := &fakeClock{now: time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)}
	s.now = clock.Now
	evt := InstallEvent{Type: InstallSkill, Name: "a", Path: t.TempDir()}
	s.set(evt, "scanning")
	clock.advance(time.Hour)
	s.set(evt, "blocked")
	if got := s.assets[evt.Path].Since; !got.Equal(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("state since = %v, want the clock's first time", got)
	}
}
