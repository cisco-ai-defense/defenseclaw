// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxreg

import (
	"testing"
	"time"
)

// GAP-0009: a registration outlives its sandbox's stop and start, so the
// session its sandbox runs is recorded apart: a running report after a
// stop, reported or a lapsed LiveLease, starts a new session
// (SessionStart); the polls of a sandbox that keeps running do not, and
// the session start survives a gateway restart.
func TestStoreReportAfterAStopStartsANewSession(t *testing.T) {
	s, clock, dir := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	bound, err := s.Bind(1001, r.ID, bind(0))
	if err != nil {
		t.Fatal(err)
	}
	boundAt := clock.t
	if !bound.SessionAt.IsZero() || !SessionStart(bound).Equal(boundAt) {
		t.Fatalf("bound: session at %v, start %v, want the bind %v", bound.SessionAt, SessionStart(bound), boundAt)
	}
	session := func(when string, want time.Time) {
		t.Helper()
		got, ok, err := s.Get(1001, r.ID)
		if err != nil || !ok || !SessionStart(got).Equal(want) {
			t.Fatalf("%s: session start %v (%v %v), want %v", when, SessionStart(got), ok, err, want)
		}
	}
	// Running on: every poll renews the lease, none starts a session.
	for range 5 {
		clock.t = clock.t.Add(time.Minute)
		if _, err := s.Report(1001, r.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	session("while it runs", boundAt)
	// A reported stop, then a start.
	clock.t = clock.t.Add(time.Minute)
	if _, err := s.Report(1001, r.ID, false); err != nil {
		t.Fatal(err)
	}
	session("stopped", boundAt)
	// A start registers it again (GAP-0673): the new registration's
	// session starts at the restart.
	clock.t = clock.t.Add(time.Minute)
	next, err := s.Restart(1001, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	r = next
	restarted := clock.t
	session("started again", restarted)
	clock.t = clock.t.Add(3 * time.Minute)
	if _, err := s.Report(1001, r.ID, true); err != nil {
		t.Fatal(err)
	}
	session("running on after the start", restarted)
	// No running report for LiveLease: the gateway judged it stopped, so
	// the next running report starts a session too.
	clock.t = clock.t.Add(LiveLease)
	if _, err := s.Report(1001, r.ID, true); err != nil {
		t.Fatal(err)
	}
	lapsed := clock.t
	session("after a lapsed lease", lapsed)
	// Kept across a gateway restart.
	reopened := NewFileStore(dir)
	reopened.Now = clock.now
	got, ok, err := reopened.Get(1001, r.ID)
	if err != nil || !ok || !got.SessionAt.Equal(lapsed) {
		t.Fatalf("after a reopen: session at %v (%v %v), want %v", got.SessionAt, ok, err, lapsed)
	}
}
