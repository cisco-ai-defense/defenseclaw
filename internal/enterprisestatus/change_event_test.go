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

package enterprisestatus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeSpoolEvents(t *testing.T, spool ChangeSpool, n int) []string {
	t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		ev := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeApplied, "")
		ev.SecretName = "splunk-hec-token"
		if err := spool.Write(ev); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ids = append(ids, ev.ContentID())
	}
	return ids
}

func shrinkChangeSpool(t *testing.T, reported, pending int) {
	t.Helper()
	savedReported, savedPending := maxReportedChangeEvents, maxPendingChangeEvents
	maxReportedChangeEvents, maxPendingChangeEvents = reported, pending
	t.Cleanup(func() { maxReportedChangeEvents, maxPendingChangeEvents = savedReported, savedPending })
}

// An event the gateway has not reported is never removed to make room: a
// write removes only reported events, oldest first.
func TestChangeSpoolRemovesOnlyReportedEvents(t *testing.T) {
	shrinkChangeSpool(t, 4, 100)
	dataDir := t.TempDir()
	spool := newTestSpool(t)
	spool.Reported = func(id string) bool { return ChangeReported(dataDir, id) }
	ids := writeSpoolEvents(t, spool, 6)
	if got := ListChangeEventIDs(spool.Dir); len(got) != 6 {
		t.Fatalf("unreported events were removed: %d of 6 left", len(got))
	}
	markers := filepath.Join(dataDir, ReportedMarkersDirName)
	if err := os.MkdirAll(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:3] {
		if err := os.WriteFile(filepath.Join(markers, id), []byte("reported\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	next := writeSpoolEvents(t, spool, 1)
	got := ListChangeEventIDs(spool.Dir)
	want := append(append([]string{}, ids[3:]...), next...)
	if len(got) != len(want) {
		t.Fatalf("spool = %v, want %v (the three reported events removed)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("spool = %v, want %v", got, want)
		}
	}
}

// With the most unreported events the spool holds, Reserve and Write refuse
// (ErrChangeSpoolFull) and nothing is written or removed.
func TestChangeSpoolRefusesWhenFullOfUnreportedEvents(t *testing.T) {
	shrinkChangeSpool(t, 2, 3)
	spool := newTestSpool(t)
	writeSpoolEvents(t, spool, 3)
	if _, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "otlp-token"); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("Reserve on a full spool: %v", err)
	}
	ev := NewChangeEvent(ChangeKindSecret, ChangeActionRemove, ChangeApplied, "")
	ev.SecretName = "otlp-token"
	if err := spool.Write(ev); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("Write on a full spool: %v", err)
	}
	if got := ListChangeEventIDs(spool.Dir); len(got) != 3 {
		t.Fatalf("spool = %v, want the three unreported events", got)
	}
}

// Only a regular marker file named by a change event id counts as reported.
func TestChangeReportedReadsTheGatewayMarker(t *testing.T) {
	dataDir := t.TempDir()
	const id = "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W"
	if ChangeReported(dataDir, id) {
		t.Fatal("reported without a marker")
	}
	markers := filepath.Join(dataDir, ReportedMarkersDirName)
	if err := os.MkdirAll(filepath.Join(markers, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if ChangeReported(dataDir, id) {
		t.Fatal("a folder counted as a marker")
	}
	if err := os.Remove(filepath.Join(markers, id)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers, id), []byte("reported\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ChangeReported(dataDir, id) || ChangeReported("", id) || ChangeReported(dataDir, "../"+id) {
		t.Fatal("ChangeReported does not read exactly the marker of a valid id")
	}
}
