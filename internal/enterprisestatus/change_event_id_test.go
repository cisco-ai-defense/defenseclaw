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
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// A change event's id is the hash of its content: the same content always
// has the same id, any other content (outcome, reason, actor, time, hashes,
// key ids, credential name, reservation) another one, and ids sort by the
// event's time. Before, the id was random: the spool could hold another
// change under an id, and a replay could send another record under it.
func TestChangeEventIDIsTheHashOfItsContent(t *testing.T) {
	base := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	base.Actor = "os:uid:0:root"
	base.SHA256, base.PreviousSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	base.KeyIDsAdded, base.KeyIDsRemoved = []string{"fleet-2026-11"}, []string{"fleet-2026-10"}
	id := base.ContentID()
	if !ValidChangeEventID(id) || base.ContentID() != id {
		t.Fatalf("ContentID = %q, not a stable c-<ULID>", id)
	}
	copied := base
	copied.EventID = "c-00000000000000000000000000"
	if copied.ContentID() != id {
		t.Fatal("the stored id is part of the hashed content")
	}
	later, err := time.Parse(time.RFC3339Nano, base.Time)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ChangeEvent){
		"outcome":         func(ev *ChangeEvent) { ev.Outcome, ev.ReasonCode = ChangeFailed, ChangeInterrupted },
		"reason":          func(ev *ChangeEvent) { ev.Outcome, ev.ReasonCode = ChangeRefused, "anchor_invalid" },
		"actor":           func(ev *ChangeEvent) { ev.Actor = "os:uid:501:alice" },
		"time":            func(ev *ChangeEvent) { ev.Time = later.Add(time.Nanosecond).Format(time.RFC3339Nano) },
		"anchor file":     func(ev *ChangeEvent) { ev.SHA256 = strings.Repeat("c", 64) },
		"replaced file":   func(ev *ChangeEvent) { ev.PreviousSHA256 = "" },
		"added key":       func(ev *ChangeEvent) { ev.KeyIDsAdded = []string{"fleet-2026-12"} },
		"removed key":     func(ev *ChangeEvent) { ev.KeyIDsRemoved = nil },
		"reservation":     func(ev *ChangeEvent) { ev.ReservationID = id },
		"credential name": func(ev *ChangeEvent) { *ev = appliedSecretChange(t, "otlp-token") },
	} {
		ev := base
		change(&ev)
		if other := ev.ContentID(); other == id || !ValidChangeEventID(other) {
			t.Fatalf("another %s has the id %q (base %q)", name, other, id)
		}
	}
	var ids []string
	for offset := range 3 {
		ev := base
		ev.Time = later.Add(time.Duration(2-offset) * time.Second).Format(time.RFC3339Nano)
		ids = append(ids, ev.ContentID())
	}
	if !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] > ids[j] }) {
		t.Fatalf("ids %v do not sort by time", ids)
	}
	bad := base
	bad.Time = "yesterday"
	if bad.ContentID() != "" {
		t.Fatal("an event without a valid time has an id")
	}
}

// A change event file that does not hold the content its id hashes (edited
// after it was written: another outcome, actor or hash under the same name
// and event_id) does not validate: nothing reads it, reports it or counts it
// as settling a reservation. A writer gives every event its content id, so
// an event a caller built with another id is written under its own.
func TestAChangeEventEditedAfterItWasWrittenIsNotRead(t *testing.T) {
	spool := newTestSpool(t)
	ev := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeRefused, "anchor_invalid")
	ev.SHA256 = strings.Repeat("a", 64)
	if err := spool.Write(ev); err != nil {
		t.Fatal(err)
	}
	id := ev.ContentID()
	path := filepath.Join(spool.Dir, id+".json")
	written, err := ReadChangeEvent(path)
	if err != nil || written.EventID != id {
		t.Fatalf("written event = %+v (%v), want id %s", written, err, id)
	}
	if got := ReportableChangeEvents(spool.Dir, nil); len(got) != 1 || got[0].EventID != id {
		t.Fatalf("reportable = %+v", got)
	}
	for name, edit := range map[string]func(*ChangeEvent){
		"applied instead": func(ev *ChangeEvent) { ev.Outcome, ev.ReasonCode = ChangeApplied, "" },
		"another account": func(ev *ChangeEvent) { ev.Actor = "os:uid:501:alice" },
		"another file":    func(ev *ChangeEvent) { ev.SHA256 = strings.Repeat("c", 64) },
		"another time":    func(ev *ChangeEvent) { ev.Time = "2026-10-21T10:00:00Z" },
		"another reserver": func(ev *ChangeEvent) {
			ev.ReservationID = NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeFailed, ChangeInterrupted).EventID
		},
	} {
		t.Run(name, func(t *testing.T) {
			edited := written
			edit(&edited)
			raw, err := json.Marshal(edited)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o640); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadChangeEvent(path); err == nil {
				t.Fatal("an edited event was read")
			}
			if got := ReportableChangeEvents(spool.Dir, nil); len(got) != 0 {
				t.Fatalf("an edited event is reportable: %+v", got)
			}
			if settled := changeSettlements(spool.Dir); len(settled) != 0 {
				t.Fatalf("an edited event settles %v", settled)
			}
		})
	}
	forged := appliedSecretChange(t, "splunk-hec-token")
	forged.EventID = id
	if err := spool.Write(forged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool.Dir, forged.ContentID()+".json")); err != nil || forged.ContentID() == id {
		t.Fatalf("an event given another id was not written under its own: %v", err)
	}
}

// The outcome a command writes for its reservation is another event, with
// its own content id, that names the reservation; the reservation goes.
// An event naming itself as its reservation does not validate. The spool
// reports the outcome once and the reservation never: not while the
// command holds it, not once it wrote its outcome and stopped before it let
// go, and the next writer settles that reservation without recording the
// change again.
func TestAChangeOutcomeNamesItsReservation(t *testing.T) {
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	if got := ReportableChangeEvents(spool.Dir, nil); len(got) != 0 {
		t.Fatalf("a held reservation is reportable: %+v", got)
	}
	applied, data := outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
	if applied.EventID == r.id || applied.EventID != applied.ContentID() || applied.ReservationID != r.id {
		t.Fatalf("outcome %+v does not have its own id naming %s", applied, r.id)
	}
	if err := spool.writeEvent(applied.EventID, data); err != nil {
		t.Fatal(err)
	}
	if got := ReportableChangeEvents(spool.Dir, nil); len(got) != 0 {
		t.Fatalf("an outcome whose command still holds its reservation is reportable: %+v", got)
	}
	r.abandon() // The command stopped after its outcome, before it let go.
	if got := ReportableChangeEvents(spool.Dir, nil); len(got) != 1 || got[0].EventID != applied.EventID {
		t.Fatalf("reportable = %+v, want the outcome", got)
	}
	if got := EndedChangeReservations(spool.Dir); len(got) != 0 {
		t.Fatalf("a reservation its outcome settles was reported: %+v", got)
	}
	refusal := NewChangeEvent(ChangeKindSecret, ChangeActionRemove, ChangeRefused, "invalid_arguments")
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	events := readSpool(t, spool)
	if len(events) != 2 || events[0].EventID != applied.EventID || events[1].EventID != refusal.EventID ||
		events[1].ReservationID != "" {
		t.Fatalf("spool = %+v, want the outcome and the refusal (under its own id) only", events)
	}
	if files := reservationFiles(t, spool); len(files) != 0 {
		t.Fatalf("reservations left: %v", files)
	}
	self := applied
	self.ReservationID = applied.EventID
	self.EventID = self.ContentID()
	self.ReservationID = self.EventID
	if self.Validate() == nil {
		t.Fatal("an event naming itself as its reservation validates")
	}
}
