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
	"runtime"
	"strings"
	"sync"
	"testing"
)

func newTestSpool(t *testing.T) ChangeSpool {
	t.Helper()
	return ChangeSpool{Dir: filepath.Join(t.TempDir(), ChangeEventsDirName), StateDir: t.TempDir()}
}

func appliedSecretChange(t *testing.T, name string) ChangeEvent {
	t.Helper()
	ev := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeApplied, "")
	ev.SecretName = name
	return ev
}

// outcomeFor is the outcome event a command writes for the reservation id
// (as ChangeReservation.Write does: it names the reservation and has its own
// id) and its encoding.
func outcomeFor(t *testing.T, id string, ev ChangeEvent) (ChangeEvent, []byte) {
	t.Helper()
	ev.ReservationID = id
	ev, data, err := marshalChangeEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	return ev, data
}

func readSpool(t *testing.T, spool ChangeSpool) []ChangeEvent {
	t.Helper()
	var out []ChangeEvent
	for _, id := range ListChangeEventIDs(spool.Dir) {
		ev, err := ReadChangeEvent(filepath.Join(spool.Dir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// Writers race for the last free place while changes are made: only the
// commands that reserved room make their change, and every one of them
// records it. Before reservations, each command checked the room on its
// own, so all of them passed and only the first one's event fit.
func TestChangeSpoolConcurrentChangesAtTheLimitAllRecord(t *testing.T) {
	shrinkChangeSpool(t, 2, 4)
	spool := newTestSpool(t)
	writeSpoolEvents(t, spool, 3)
	const writers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		changed  int
		refused  int
		lost     []error
		start    = make(chan struct{})
		outcomes = make([]ChangeEvent, writers)
	)
	for i := range outcomes {
		outcomes[i] = appliedSecretChange(t, "splunk-hec-token")
	}
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				if errors.Is(err, ErrChangeSpoolFull) {
					refused++
				} else {
					lost = append(lost, err)
				}
				return
			}
			// The change is made here, while the other writers race.
			if err := r.Write(outcomes[i]); err != nil {
				mu.Lock()
				lost = append(lost, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			changed++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if len(lost) > 0 || changed != 1 || refused != writers-1 {
		t.Fatalf("changed=%d refused=%d lost=%v, want one change recorded and %d refused before changing", changed, refused, lost, writers-1)
	}
	if got := len(ListChangeEventIDs(spool.Dir)); got != 4 {
		t.Fatalf("spool holds %d events, want 4", got)
	}
}

// A held reservation keeps its place against a refusal, and Write fills
// the reserved place even when the spool is otherwise full.
func TestChangeReservationKeepsItsPlace(t *testing.T) {
	shrinkChangeSpool(t, 2, 3)
	spool := newTestSpool(t)
	writeSpoolEvents(t, spool, 2)
	r, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	if err := spool.Write(refusal); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("a refusal took the reserved place: %v", err)
	}
	if _, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token"); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("a second change reserved the same place: %v", err)
	}
	applied := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	if err := r.Write(applied); err != nil {
		t.Fatalf("write into the reserved place: %v", err)
	}
	if err := r.Write(applied); !errors.Is(err, errChangeReservationUsed) {
		t.Fatalf("a reservation was written twice: %v", err)
	}
	r.Release()
	events := readSpool(t, spool)
	if len(events) != 3 || events[2].ReservationID != r.id || events[2].EventID == r.id ||
		events[2].Outcome != ChangeApplied {
		t.Fatalf("spool = %+v, want the applied install naming the reservation", events)
	}
	if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
		t.Fatalf("reservations left: %v", entries)
	}
}

// Release gives the place back and records nothing.
func TestChangeReservationReleaseRecordsNothing(t *testing.T) {
	shrinkChangeSpool(t, 2, 1)
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
	r.Release()
	if got := ListChangeEventIDs(spool.Dir); len(got) != 0 {
		t.Fatalf("a released reservation recorded %v", got)
	}
	again, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatalf("the released place was not given back: %v", err)
	}
	again.Release()
}

// A command that ends between its change and its event leaves its
// reservation unlocked; the next writer records it as an interrupted
// change with the credential name, once. A reservation whose command wrote
// its event before it ended adds no second record.
func TestChangeSpoolRecordsTheReservationOfACommandThatEnded(t *testing.T) {
	spool := newTestSpool(t)
	ended, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ended.abandon() // The process stopped after the change.
	written, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	applied, data := outcomeFor(t, written.id, NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, ""))
	if err := spool.writeEvent(applied.EventID, data); err != nil {
		t.Fatal(err)
	}
	written.abandon() // The process stopped after the event, before the cleanup.
	held, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	events := readSpool(t, spool)
	if len(events) != 2 {
		t.Fatalf("spool = %+v, want the interrupted set and the applied install", events)
	}
	interrupted := events[0]
	if interrupted.EventID != ended.id || interrupted.Kind != ChangeKindSecret || interrupted.Outcome != ChangeFailed ||
		interrupted.ReasonCode != ChangeInterrupted || interrupted.SecretName != "splunk-hec-token" {
		t.Fatalf("interrupted change = %+v", interrupted)
	}
	if events[1].ReservationID != written.id || events[1].Outcome != ChangeApplied {
		t.Fatalf("applied install = %+v", events[1])
	}
	entries, err := os.ReadDir(spool.reservedDir())
	if err != nil || len(entries) != 1 || entries[0].Name() != held.id+".json" {
		t.Fatalf("reservations = %v (%v), want only the held one", entries, err)
	}
}

// The gateway, which only reads the spool, finds the reservation of a
// command that ended after its change (the change may have been made) and
// nothing else: not a held one, not one whose command wrote its event or
// released it, not one whose event is in the spool, not an empty or a
// damaged one. Before, such a reservation sat in the root-only lifecycle
// folder until the next change command, so a gateway restart alone never
// reported it.
func TestEndedChangeReservationsAreTheCommandsThatEndedAfterTheirChange(t *testing.T) {
	spool := newTestSpool(t)
	held, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	written, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	applied := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	if err := written.Write(applied); err != nil {
		t.Fatal(err)
	}
	released, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token")
	if err != nil {
		t.Fatal(err)
	}
	released.Release()
	// The last reservation: every Reserve moves the ended ones into the
	// spool first.
	ended, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ended.abandon() // The process stopped after the change.
	// A command that stopped after its event, before the cleanup; one that
	// stopped before its reservation held its event; a damaged reservation.
	beforeCleanup, provisional, err := marshalChangeEvent(
		NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeFailed, ChangeInterrupted))
	if err != nil {
		t.Fatal(err)
	}
	settling, data := outcomeFor(t, beforeCleanup.EventID, applied)
	if err := spool.writeEvent(settling.EventID, data); err != nil {
		t.Fatal(err)
	}
	empty := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeFailed, ChangeInterrupted)
	damaged := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeFailed, ChangeInterrupted)
	for id, body := range map[string]string{beforeCleanup.EventID: string(provisional), empty.EventID: "",
		damaged.EventID: `{"event_id":"` + damaged.EventID + `"}`} {
		if err := os.WriteFile(filepath.Join(spool.reservedDir(), id+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := EndedChangeReservations(spool.Dir)
	if len(got) != 1 || got[0].EventID != ended.id || got[0].Outcome != ChangeFailed || got[0].ReasonCode != ChangeInterrupted ||
		got[0].SecretName != "splunk-hec-token" {
		t.Fatalf("ended reservations = %+v, want only the interrupted set %s", got, ended.id)
	}
	// Reading takes nothing: the held reservation keeps its lock, and the
	// next writer still moves the ended one into the spool.
	if err := held.Write(applied); err != nil {
		t.Fatalf("the held reservation lost its place: %v", err)
	}
	refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
		t.Fatalf("reservations left after the next writer: %v", entries)
	}
	ids := ListChangeEventIDs(spool.Dir)
	found := false
	for _, id := range ids {
		found = found || id == ended.id
	}
	if !found {
		t.Fatalf("spool = %v, want the ended reservation moved in", ids)
	}
	if got := EndedChangeReservations(spool.Dir); len(got) != 0 {
		t.Fatalf("ended reservations after the next writer = %+v", got)
	}
	if got := EndedChangeReservations(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("a missing spool has ended reservations: %+v", got)
	}
}

// A writer can publish an outcome while the gateway walks a directory of
// reservations. The gateway must check the spool after it locks each one:
// the settlement map it read for an earlier reservation is already stale.
func TestEndedChangeReservationsSeeOutcomesWrittenDuringTheScan(t *testing.T) {
	spool := newTestSpool(t)
	left, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	right, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	first, second := left, right
	if first.id > second.id {
		first, second = second, first
	}
	first.abandon()
	originalFlush := flushEndedReservation
	t.Cleanup(func() { flushEndedReservation = originalFlush })
	flushEndedReservation = func(file *os.File) error {
		if file.Name() == first.path {
			outcome, data := outcomeFor(t, second.id,
				NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, ""))
			if err := spool.writeEvent(outcome.EventID, data); err != nil {
				t.Fatal(err)
			}
			second.abandon() // The command stopped before cleaning up.
		}
		return originalFlush(file)
	}
	got := EndedChangeReservations(spool.Dir)
	if len(got) != 1 || got[0].EventID != first.id {
		t.Fatalf("ended reservations = %+v, want only %s", got, first.id)
	}
}

// The spool needs its existing state directory: without one nothing is
// written.
func TestChangeSpoolNeedsItsStateDirectory(t *testing.T) {
	spool := ChangeSpool{Dir: filepath.Join(t.TempDir(), ChangeEventsDirName)}
	if err := spool.Write(appliedSecretChange(t, "splunk-hec-token")); err == nil {
		t.Fatal("wrote without a state directory")
	}
	spool.StateDir = filepath.Join(t.TempDir(), "missing")
	if _, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token"); err == nil {
		t.Fatal("reserved in a missing state directory")
	}
}

// publishLog is a Publish hook that records each path it was given and
// whether <event_id>.json already existed then; fail makes it refuse.
type publishLog struct {
	mu     sync.Mutex
	paths  []string
	early  []string
	fail   error
	onCall func(path string)
}

func (l *publishLog) publish(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths = append(l.paths, path)
	if base := filepath.Base(path); strings.HasPrefix(base, ".") {
		rest, _ := strings.CutPrefix(base, ".")
		if id, _, ok := strings.Cut(rest, ".json."); ok {
			if _, err := os.Lstat(filepath.Join(filepath.Dir(path), id+".json")); err == nil {
				l.early = append(l.early, id)
			}
		}
	}
	if l.onCall != nil {
		l.onCall(path)
	}
	return l.fail
}

// An event gets the gateway's access before it is in the spool: Publish
// runs on the temp file, and <event_id>.json never exists with another
// access. Before, the event was renamed into place root-only and Publish
// gave it the gateway's group after, so a command that stopped in between
// left an event the gateway could not read.
func TestChangeEventIsPublishedBeforeItIsInTheSpool(t *testing.T) {
	log := &publishLog{}
	spool := newTestSpool(t)
	spool.Publish = log.publish
	refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	applied := appliedSecretChange(t, "splunk-hec-token")
	if err := r.Write(applied); err != nil {
		t.Fatal(err)
	}
	written, _ := outcomeFor(t, r.id, applied)
	for _, id := range []string{refusal.EventID, written.EventID} {
		final := filepath.Join(spool.Dir, id+".json")
		published := false
		for _, path := range log.paths {
			if path == final {
				t.Fatalf("Publish ran on %s after the rename", final)
			}
			published = published || strings.HasPrefix(filepath.Base(path), "."+id+".json.")
		}
		if !published {
			t.Fatalf("Publish never ran on the temp file of %s: %v", id, log.paths)
		}
	}
	if len(log.early) != 0 {
		t.Fatalf("events in the spool before Publish: %v", log.early)
	}
	if got := len(readSpool(t, spool)); got != 2 {
		t.Fatalf("spool holds %d events, want 2", got)
	}
}

// A command stops while its event is being given the gateway's access (or
// the access cannot be set): no event is in the spool, the reservation
// stays, the gateway reports it as interrupted, and the next writer moves
// it into the spool with the gateway's access, once. Before, the event was
// already in the spool root-only: the gateway could not read it, skipped
// the reservation because the event existed, and the next writer removed
// the reservation, so the change was never reported.
func TestChangeSpoolKeepsTheReservationOfACommandThatStoppedWhilePublishing(t *testing.T) {
	for _, stop := range []string{"process stopped", "publish refused"} {
		t.Run(stop, func(t *testing.T) {
			log := &publishLog{}
			spool := newTestSpool(t)
			spool.Publish = log.publish
			r, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
			if err != nil {
				t.Fatal(err)
			}
			applied := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
			log.mu.Lock()
			if stop == "process stopped" {
				log.onCall = func(string) { runtime.Goexit() } // Goexit runs the deferred unlock
			} else {
				log.fail = errors.New("chown refused")
			}
			log.mu.Unlock()
			done := make(chan error, 1)
			go func() {
				defer close(done)
				done <- r.Write(applied)
			}()
			if err := <-done; stop == "publish refused" && err == nil {
				t.Fatal("the write reported success without the gateway's access")
			}
			// The process ended: its reservation lock goes with it.
			if r.file != nil {
				r.abandon()
			}
			log.mu.Lock()
			log.onCall, log.fail = nil, nil
			log.mu.Unlock()
			if ids := ListChangeEventIDs(spool.Dir); len(ids) != 0 {
				t.Fatalf("the event is in the spool without the gateway's access: %v", ids)
			}
			got := EndedChangeReservations(spool.Dir)
			if len(got) != 1 || got[0].EventID != r.id || got[0].ReasonCode != ChangeInterrupted {
				t.Fatalf("the gateway sees %+v, want the interrupted install %s", got, r.id)
			}
			refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
			if err := spool.Write(refusal); err != nil {
				t.Fatal(err)
			}
			events := readSpool(t, spool)
			if len(events) != 2 || events[0].EventID != r.id || events[0].ReasonCode != ChangeInterrupted {
				t.Fatalf("spool = %+v, want the interrupted install first", events)
			}
			if len(log.early) != 0 {
				t.Fatalf("events in the spool before Publish: %v", log.early)
			}
			if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
				t.Fatalf("reservations left: %v", entries)
			}
			if leftovers := spoolTempFiles(t, spool); len(leftovers) != 0 {
				t.Fatalf("temp files left: %v", leftovers)
			}
		})
	}
}

// The next writer removes a reservation whose event is in the spool only
// once that event validates and Publish gave it the gateway's access
// again; a failed Publish keeps the reservation for a later writer. An
// event file that does not validate is replaced by the reservation's
// event. Before, any file at <event_id>.json made the writer drop the
// reservation, so an event the gateway could not read or validate lost
// the change.
func TestChangeSpoolKeepsAReservationUntilItsEventIsReadable(t *testing.T) {
	for _, stored := range []string{"valid event, access lost", "damaged event"} {
		t.Run(stored, func(t *testing.T) {
			log := &publishLog{}
			spool := newTestSpool(t)
			spool.Publish = log.publish
			r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
			if err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(spool.Dir, r.id+".json")
			body := []byte("{\"event_id\":\"" + r.id + "\"}\n")
			want := ChangeInterrupted
			if stored == "valid event, access lost" {
				var applied ChangeEvent
				applied, body = outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
				final = filepath.Join(spool.Dir, applied.EventID+".json")
				want = ""
			}
			if err := os.WriteFile(final, body, 0o600); err != nil {
				t.Fatal(err)
			}
			r.abandon() // The process stopped before its cleanup.
			if stored == "damaged event" {
				// The gateway cannot use the stored event, so it reports the
				// reservation.
				if got := EndedChangeReservations(spool.Dir); len(got) != 1 || got[0].EventID != r.id {
					t.Fatalf("the gateway sees %+v, want the reservation %s", got, r.id)
				}
			}
			log.mu.Lock()
			log.fail = errors.New("chown refused")
			log.mu.Unlock()
			refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
			if err := spool.Write(refusal); err == nil {
				t.Fatal("the writer settled the reservation without the gateway's access")
			}
			if _, err := os.Lstat(filepath.Join(spool.reservedDir(), r.id+".json")); err != nil {
				t.Fatalf("the reservation was removed before its event was readable: %v", err)
			}
			log.mu.Lock()
			log.fail, log.paths = nil, nil
			log.mu.Unlock()
			if err := spool.Write(refusal); err != nil {
				t.Fatal(err)
			}
			if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
				t.Fatalf("reservations left: %v", entries)
			}
			ev, err := ReadChangeEvent(final)
			if err != nil || ev.ReasonCode != want {
				t.Fatalf("stored event = %+v (%v), want reason %q", ev, err, want)
			}
			published := false
			for _, path := range log.paths {
				published = published || path == final || strings.HasPrefix(filepath.Base(path), "."+r.id+".json.")
			}
			if !published {
				t.Fatalf("Publish never ran on the event of %s: %v", r.id, log.paths)
			}
		})
	}
}

// The gateway reports the reservation of a command that ended when the
// event in the spool is one it cannot read. Before, the event's existence
// alone made it skip the reservation.
func TestEndedChangeReservationsReportsAReservationWhoseEventTheGatewayCannotRead(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a POSIX account that a 0000 file locks out")
	}
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	applied, data := outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
	final := filepath.Join(spool.Dir, applied.EventID+".json")
	if err := os.WriteFile(final, data, 0); err != nil {
		t.Fatal(err)
	}
	r.abandon()
	got := EndedChangeReservations(spool.Dir)
	if len(got) != 1 || got[0].EventID != r.id || got[0].ReasonCode != ChangeInterrupted {
		t.Fatalf("the gateway sees %+v, want the interrupted set %s", got, r.id)
	}
}

// The next writer removes the temp file an event write left when its
// command stopped before the rename, and nothing else.
func TestChangeSpoolRemovesTheTempFileOfAStoppedEventWrite(t *testing.T) {
	spool := newTestSpool(t)
	if err := spool.Write(appliedSecretChange(t, "splunk-hec-token")); err != nil {
		t.Fatal(err)
	}
	stopped := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	leftover := filepath.Join(spool.Dir, "."+stopped.EventID+".json.1234567.tmp")
	other := filepath.Join(spool.Dir, ".notes.tmp")
	for _, path := range []string{leftover, other} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Write(appliedSecretChange(t, "otlp-token")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stopped write's temp file is still there: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("a file that is not an event temp file was removed: %v", err)
	}
	if got := len(readSpool(t, spool)); got != 2 {
		t.Fatalf("spool holds %d events, want 2", got)
	}
}

func spoolTempFiles(t *testing.T, spool ChangeSpool) []string {
	t.Helper()
	entries, err := os.ReadDir(spool.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			out = append(out, entry.Name())
		}
	}
	return out
}

// recordChangeSyncs records, in order, the folders ("dir <path>") and files
// ("file <path>") the spool flushes; check runs on each before the flush.
func recordChangeSyncs(t *testing.T, check func(entry string) error) *[]string {
	t.Helper()
	savedDir, savedFile := syncChangeDir, syncChangeFile
	t.Cleanup(func() { syncChangeDir, syncChangeFile = savedDir, savedFile })
	var mu sync.Mutex
	var log []string
	record := func(entry string, flush func(string) error, path string) error {
		mu.Lock()
		log = append(log, entry)
		mu.Unlock()
		if check != nil {
			if err := check(entry); err != nil {
				return err
			}
		}
		return flush(path)
	}
	syncChangeDir = func(dir string) error { return record("dir "+dir, savedDir, dir) }
	syncChangeFile = func(path string) error { return record("file "+path, savedFile, path) }
	return &log
}

// A reservation is durable when Reserve returns: the reserved folder is
// flushed after the reservation is in it, and the parent of every folder
// the spool creates for it is flushed, so a power loss after the change
// cannot lose the event. Before, only the reservation file was flushed:
// its entry, and on the first change the spool folders, could be lost
// with the change already made.
func TestChangeReservationIsDurableWhenReserveReturns(t *testing.T) {
	base := t.TempDir()
	spool := ChangeSpool{Dir: filepath.Join(base, "bundles", ChangeEventsDirName), StateDir: t.TempDir()}
	reserved := filepath.Join(spool.Dir, ChangeReservedDirName)
	// The releases at the end flush the folder after their removal.
	reserving := true
	log := recordChangeSyncs(t, func(entry string) error {
		if reserving && entry == "dir "+reserved && len(reservationFiles(t, spool)) == 0 {
			t.Fatalf("the reserved folder was flushed before the reservation was in it")
		}
		return nil
	})
	first, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { reserving = false; _ = first.Release() }()
	want := []string{"dir " + base, "dir " + filepath.Join(base, "bundles"), "dir " + spool.Dir, "dir " + reserved}
	if strings.Join(*log, "|") != strings.Join(want, "|") {
		t.Fatalf("first reservation flushed %v, want %v", *log, want)
	}
	*log = nil
	second, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { reserving = false; _ = second.Release() }()
	if strings.Join(*log, "|") != "dir "+reserved {
		t.Fatalf("second reservation flushed %v, want only the reserved folder", *log)
	}
}

// A reservation that cannot be made durable is not made: Reserve fails and
// leaves no reservation, so the command changes nothing (fail closed). The
// same holds when a folder created for it cannot be flushed into its parent.
func TestChangeReservationThatCannotBeFlushedIsNotMade(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(spool ChangeSpool) string
	}{
		{"reserved folder", func(s ChangeSpool) string { return filepath.Join(s.Dir, ChangeReservedDirName) }},
		{"new reserved folder in the spool", func(s ChangeSpool) string { return s.Dir }},
		{"new spool folder in its parent", func(s ChangeSpool) string { return filepath.Dir(s.Dir) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spool := newTestSpool(t)
			failing := tc.fail(spool)
			flushErr := errors.New("flush failed")
			recordChangeSyncs(t, func(entry string) error {
				if entry == "dir "+failing {
					return flushErr
				}
				return nil
			})
			if _, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, ""); !errors.Is(err, flushErr) {
				t.Fatalf("Reserve err = %v, want the flush error", err)
			}
			if files := reservationFiles(t, spool); len(files) != 0 {
				t.Fatalf("reservations left after a failed flush: %v", files)
			}
		})
	}
}

// An event a stopped command left in the spool gets the gateway's access
// again (Publish) and that access is flushed before the next writer removes
// the reservation; a failed flush keeps the reservation. Before, the
// reservation could go while the new access was not yet durable.
func TestChangeSpoolFlushesARepublishedEventBeforeItRemovesTheReservation(t *testing.T) {
	for _, flushFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "flushed", true: "flush fails"}[flushFails], func(t *testing.T) {
			pub := &publishLog{}
			spool := newTestSpool(t)
			spool.Publish = pub.publish
			r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
			if err != nil {
				t.Fatal(err)
			}
			ev, data := outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
			if err := spool.writeEvent(ev.EventID, data); err != nil {
				t.Fatal(err)
			}
			r.abandon() // The command stopped after its event, before it let go of the reservation.
			final := filepath.Join(spool.Dir, ev.EventID+".json")
			reservation := filepath.Join(spool.reservedDir(), r.id+".json")
			flushErr := errors.New("flush failed")
			log := recordChangeSyncs(t, func(entry string) error {
				if entry != "file "+final {
					return nil
				}
				if _, err := os.Lstat(reservation); err != nil {
					t.Fatalf("the reservation went before the event's access was flushed: %v", err)
				}
				pub.mu.Lock()
				defer pub.mu.Unlock()
				if len(pub.paths) == 0 || pub.paths[len(pub.paths)-1] != final {
					t.Fatalf("flushed %s before Publish ran on it: %v", final, pub.paths)
				}
				if flushFails {
					return flushErr
				}
				return nil
			})
			refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
			err = spool.Write(refusal)
			if !strings.Contains(strings.Join(*log, "|"), "file "+final) {
				t.Fatalf("the republished event was never flushed: %v", *log)
			}
			_, statErr := os.Lstat(reservation)
			if flushFails {
				if !errors.Is(err, flushErr) || statErr != nil {
					t.Fatalf("failed flush: write err = %v, reservation %v; want the flush error and the reservation kept", err, statErr)
				}
				return
			}
			if err != nil || !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("write err = %v, reservation %v; want the reservation removed", err, statErr)
			}
		})
	}
}

// A released reservation is gone for good when Release returns: the emptied
// file is flushed while it is still in the reserved folder, and the folder
// once the file is removed, so a power loss cannot bring back the
// interrupted event of a command that changed nothing (the gateway would
// report a change that never happened). Release fails only when neither
// flush worked; on Windows, where a folder cannot be flushed, when the
// emptied file was not. Before, neither the truncation nor the removal was
// flushed and Release returned nothing. A reservation Reserve gives up is
// emptied and flushed the same way.
func TestChangeReservationReleaseIsDurable(t *testing.T) {
	flushErr := errors.New("flush failed")
	watch := func(t *testing.T, spool ChangeSpool, failHandle, failDir bool) *[]string {
		t.Helper()
		var order []string
		reserved := spool.reservedDir()
		savedHandle := syncChangeHandle
		t.Cleanup(func() { syncChangeHandle = savedHandle })
		syncChangeHandle = func(file *os.File) error {
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != 0 || len(reservationFiles(t, spool)) != 1 {
				t.Fatalf("flushed a reservation of %d bytes, or one no longer in its folder", info.Size())
			}
			order = append(order, "emptied file")
			if failHandle {
				return flushErr
			}
			return savedHandle(file)
		}
		recordChangeSyncs(t, func(entry string) error {
			if entry != "dir "+reserved {
				return nil
			}
			order = append(order, "reserved folder")
			if failDir {
				return flushErr
			}
			return nil
		})
		return &order
	}
	for _, tc := range []struct {
		name                string
		failHandle, failDir bool
		wantErr             bool
	}{
		{"both flushed", false, false, false},
		{"emptied file not flushed", true, false, runtime.GOOS == "windows"},
		{"folder not flushed", false, true, false},
		{"neither flushed", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spool := newTestSpool(t)
			r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
			if err != nil {
				t.Fatal(err)
			}
			order := watch(t, spool, tc.failHandle, tc.failDir)
			err = r.Release()
			if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, flushErr)) {
				t.Fatalf("Release err = %v, want an error %t", err, tc.wantErr)
			}
			if got := strings.Join(*order, "|"); got != "emptied file|reserved folder" {
				t.Fatalf("Release flushed %q, want the emptied file, then the reserved folder", got)
			}
			if files := reservationFiles(t, spool); len(files) != 0 {
				t.Fatalf("reservations left: %v", files)
			}
			if err := r.Release(); err != nil {
				t.Fatalf("a second Release: %v", err)
			}
		})
	}
	t.Run("given up by Reserve", func(t *testing.T) {
		spool := newTestSpool(t)
		// The reserved folder exists, so the first flush of it is the one
		// after the reservation is in it.
		if r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "a"); err != nil {
			t.Fatal(err)
		} else if err := r.Release(); err != nil {
			t.Fatal(err)
		}
		order := watch(t, spool, false, true)
		if _, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token"); !errors.Is(err, flushErr) {
			t.Fatalf("Reserve err = %v, want the flush error", err)
		}
		if got := strings.Join(*order, "|"); got != "reserved folder|emptied file|reserved folder" {
			t.Fatalf("Reserve flushed %q, want the emptied reservation flushed before it went", got)
		}
		if files := reservationFiles(t, spool); len(files) != 0 {
			t.Fatalf("reservations left: %v", files)
		}
	})
}

// reservationFiles lists the files in the reserved folder (none when it is
// not there).
func reservationFiles(t *testing.T, spool ChangeSpool) []string {
	t.Helper()
	entries, err := os.ReadDir(spool.reservedDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		out = append(out, entry.Name())
	}
	return out
}

// Every event is written under a reservation held until its entry in the
// spool is flushed, a refusal (Write) included, and the reservation holds
// the refusal itself. Before, Write renamed a refusal into the spool with
// no reservation: the gateway could read and report it before the folder
// was flushed, and a power loss then took the event back with nothing left
// to record it again.
func TestChangeSpoolWritesARefusalUnderItsReservation(t *testing.T) {
	spool := newTestSpool(t)
	refusal := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	reservation := filepath.Join(spool.reservedDir(), refusal.EventID+".json")
	held := false
	pub := &publishLog{onCall: func(path string) {
		if !strings.HasPrefix(filepath.Base(path), "."+refusal.EventID+".json.") {
			return
		}
		held = changeReservationHeld(reservation)
		if runtime.GOOS == "windows" {
			// Windows' exclusive lock covers byte zero, so a second handle
			// cannot read the JSON while the writer holds the reservation.
			return
		}
		file, err := os.Open(reservation)
		if err != nil {
			t.Errorf("no reservation while the refusal is written: %v", err)
			return
		}
		defer file.Close()
		if _, ev, ok := readReservation(file, refusal.EventID); !ok || ev.Outcome != ChangeRefused ||
			ev.ReasonCode != "invalid_arguments" {
			t.Errorf("the reservation does not hold the refusal: %+v", ev)
		}
	}}
	spool.Publish = pub.publish
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("the refusal was written without a held reservation")
	}
	if files := reservationFiles(t, spool); len(files) != 0 {
		t.Fatalf("reservations left after the write: %v", files)
	}
	if got := readSpool(t, spool); len(got) != 1 || got[0].EventID != refusal.EventID {
		t.Fatalf("spool = %+v", got)
	}
}

// The gateway reports an event only once it is on disk to stay: not while
// its writer still holds its reservation (the rename is not flushed yet),
// and only after the spool folder is flushed, for a writer that stopped
// between its rename and its flush. A reported event is skipped without a
// flush. Before, the gateway reported every event it could read.
func TestReportableChangeEventsAreOnDiskToStay(t *testing.T) {
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ev, data := outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
	// Renamed into the spool; the writer has not flushed it nor let go.
	if err := os.WriteFile(filepath.Join(spool.Dir, ev.EventID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if ids := ReportableChangeEvents(spool.Dir, nil); len(ids) != 0 {
		t.Fatalf("an event its writer still holds is reportable: %v", ids)
	}
	r.abandon() // The writer stopped after the rename.
	flushErr := errors.New("flush failed")
	failing := true
	log := recordChangeSyncs(t, func(entry string) error {
		if failing && entry == "dir "+spool.Dir {
			return flushErr
		}
		return nil
	})
	if ids := ReportableChangeEvents(spool.Dir, nil); len(ids) != 0 {
		t.Fatalf("an event whose folder cannot be flushed is reportable: %v", ids)
	}
	failing = false
	if ids := ReportableChangeEvents(spool.Dir, nil); len(ids) != 1 || ids[0].EventID != ev.EventID {
		t.Fatalf("reportable = %v, want %s", ids, ev.EventID)
	}
	if strings.Join(*log, "|") != "dir "+spool.Dir+"|dir "+spool.Dir {
		t.Fatalf("flushed %v, want the spool folder", *log)
	}
	*log = nil
	if ids := ReportableChangeEvents(spool.Dir, func(string) bool { return true }); len(ids) != 0 || len(*log) != 0 {
		t.Fatalf("reported events are reportable %v, flushed %v", ids, *log)
	}
}

// A reservation is reported only once it is on disk to stay: a command
// that stopped inside Reserve may not have flushed its file or its folder,
// so the gateway flushes both first and reports nothing when it cannot.
// Before, it reported the reservation as read, and a power loss could take
// it back after the gateway stored it, with nothing left to offer again.
func TestEndedChangeReservationsAreFlushedBeforeTheyAreReported(t *testing.T) {
	for _, fail := range []string{"", "file", "folder"} {
		t.Run("fail "+fail, func(t *testing.T) {
			spool := newTestSpool(t)
			r, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
			if err != nil {
				t.Fatal(err)
			}
			r.abandon() // The command ended before it wrote its event.
			flushErr := errors.New("flush failed")
			savedFlush := flushEndedReservation
			t.Cleanup(func() { flushEndedReservation = savedFlush })
			flushed := 0
			flushEndedReservation = func(file *os.File) error {
				flushed++
				if fail == "file" {
					return flushErr
				}
				return savedFlush(file)
			}
			log := recordChangeSyncs(t, func(entry string) error {
				if fail == "folder" && entry == "dir "+spool.reservedDir() {
					return flushErr
				}
				return nil
			})
			got := EndedChangeReservations(spool.Dir)
			if fail != "" {
				if len(got) != 0 {
					t.Fatalf("a reservation that cannot be flushed was reported: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].EventID != r.id || flushed != 1 ||
				strings.Join(*log, "|") != "dir "+spool.reservedDir() {
				t.Fatalf("reported %+v after flushing the file %d times and %v", got, flushed, *log)
			}
		})
	}
}

// A writer that keeps the event a stopped command renamed into the spool
// flushes the spool folder before it removes that command's reservation.
// Before, it removed the reservation with the rename maybe not on disk, so
// a power loss could lose both the event and its reservation.
func TestChangeSpoolFlushesAKeptEventBeforeItRemovesTheReservation(t *testing.T) {
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ev, data := outcomeFor(t, r.id, appliedSecretChange(t, "splunk-hec-token"))
	if err := os.WriteFile(filepath.Join(spool.Dir, ev.EventID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r.abandon() // The command stopped after its rename, before its flush.
	reservation := filepath.Join(spool.reservedDir(), r.id+".json")
	flushedFirst := false
	recordChangeSyncs(t, func(entry string) error {
		if entry == "dir "+spool.Dir && !flushedFirst {
			if _, err := os.Lstat(reservation); err == nil {
				flushedFirst = true
			}
		}
		return nil
	})
	next, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := next.Release(); err != nil {
			t.Error(err)
		}
	})
	if !flushedFirst {
		t.Fatal("the reservation went before the kept event was flushed")
	}
	if _, err := os.Lstat(reservation); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the settled reservation is still there: %v", err)
	}
}
