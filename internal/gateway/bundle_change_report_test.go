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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func writeTestChangeEvent(t *testing.T, dir string, kind, action, outcome, code string, edit func(*enterprisestatus.ChangeEvent)) enterprisestatus.ChangeEvent {
	t.Helper()
	ev := enterprisestatus.NewChangeEvent(kind, action, outcome, code)
	if edit != nil {
		edit(&ev)
	}
	ev.EventID = ev.ContentID()
	if err := (enterprisestatus.ChangeSpool{Dir: dir, StateDir: t.TempDir()}).Write(ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// A change made while the gateway was stopped waits in the spool and is
// reported once at the next start; a restart does not report it again.
func TestBundleReceiptReporterReportsEachChangeEventOnce(t *testing.T) {
	dir := t.TempDir()
	receipts := enterprisestatus.PublicReceiptPath(dir)
	spool := enterprisestatus.ChangeEventsDir(dir)
	sink := &fakeBundleReceiptSink{}
	newReporter := func() *bundleReceiptReporter {
		return &bundleReceiptReporter{receiptPath: receipts, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
			sink: sink, enforcedVersion: func() uint64 { return 0 }}
	}
	anchors := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) {
			ev.SHA256, ev.KeyIDsAdded = strings.Repeat("a", 64), []string{"fleet-2026-11"}
		})
	secret := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	reporter := newReporter()
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	newReporter().poll(context.Background())
	if len(sink.changes) != 2 || sink.changes[0].EventID != anchors.EventID || sink.changes[1].EventID != secret.EventID ||
		sink.changes[0].SHA256 != anchors.SHA256 || sink.changes[0].KeyIDsAdded[0] != "fleet-2026-11" ||
		sink.changes[1].SecretName != "splunk-hec-token" || sink.changes[1].Actor == "" {
		t.Fatalf("changes = %+v", sink.changes)
	}
	failed := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeRefused, "invalid_arguments", nil)
	newReporter().poll(context.Background())
	if len(sink.changes) != 3 || sink.changes[2].EventID != failed.EventID || sink.changes[2].ReasonCode != "invalid_arguments" ||
		sink.changes[2].SecretName != "" {
		t.Fatalf("changes = %+v", sink.changes)
	}
}

// A file in the spool that does not validate is never reported. An event
// the audit logger refuses is never marked reported, however often it is
// refused: it is reported once the logger takes it, and only once.
func TestBundleReceiptReporterKeepsRefusedChangeEventsUntilRecorded(t *testing.T) {
	dir := t.TempDir()
	spool := enterprisestatus.ChangeEventsDir(dir)
	if err := os.MkdirAll(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W.json"),
		[]byte(`{"schema_version":1,"event_id":"c-01JB8Z4X6T2Q9V3M5N7P1R0S4W","kind":"token","action":"set","outcome":"applied","time":"2026-10-21T10:00:00Z","secret_name":"x"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sink := &fakeBundleReceiptSink{changeErr: errors.New("audit store unavailable")}
	reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
		markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
	ev := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "otlp-token" })
	for i := 0; i < 3*bundleReceiptRetries; i++ {
		reporter.poll(context.Background())
	}
	if reporter.hasSeen(ev.EventID) || enterprisestatus.ChangeReported(dir, ev.EventID) {
		t.Fatal("a change event the audit logger refused was marked reported")
	}
	sink.changeErr = nil
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	if len(sink.changes) != 1 || sink.changes[0].EventID != ev.EventID {
		t.Fatalf("changes = %+v, want the refused event once", sink.changes)
	}
	if !enterprisestatus.ChangeReported(dir, ev.EventID) {
		t.Fatal("the recorded event has no marker the change commands can read")
	}
}

// The markers stay where earlier builds wrote them (<data>/bundle-receipt.reported.d),
// so an upgraded gateway does not report its receipts again and the change
// commands read the same folder.
func TestBundleReceiptReporterMarkersFolderIsStable(t *testing.T) {
	dir := t.TempDir()
	reporter := &bundleReceiptReporter{markerPath: filepath.Join(dir, bundleReceiptMarkerName)}
	if got, want := reporter.seenDir(), filepath.Join(dir, bundleReceiptMarkerName)+".d"; got != want {
		t.Fatalf("markers folder = %s, want %s", got, want)
	}
}

// A command that ends after its change and before its event leaves only
// its reservation. The gateway reports it (failed, interrupted) at its
// next start, with no other change command run since, and once: not again
// after a restart, nor once a later command moves it into the spool. A
// reservation still held is not reported. Before, only the next change
// command recorded it, so a gateway restart alone left the change
// unaudited.
func TestBundleReceiptReporterReportsAnInterruptedChangeAtRestart(t *testing.T) {
	dir := t.TempDir()
	spoolDir := enterprisestatus.ChangeEventsDir(dir)
	spool := enterprisestatus.ChangeSpool{Dir: spoolDir, StateDir: t.TempDir(),
		Reported: func(id string) bool { return enterprisestatus.ChangeReported(dir, id) }}
	held, err := spool.Reserve(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	// The reservation of a command that was killed after it changed the
	// credential: the provisional event, with no lock on it.
	ended := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeFailed, enterprisestatus.ChangeInterrupted)
	ended.SecretName = "splunk-hec-token"
	ended.EventID = ended.ContentID()
	raw, err := json.Marshal(ended)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, enterprisestatus.ChangeReservedDirName, ended.EventID+".json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	sink := &fakeBundleReceiptSink{}
	newReporter := func() *bundleReceiptReporter {
		return &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
			markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
	}
	newReporter().poll(context.Background()) // The gateway restarts.
	if len(sink.changes) != 1 || sink.changes[0].EventID != ended.EventID || sink.changes[0].Outcome != enterprisestatus.ChangeFailed ||
		sink.changes[0].ReasonCode != enterprisestatus.ChangeInterrupted || sink.changes[0].SecretName != "splunk-hec-token" {
		t.Fatalf("changes = %+v, want the interrupted secret set only", sink.changes)
	}
	newReporter().poll(context.Background())
	// The next change command moves the reservation into the spool.
	refusal := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove,
		enterprisestatus.ChangeRefused, "invalid_arguments")
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	newReporter().poll(context.Background())
	if len(sink.changes) != 2 || sink.changes[1].EventID != refusal.EventID {
		t.Fatalf("changes = %+v, want the interrupted set once, then the refusal", sink.changes)
	}
}

// The gateway reports a change event only once it is on disk to stay. While
// the command that writes it still holds its reservation, the rename may
// not be flushed: a power loss could take the event back after the
// gateway stored and offered it, and a destination that refused it would
// never be offered it again. Before, the gateway reported every event it
// could read, so it reported this one at once.
func TestBundleReceiptReporterWaitsForTheWriterToFlushAChangeEvent(t *testing.T) {
	dir := t.TempDir()
	spool := enterprisestatus.ChangeSpool{Dir: enterprisestatus.ChangeEventsDir(dir), StateDir: t.TempDir()}
	reservation, err := spool.Reserve(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(spool.Dir, enterprisestatus.ChangeReservedDirName))
	if err != nil || len(entries) != 1 {
		t.Fatalf("reservations %v err %v", entries, err)
	}
	id := strings.TrimSuffix(entries[0].Name(), ".json")
	ev := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall,
		enterprisestatus.ChangeApplied, "")
	ev.SHA256, ev.ReservationID = strings.Repeat("a", 64), id
	ev.EventID = ev.ContentID()
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	// The writer renamed the event into the spool and has not flushed it.
	if err := os.WriteFile(filepath.Join(spool.Dir, ev.EventID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &fakeBundleReceiptSink{}
	reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
		markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
	reporter.poll(context.Background())
	if len(sink.changes) != 0 {
		t.Fatalf("an event its writer still holds was reported: %+v", sink.changes)
	}
	if err := reservation.Write(ev); err != nil {
		t.Fatal(err)
	}
	reporter.poll(context.Background())
	if len(sink.changes) != 1 || sink.changes[0].EventID != ev.EventID || sink.changes[0].Outcome != enterprisestatus.ChangeApplied {
		t.Fatalf("changes = %+v", sink.changes)
	}
}

// A change event file whose content is not the content its id hashes
// (edited after its command wrote it: another outcome, account or
// credential under the same name and event_id) is never reported, so no
// sink gets another record under the event's id. Before, the gateway
// reported whatever the file held under its id.
func TestBundleReceiptReporterSkipsAChangeEventEditedAfterItWasWritten(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"another outcome": func(ev map[string]any) { ev["outcome"], ev["reason_code"] = "failed", "change_failed" },
		"another account": func(ev map[string]any) { ev["actor"] = "os:uid:501:alice" },
		"another name":    func(ev map[string]any) { ev["secret_name"] = "otlp-token" },
		"another time":    func(ev map[string]any) { ev["time"] = "2026-10-21T10:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			spool := enterprisestatus.ChangeEventsDir(dir)
			ev := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
				enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
			path := filepath.Join(spool, ev.EventID+".json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			edit(fields)
			if raw, err = json.Marshal(fields); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o640); err != nil {
				t.Fatal(err)
			}
			sink := &fakeBundleReceiptSink{}
			reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
				markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
			reporter.poll(context.Background())
			if len(sink.changes) != 0 {
				t.Fatalf("an edited change event was reported: %+v", sink.changes)
			}
		})
	}
}

// A change or receipt whose reported marker could not be written is not
// offered again, and its marker is written at a later poll once the marker
// folder is repaired, so the change commands can remove the change from the
// spool; the change keeps its delivery state until then. Before, the id was
// cached as reported and this process never wrote its marker, so unreported
// changes piled up until the spool refused new ones.
func TestBundleReceiptReporterRetriesAMarkerItCouldNotWrite(t *testing.T) {
	dir := t.TempDir()
	receipts := enterprisestatus.PublicReceiptPath(dir)
	sink := &fakeBundleReceiptSink{}
	reporter := &bundleReceiptReporter{receiptPath: receipts, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		sink: sink, enforcedVersion: func() uint64 { return 0 },
		pins: audit.NewConfigChangePins(filepath.Join(dir, changeRecordPinsDirName))}
	ev := writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "",
		func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	const receiptID = "r-01JAZ3Y8Q2K7V4N6M5P0R9S8T1"
	writeTestPublicReceipt(t, filepath.Join(filepath.Dir(receipts), enterprisestatus.PublicReceiptEventsDirName, receiptID+".json"),
		enterprisestatus.PublicReceipt{SchemaVersion: 1, ReceiptID: receiptID, BundleID: testBundleID, Version: 3,
			State: enterprisestatus.BundleConfirmed, FinishedAt: "2026-10-23T10:00:00Z",
			CurrentBundleID: testBundleID, CurrentVersion: 3})
	// A file where the marker folder belongs: every marker write fails.
	if err := os.WriteFile(reporter.seenDir(), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	if len(sink.changes) != 1 || len(sink.receipts) != 1 {
		t.Fatalf("offers with the marker folder broken: %d changes, %d receipts; want one each", len(sink.changes), len(sink.receipts))
	}
	if enterprisestatus.ChangeReported(dir, ev.EventID) || reporter.reportedOnDisk(receiptID) {
		t.Fatal("a marker is on disk although its folder is broken")
	}
	if reporter.changes[ev.EventID] == nil {
		t.Error("the change dropped its delivery state before its marker was on disk")
	}
	if err := os.Remove(reporter.seenDir()); err != nil {
		t.Fatal(err)
	}
	reporter.poll(context.Background())
	if !enterprisestatus.ChangeReported(dir, ev.EventID) || !reporter.reportedOnDisk(receiptID) {
		t.Fatal("markers not written after the marker folder was repaired")
	}
	if reporter.changes[ev.EventID] != nil {
		t.Fatal("the change kept its delivery state after its marker was written")
	}
	reporter.poll(context.Background())
	if len(sink.changes) != 1 || len(sink.receipts) != 1 {
		t.Fatalf("offers after the repair: %d changes, %d receipts; want still one each", len(sink.changes), len(sink.receipts))
	}
}

// Only the first offer of a change that entered the spool while the
// reporter ran is a first offer (audit.ConfigChange.FirstOffer): a change
// that was in the spool at the reporter's first poll may have been offered
// by an earlier gateway process, and an offer after a refused one is never
// a first offer. The audit logger lets a change without a record pin go to
// the remote destinations while the store cannot answer only on its first
// offer.
func TestBundleReceiptReporterSaysWhichOfferOfAChangeIsItsFirst(t *testing.T) {
	dir := t.TempDir()
	spool := enterprisestatus.ChangeEventsDir(dir)
	sink := &fakeBundleReceiptSink{}
	reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
		markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
	before := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	reporter.poll(context.Background())
	later := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "otlp-token" })
	sink.changeErr = errors.New("audit store unavailable")
	reporter.poll(context.Background())
	sink.changeErr = nil
	reporter.poll(context.Background())
	type offer struct {
		id    string
		first bool
	}
	var got []offer
	for _, change := range sink.offers {
		got = append(got, offer{change.EventID, change.FirstOffer})
	}
	want := []offer{{before.EventID, false}, {later.EventID, true}, {later.EventID, false}}
	if len(got) != len(want) {
		t.Fatalf("offers = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("offers = %+v, want %+v", got, want)
		}
	}
	// A reporter that could not read the spool at its first poll takes no
	// change as a first offer until it has read it. On Windows a path under
	// a file reads as one that does not exist, which holds no change either.
	if runtime.GOOS == "windows" {
		return
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ids, read := changeSpoolIDs(filepath.Join(file, enterprisestatus.ChangeEventsDirName)); read || ids != nil {
		t.Fatalf("spool under a file: ids %v, read %t; want it unread", ids, read)
	}
}
