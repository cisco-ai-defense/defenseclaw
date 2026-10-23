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
	"strings"
	"testing"

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
