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
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// changeExportFixture is a bootstrapped gateway runtime with one OTLP log
// destination that can be told to refuse the change's exports (HTTP 400), the
// gateway's audit database, and one credential change event in a spool.
type changeExportFixture struct {
	capture         *hookModelV8OTLPCapture
	sidecar         *Sidecar
	dataDir         string
	configPath      string
	endpoint        string
	refusing        atomic.Bool
	refused         atomic.Int64
	trackRecipients atomic.Bool
	tenantA         atomic.Int64
	tenantB         atomic.Int64
	// slow delays the destination's answer to the change's exports.
	slow     atomic.Bool
	control  atomic.Pointer[changeExportControl]
	logger   *audit.Logger
	database *sql.DB
	dir      string
	ev       enterprisestatus.ChangeEvent
}

type changeExportControl struct {
	release <-chan struct{}
	started chan<- struct{}
}

func newChangeExportFixture(t *testing.T) *changeExportFixture {
	t.Helper()
	f := &changeExportFixture{capture: &hookModelV8OTLPCapture{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refuse only the change's exports: refusing every record would
		// open the destination's circuit for 30 s.
		control := f.control.Load()
		if (f.refusing.Load() || f.slow.Load() || f.trackRecipients.Load() || control != nil) &&
			r.URL.Path == "/v1/logs" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			if bytes.Contains(body, []byte(f.ev.EventID)) {
				switch r.Header.Get("X-Recipient") {
				case "first recipient":
					f.tenantA.Add(1)
				case "replacement recipient":
					f.tenantB.Add(1)
				}
				if control != nil {
					select {
					case control.started <- struct{}{}:
					default:
					}
					<-control.release
				}
			}
			if f.slow.Load() && bytes.Contains(body, []byte(f.ev.EventID)) {
				time.Sleep(300 * time.Millisecond)
			} else if f.refusing.Load() && bytes.Contains(body, []byte(f.ev.EventID)) {
				f.refused.Add(1)
				http.Error(w, "refused", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		f.capture.handler(w, r)
	}))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	fixture.sidecar.setAPIServer(&APIServer{})
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath,
		hookModelV8BootstrapRaw(fixture.dataDir, server.URL, []string{"logs"})); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	f.logger = fixture.logger
	f.sidecar = fixture.sidecar
	f.dataDir = fixture.dataDir
	f.configPath = fixture.configPath
	f.endpoint = server.URL
	database, err := sql.Open("sqlite", filepath.Join(fixture.dataDir, config.DefaultAuditDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	f.database = database
	f.dir = t.TempDir()
	f.ev = writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(f.dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "",
		func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	return f
}

// reporter returns a new reporter on the fixture's spool, as a gateway
// start does: it has no memory of earlier offers.
func (f *changeExportFixture) reporter() *bundleReceiptReporter {
	return &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(f.dir),
		markerPath: filepath.Join(f.dir, bundleReceiptMarkerName), sink: f.logger,
		enforcedVersion: func() uint64 { return 0 }}
}

// exported counts the change's records the destination accepted.
func (f *changeExportFixture) exported() int {
	count := 0
	for _, record := range hookModelV8CapturedLogs(f.capture.logSnapshot()) {
		if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
			count++
		}
	}
	return count
}

func (f *changeExportFixture) storedRows(t *testing.T) int {
	t.Helper()
	var rows int
	if err := f.database.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
		string(audit.ActionConfigSecretChanged)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// pollUntil polls the reporter until cond holds.
func pollUntil(t *testing.T, reporter *bundleReceiptReporter, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		reporter.poll(t.Context())
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A change event the audit store cannot insert (the disk is full, the
// store still reads) stays in the spool and is offered at every poll. It
// reaches the remote destination only once it is stored, and only once.
// Before, every failed offer exported it again, every 5 seconds while the
// store stayed full.
func TestBundleReceiptReporterExportsAChangeOnlyOnceItIsStored(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`CREATE TRIGGER audit_store_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change the audit store refused was marked reported")
	}
	time.Sleep(500 * time.Millisecond) // the destination exports every 10 ms
	if n := f.exported(); n != 0 {
		t.Fatalf("a change the audit store refused was exported %d times", n)
	}
	if _, err := f.database.Exec(`DROP TRIGGER audit_store_full`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
	for range 3 {
		reporter.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.exported(); n != 1 {
		t.Fatalf("the stored change was exported %d times, want once", n)
	}
}

// A change is marked reported (which lets the change commands remove it
// from the spool) only once the remote destination acknowledged it. While
// the destination refuses it, it stays unmarked and is offered again; a
// gateway restart in between (a new reporter, the delivery state gone and
// the audit row already stored) sends the stored record again instead of
// skipping it. Before, the marker was written as soon as the local row was
// stored, and after a restart the stored row returned before any export, so
// a delivery lost in memory was never made.
func TestBundleReceiptReporterKeepsAChangeUntilTheDestinationHasIt(t *testing.T) {
	f := newChangeExportFixture(t)
	f.refusing.Store(true)
	first := f.reporter()
	pollUntil(t, first, func() bool { return f.refused.Load() >= 1 })
	if first.hasSeen(f.ev.EventID) {
		t.Fatal("a change the destination refused was marked reported")
	}
	if n := f.storedRows(t); n != 1 {
		t.Fatalf("the offers stored %d rows, want 1", n)
	}
	// A restarted gateway follows a stopped one: the first gateway's retry
	// must not still be in flight when the destination starts accepting.
	for settled := false; !settled; time.Sleep(20 * time.Millisecond) {
		settled, _ = first.changes[f.ev.EventID].delivery.Settled()
	}
	restarted := f.reporter()
	restarted.poll(t.Context())
	if restarted.hasSeen(f.ev.EventID) {
		t.Fatal("a restarted gateway marked a stored change the destination never had")
	}
	f.refusing.Store(false)
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	if n := f.exported(); n != 1 {
		t.Fatalf("the destination has the change %d times, want once", n)
	}
	for range 3 {
		restarted.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n, rows := f.exported(), f.storedRows(t); n != 1 || rows != 1 {
		t.Fatalf("after the report: exported %d, stored %d, want 1 and 1", n, rows)
	}
}

// A change is marked reported only once its audit row survives a power
// loss. The store commits with synchronous=NORMAL; LogConfigChange then
// commits once on a synchronous=FULL connection, which flushes the whole
// log. While that flush fails (here the durable write is refused), the
// change stays unmarked, whether its row was just written or found stored.
// Before, the marker was written right after the NORMAL commit.
func TestBundleReceiptReporterMarksAChangeOnlyOnceItsRowIsDurable(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`CREATE TRIGGER audit_flush_fails BEFORE UPDATE ON observability_store_readiness
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change whose row could not be flushed was marked reported")
	}
	if n := f.storedRows(t); n != 1 {
		t.Fatalf("stored %d rows, want 1", n)
	}
	restarted := f.reporter()
	restarted.poll(t.Context())
	if restarted.hasSeen(f.ev.EventID) {
		t.Fatal("a restarted gateway marked a stored change it could not flush")
	}
	if _, err := f.database.Exec(`DROP TRIGGER audit_flush_fails`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
}

// A gateway that stops after the destination acknowledged a change but
// before its next poll marked it reported (a credential change restarts
// the gateway within seconds) must not send it again from the next
// gateway: the acknowledgement is recorded on disk as it arrives
// (GAP-0526). Before, the delivery state was in memory only and the
// restarted gateway exported the change a second time.
func TestBundleReceiptReporterDoesNotExportAnAcknowledgedChangeAgainAfterARestart(t *testing.T) {
	f := newChangeExportFixture(t)
	f.slow.Store(true)
	first := f.reporter()
	first.poll(t.Context())
	deadline := time.Now().Add(20 * time.Second)
	for settled, delivered := false, false; !settled || !delivered; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the destination never acknowledged the change")
		}
		settled, delivered = first.changes[f.ev.EventID].delivery.Settled()
	}
	if first.hasSeen(f.ev.EventID) {
		t.Fatal("the change was marked reported without a second poll")
	}
	restarted := f.reporter()
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	for range 3 {
		restarted.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.exported(); n != 1 {
		t.Fatalf("the destination has the change %d times after a restart, want once", n)
	}
}

// A marker write can fail after a destination acknowledges a change. Its
// acknowledgement must remain durable until the reported marker is durable;
// otherwise a restart sends the same change to that endpoint again.
func TestBundleReceiptReporterKeepsAcknowledgementsUntilReportedMarkerIsDurable(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if err := os.WriteFile(reporter.seenDir(), []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	reporter.poll(t.Context())
	deadline := time.Now().Add(20 * time.Second)
	for {
		state := reporter.changes[f.ev.EventID]
		if state != nil {
			if settled, delivered := state.delivery.Settled(); settled && delivered {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("destination did not acknowledge the change")
		}
		time.Sleep(20 * time.Millisecond)
	}
	reporter.poll(t.Context())
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("change marked reported although its marker could not be written")
	}
	if got := reporter.acknowledgedDestinations(f.ev.EventID); len(got) != 1 {
		t.Fatalf("acknowledgements after failed marker write = %v, want one", got)
	}
	if err := os.Remove(reporter.seenDir()); err != nil {
		t.Fatal(err)
	}
	restarted := f.reporter()
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	if got := f.exported(); got != 1 {
		t.Fatalf("destination received change %d times, want once", got)
	}
}

// A timed-out offer can still be queued or retrying. Its destination must
// receive the change only once, even if the reporter offers the stored row
// again. A replacement identity can receive it before the old one settles.
func TestBundleReceiptReporterDoesNotQueueAnOutstandingChangeAgain(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "same destination"
		if replacement {
			name = "replacement destination"
		}
		t.Run(name, func(t *testing.T) {
			f := newChangeExportFixture(t)
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			started := make(chan struct{}, 2)
			f.control.Store(&changeExportControl{release: release, started: started})
			reporter := f.reporter()
			reporter.poll(t.Context())
			if reporter.changes[f.ev.EventID] == nil {
				t.Fatalf("change not offered: id=%q listed=%v seen=%t", f.ev.EventID,
					enterprisestatus.ListChangeEventIDs(reporter.changeDir()), reporter.hasSeen(f.ev.EventID))
			}
			select {
			case <-started:
			case <-time.After(20 * time.Second):
				settled, delivered := reporter.changes[f.ev.EventID].delivery.Settled()
				t.Fatalf("original destination did not start delivery: settled=%t delivered=%t exports=%d", settled, delivered, f.exported())
			}

			var replacementCapture *hookModelV8OTLPCapture
			if replacement {
				replacementCapture = &hookModelV8OTLPCapture{}
				server := httptest.NewServer(http.HandlerFunc(replacementCapture.handler))
				t.Cleanup(server.Close)
				raw := hookModelV8BootstrapRaw(f.dataDir, server.URL, []string{"logs"})
				result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath, raw)
				if err != nil || result.Status() != runtimegraph.ReloadApplied {
					t.Fatalf("replace destination: status=%v error=%v", result.Status(), err)
				}
			}
			// Force the reporter's ten-minute retry while the first payload
			// is still in the destination queue.
			reporter.changes[f.ev.EventID].offered = time.Now().Add(-bundleChangeDeliveryWait - time.Second)
			reporter.poll(t.Context())
			if replacement {
				pollUntil(t, reporter, func() bool {
					for _, record := range hookModelV8CapturedLogs(replacementCapture.logSnapshot()) {
						if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
							return true
						}
					}
					return false
				})
				if reporter.hasSeen(f.ev.EventID) {
					t.Fatal("change reported before original delivery settled")
				}
			}
			close(release)
			pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
			if got := f.exported(); got != 1 {
				t.Fatalf("original destination received change %d times, want once", got)
			}
			if replacement {
				count := 0
				for _, record := range hookModelV8CapturedLogs(replacementCapture.logSnapshot()) {
					if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("replacement destination received change %d times, want once", count)
				}
			}
		})
	}
}

// Every current endpoint gets one copy of a change. Policy and collection
// reloads, a ten-minute retry and a reporter restart preserve the same key;
// a changed endpoint or resolved credential has another key.
func TestBundleReceiptReporterDeliversEachChangeOncePerCurrentEndpoint(t *testing.T) {
	for _, test := range []struct {
		name               string
		restartReporter    bool
		routeOnly          bool
		collectionOff      bool
		tenMinuteRetry     bool
		credentialRotation bool
	}{
		{name: "endpoint replacement"},
		{name: "endpoint replacement after restart", restartReporter: true},
		{name: "policy reload", routeOnly: true},
		{name: "collection reload", collectionOff: true},
		{name: "ten-minute retry", tenMinuteRetry: true},
		{name: "credential rotation", credentialRotation: true, restartReporter: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newChangeExportFixture(t)
			const credential = "W8_TABLE_DEST_RECIPIENT"
			if test.credentialRotation {
				f.trackRecipients.Store(true)
				t.Setenv(credential, "first recipient")
				raw := hookModelV8BootstrapRaw(f.dataDir, f.endpoint, []string{"logs"})
				raw = bytes.Replace(raw, []byte("      protocol: http/protobuf\n"),
					[]byte("      protocol: http/protobuf\n      headers:\n        X-Recipient: {env: "+credential+"}\n"), 1)
				if result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath, raw); err != nil ||
					result.Status() != runtimegraph.ReloadApplied {
					t.Fatalf("configure recipient: status=%v error=%v", result.Status(), err)
				}
			}
			f.slow.Store(true)
			first := f.reporter()
			first.poll(t.Context())
			deadline := time.Now().Add(20 * time.Second)
			for settled, delivered := false, false; !settled || !delivered; time.Sleep(20 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("endpoint A did not acknowledge the change")
				}
				settled, delivered = first.changes[f.ev.EventID].delivery.Settled()
			}
			if first.hasSeen(f.ev.EventID) || f.exported() != 1 {
				t.Fatalf("before rebind: reported=%t, endpoint A exports=%d", first.hasSeen(f.ev.EventID), f.exported())
			}
			if test.tenMinuteRetry {
				first.changes[f.ev.EventID].offered = time.Now().Add(-bundleChangeDeliveryWait - time.Second)
				pollUntil(t, first, func() bool { return first.hasSeen(f.ev.EventID) })
				if got := f.exported(); got != 1 {
					t.Fatalf("retry delivered change %d times, want once", got)
				}
				return
			}
			if test.restartReporter {
				// A 1.0.4 journal written before this fix has only the name.
				// It cannot prove that the replacement endpoint received it.
				dir := filepath.Join(first.acknowledgedDir(), f.ev.EventID)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, acknowledgedFileName("hook-otlp")), []byte("hook-otlp"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			var secondCapture *hookModelV8OTLPCapture
			endpoint := f.endpoint
			if !test.routeOnly && !test.collectionOff && !test.credentialRotation {
				secondCapture = &hookModelV8OTLPCapture{}
				secondServer := httptest.NewServer(http.HandlerFunc(secondCapture.handler))
				t.Cleanup(secondServer.Close)
				endpoint = secondServer.URL
			}
			raw := hookModelV8BootstrapRaw(f.dataDir, endpoint, []string{"logs"})
			if test.credentialRotation {
				t.Setenv(credential, "replacement recipient")
				raw = bytes.Replace(raw, []byte("      protocol: http/protobuf\n"),
					[]byte("      protocol: http/protobuf\n      headers:\n        X-Recipient: {env: "+credential+"}\n"), 1)
				raw = bytes.Replace(raw, []byte("export_interval_seconds: 1"),
					[]byte("export_interval_seconds: 2"), 1)
			}
			if test.routeOnly {
				changed := bytes.Replace(raw, []byte("        buckets: ['*']\n"),
					[]byte("        buckets: ['*']\n        redaction_profile: strict\n"), 1)
				if bytes.Equal(changed, raw) {
					t.Fatal("test did not change the destination route")
				}
				raw = changed
			}
			if test.collectionOff {
				raw = bytes.Replace(raw, []byte("compliance.activity:\n      collect: {logs: true"),
					[]byte("compliance.activity:\n      collect: {logs: false"), 1)
			}
			result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath,
				raw)
			if err != nil || result.Status() != runtimegraph.ReloadApplied {
				t.Fatalf("rebind destination: status=%v error=%v", result.Status(), err)
			}
			reporter := first
			if test.restartReporter {
				reporter = f.reporter()
			}
			pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
			countB := 0
			if secondCapture != nil {
				for _, record := range hookModelV8CapturedLogs(secondCapture.logSnapshot()) {
					if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
						countB++
					}
				}
			}
			wantA, wantB := 1, 1
			if test.routeOnly || test.collectionOff {
				wantB = 0
			}
			if test.credentialRotation {
				wantA, wantB = 2, 0
			}
			if countB != wantB || f.exported() != wantA {
				t.Fatalf("pending change exports: endpoint A=%d, endpoint B=%d; want %d and %d", f.exported(), countB, wantA, wantB)
			}
			if test.credentialRotation && (f.tenantA.Load() != 1 || f.tenantB.Load() != 1) {
				t.Fatalf("credential rotation delivered old=%d new=%d, want one each", f.tenantA.Load(), f.tenantB.Load())
			}
		})
	}
}

// A referenced authentication value is part of the recipient identity. The
// same configured destination may address another tenant after rotation.
func TestBundleReceiptReporterReoffersAChangeAfterAuthenticationRotation(t *testing.T) {
	f := newChangeExportFixture(t)
	f.trackRecipients.Store(true)
	const name = "W8_DEST_RECIPIENT"
	t.Setenv(name, "first recipient")
	raw := hookModelV8BootstrapRaw(f.dataDir, f.endpoint, []string{"logs"})
	raw = bytes.Replace(raw, []byte("      protocol: http/protobuf\n"),
		[]byte("      protocol: http/protobuf\n      headers:\n        X-Recipient: {env: "+name+"}\n"), 1)
	if result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath, raw); err != nil ||
		result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("configure recipient: status=%v error=%v", result.Status(), err)
	}
	f.slow.Store(true)
	first := f.reporter()
	first.poll(t.Context())
	deadline := time.Now().Add(20 * time.Second)
	for settled, delivered := false, false; !settled || !delivered; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("first recipient did not acknowledge the change")
		}
		settled, delivered = first.changes[f.ev.EventID].delivery.Settled()
	}
	if first.hasSeen(f.ev.EventID) || f.tenantA.Load() != 1 {
		t.Fatalf("before rotation: reported=%t first recipient=%d", first.hasSeen(f.ev.EventID), f.tenantA.Load())
	}
	f.slow.Store(false)
	t.Setenv(name, "replacement recipient")
	// A separate config edit restarts the adapter while leaving this
	// destination's compiled transport and routes unchanged.
	rotated := bytes.Replace(raw, []byte("export_interval_seconds: 1"), []byte("export_interval_seconds: 2"), 1)
	if bytes.Equal(rotated, raw) {
		t.Fatal("test did not change the graph")
	}
	if result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath, rotated); err != nil ||
		result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("rotate recipient: status=%v error=%v", result.Status(), err)
	}
	restarted := f.reporter()
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	if a, b := f.tenantA.Load(), f.tenantB.Load(); a != 1 || b != 1 {
		t.Fatalf("pending change deliveries: first recipient=%d, replacement recipient=%d; want one each", a, b)
	}
}

// A collection edit must not change the form of a row already stored. An
// unchanged recipient needs no replay; a replacement receives that row.
func TestBundleReceiptReporterReconcilesAStoredChangeAfterCollectionReload(t *testing.T) {
	for _, replaceRecipient := range []bool{false, true} {
		name := "unchanged recipient"
		if replaceRecipient {
			name = "replacement recipient"
		}
		t.Run(name, func(t *testing.T) {
			f := newChangeExportFixture(t)
			f.slow.Store(true)
			first := f.reporter()
			first.poll(t.Context())
			deadline := time.Now().Add(20 * time.Second)
			for settled, delivered := false, false; !settled || !delivered; time.Sleep(20 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("original recipient did not acknowledge the change")
				}
				settled, delivered = first.changes[f.ev.EventID].delivery.Settled()
			}
			if first.hasSeen(f.ev.EventID) || f.exported() != 1 {
				t.Fatalf("before reload: reported=%t exports=%d", first.hasSeen(f.ev.EventID), f.exported())
			}
			f.slow.Store(false)
			endpoint := f.endpoint
			var replacement *hookModelV8OTLPCapture
			if replaceRecipient {
				replacement = &hookModelV8OTLPCapture{}
				server := httptest.NewServer(http.HandlerFunc(replacement.handler))
				t.Cleanup(server.Close)
				endpoint = server.URL
			}
			raw := hookModelV8BootstrapRaw(f.dataDir, endpoint, []string{"logs"})
			raw = bytes.Replace(raw, []byte("compliance.activity:\n      collect: {logs: true"),
				[]byte("compliance.activity:\n      collect: {logs: false"), 1)
			if bytes.Contains(raw, []byte("compliance.activity:\n      collect: {logs: true")) {
				t.Fatal("test did not disable collection")
			}
			if result, err := f.sidecar.ReloadObservabilityRuntime(t.Context(), f.configPath, raw); err != nil ||
				result.Status() != runtimegraph.ReloadApplied {
				t.Fatalf("disable collection: status=%v error=%v", result.Status(), err)
			}
			restarted := f.reporter()
			pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
			countB := 0
			if replacement != nil {
				for _, record := range hookModelV8CapturedLogs(replacement.logSnapshot()) {
					if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
						countB++
					}
				}
			}
			wantB := 0
			if replaceRecipient {
				wantB = 1
			}
			if a := f.exported(); a != 1 || countB != wantB {
				t.Fatalf("stored change deliveries: original=%d replacement=%d; want 1 and %d", a, countB, wantB)
			}
		})
	}
}
