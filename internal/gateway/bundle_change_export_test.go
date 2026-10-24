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
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// changeExportFixture is a bootstrapped gateway runtime with one OTLP log
// destination that can be told to refuse the change's exports (HTTP 400), the
// gateway's audit database, and one credential change event in a spool.
type changeExportFixture struct {
	capture  *hookModelV8OTLPCapture
	refusing atomic.Bool
	refused  atomic.Int64
	logger   *audit.Logger
	database *sql.DB
	dir      string
	ev       enterprisestatus.ChangeEvent
	// gateway and raw are the gateway and its observability config, for a
	// reload.
	gateway sidecarV8BootstrapFixture
	raw     []byte
}

func newChangeExportFixture(t *testing.T) *changeExportFixture {
	t.Helper()
	f := &changeExportFixture{capture: &hookModelV8OTLPCapture{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refuse only the change's exports: refusing every record would
		// open the destination's circuit for 30 s.
		if f.refusing.Load() && r.URL.Path == "/v1/logs" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			if bytes.Contains(body, []byte(f.ev.EventID)) {
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
	f.gateway, f.raw = fixture, hookModelV8BootstrapRaw(fixture.dataDir, server.URL, []string{"logs"})
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, f.raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	f.logger = fixture.logger
	database, err := sql.Open("sqlite", filepath.Join(fixture.dataDir, config.DefaultAuditDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	f.database = database
	f.dir = t.TempDir()
	// The change was made an hour before the gateway reports it (it was
	// stopped): its record keeps the change's time.
	f.ev = writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(f.dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "",
		func(ev *enterprisestatus.ChangeEvent) {
			ev.SecretName = "splunk-hec-token"
			ev.Time = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		})
	return f
}

// reporter returns a new reporter on the fixture's spool, as a gateway
// start does: it has no memory of earlier offers.
func (f *changeExportFixture) reporter() *bundleReceiptReporter {
	return &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(f.dir),
		markerPath: filepath.Join(f.dir, bundleReceiptMarkerName), sink: f.logger,
		enforcedVersion: func() uint64 { return 0 },
		pins:            audit.NewConfigChangePins(f.pinDir())}
}

// pinDir holds the record pins of the fixture's gateway.
func (f *changeExportFixture) pinDir() string { return filepath.Join(f.dir, changeRecordPinsDirName) }

// pinned reports whether the change has a record pin.
func (f *changeExportFixture) pinned() bool {
	_, err := os.Lstat(filepath.Join(f.pinDir(), f.ev.EventID+".json"))
	return err == nil
}

// exported counts the change's records the destination accepted.
func (f *changeExportFixture) exported() int { return len(f.exportedRecords()) }

// exportedRecords are the change's records the destination accepted.
func (f *changeExportFixture) exportedRecords() []*logspb.LogRecord {
	var out []*logspb.LogRecord
	for _, record := range hookModelV8CapturedLogs(f.capture.logSnapshot()) {
		if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
			out = append(out, record)
		}
	}
	return out
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

// The change spool is the durable record of a change (its command flushed
// the event before it made the change), and the reporter its one sender:
// the audit store and the remote destination are separate sinks of it.
// While the audit store cannot insert (the disk is full, the store still
// reads), the destination still gets the change, once however often it is
// offered, with the change's id and time, and the change stays unmarked;
// once the store takes it, it is marked reported, stored once and not sent
// again. Before, a change reached a destination only after its audit row
// was written and flushed, so the remote sink waited on the local store,
// and its record had the time of that write.
func TestBundleReceiptReporterSendsAChangeToEachSinkOnItsOwn(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`CREATE TRIGGER audit_store_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return f.exported() > 0 })
	for range 3 {
		reporter.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond) // the destination exports every 10 ms
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change the audit store refused was marked reported")
	}
	if n, rows := f.exported(), f.storedRows(t); n != 1 || rows != 0 {
		t.Fatalf("while the store refused: exported %d, stored %d; want 1 and 0", n, rows)
	}
	at, err := time.Parse(time.RFC3339Nano, f.ev.Time)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(0, int64(f.exportedRecords()[0].GetTimeUnixNano())); got.Sub(at).Abs() > time.Millisecond {
		t.Fatalf("the exported record has the time %s, want the change's %s", got, at)
	}
	if _, err := f.database.Exec(`DROP TRIGGER audit_store_full`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
	for range 3 {
		reporter.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n, rows := f.exported(), f.storedRows(t); n != 1 || rows != 1 {
		t.Fatalf("after the report: exported %d, stored %d; want 1 and 1", n, rows)
	}
	if f.pinned() {
		t.Fatal("the record pin of a reported change was kept")
	}
}

// One change is one record under its id at every sink, however the
// gateway changes between offers. The destination refuses the first offer
// (the store keeps the row); then the gateway restarts as another process
// (another run id, sidecar id and binary) and its observability config is
// reloaded (another generation and digest). The destination then gets the
// record the store holds: the run, sidecar, binary and config of the first
// offer, from the change's record pin. A pin a stopped gateway left for a
// reported change is removed at the next start. Before, the later offer
// was rebuilt with the new process and config, so the destination had
// another record than the row under the same id.
func TestBundleReceiptReporterSendsOneRecordUnderAChangeID(t *testing.T) {
	setProcess := func(run, sidecar, binary string) {
		gatewaylog.SetProcessRunID(run)
		audit.SetProcessAgentInstanceID(sidecar)
		version.SetBinaryVersion(binary)
	}
	previousRun, previousSidecar := gatewaylog.ProcessRunID(), audit.ProcessAgentInstanceID()
	previousBinary := version.Current().BinaryVersion
	t.Cleanup(func() { setProcess(previousRun, previousSidecar, previousBinary) })
	f := newChangeExportFixture(t)
	setProcess("run-first-offer", "sidecar-first-offer", "1.0.4-dev.1")
	f.refusing.Store(true)
	first := f.reporter()
	pollUntil(t, first, func() bool { return f.refused.Load() >= 1 && f.storedRows(t) == 1 })

	setProcess("run-after-restart", "sidecar-after-restart", "1.0.4-dev.2")
	reload, err := f.gateway.sidecar.ReloadObservabilityRuntime(t.Context(), f.gateway.configPath,
		bytes.Replace(f.raw, []byte("export_interval_seconds: 1"), []byte("export_interval_seconds: 2"), 1))
	if err != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%v error=%v", reload.Status(), err)
	}
	f.refusing.Store(false)
	restarted := f.reporter()
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	records := f.exportedRecords()
	if len(records) != 1 {
		t.Fatalf("the destination has the change %d times, want once", len(records))
	}
	exported, err := protojson.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := f.database.QueryRow(`SELECT projected_record_json FROM audit_events WHERE action = ?`,
		string(audit.ActionConfigSecretChanged)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var row struct {
		Correlation struct {
			RunID   string `json:"run_id"`
			Sidecar string `json:"sidecar_instance_id"`
		} `json:"correlation"`
		Provenance struct {
			Binary     string `json:"binary_version"`
			Generation int64  `json:"config_generation"`
			Digest     string `json:"config_digest"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal([]byte(stored), &row); err != nil {
		t.Fatal(err)
	}
	if row.Correlation.RunID != "run-first-offer" || row.Correlation.Sidecar != "sidecar-first-offer" ||
		row.Provenance.Binary != "1.0.4-dev.1" || row.Provenance.Digest == "" {
		t.Fatalf("the stored row is not the first offer's record: %s", stored)
	}
	for _, value := range []string{row.Correlation.RunID, row.Correlation.Sidecar, row.Provenance.Binary, row.Provenance.Digest} {
		if !strings.Contains(string(exported), value) {
			t.Fatalf("the exported record lacks the stored %q: %s", value, exported)
		}
	}
	for _, value := range []string{"run-after-restart", "sidecar-after-restart", "1.0.4-dev.2"} {
		if strings.Contains(string(exported), value) {
			t.Fatalf("the exported record has the restarted gateway's %q: %s", value, exported)
		}
	}
	if f.pinned() {
		t.Fatal("the record pin of a reported change was kept")
	}

	// A pin left by a gateway that stopped between marking a change and
	// removing its pin goes at the next start.
	if err := os.WriteFile(filepath.Join(f.pinDir(), f.ev.EventID+".json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f.reporter().run(ctx)
	if f.pinned() {
		t.Fatal("a start kept the record pin of a reported change")
	}
}

// While the audit store cannot say whether it holds a change (its lookup
// fails), the healthy destination still gets the change, once however
// often it is offered, and the change stays unmarked; once the store
// answers, the row is written once and the change is marked reported, not
// sent again. Before, the failed lookup returned before the change was
// built, so no destination got it at any poll.
func TestBundleReceiptReporterSendsAChangeWhileTheStoreCannotAnswer(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`ALTER TABLE audit_events RENAME TO audit_events_unreadable`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return f.exported() > 0 })
	for range 3 {
		reporter.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change the audit store could not answer for was marked reported")
	}
	if n := f.exported(); n != 1 {
		t.Fatalf("while the store could not answer: exported %d, want 1", n)
	}
	if _, err := f.database.Exec(`ALTER TABLE audit_events_unreadable RENAME TO audit_events`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
	time.Sleep(300 * time.Millisecond)
	if n, rows := f.exported(), f.storedRows(t); n != 1 || rows != 1 {
		t.Fatalf("after the report: exported %d, stored %d; want 1 and 1", n, rows)
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
