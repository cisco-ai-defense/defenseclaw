// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// setTestProcess sets the run id, sidecar id and binary version a gateway
// process stamps, and restores them after the test.
func setTestProcess(t *testing.T, run, sidecar, binary string) {
	t.Helper()
	previousRun, previousSidecar := gatewaylog.ProcessRunID(), ProcessAgentInstanceID()
	previousBinary := version.Current().BinaryVersion
	t.Cleanup(func() {
		gatewaylog.SetProcessRunID(previousRun)
		SetProcessAgentInstanceID(previousSidecar)
		version.SetBinaryVersion(previousBinary)
	})
	gatewaylog.SetProcessRunID(run)
	SetProcessAgentInstanceID(sidecar)
	version.SetBinaryVersion(binary)
}

// openTestStore opens the audit store at path, as a gateway start does.
func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testAnchorChange() ConfigChange {
	return ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", ChangedAt: "2026-10-20T08:30:00.123Z",
		SHA256: strings.Repeat("a", 64), PreviousSHA256: strings.Repeat("b", 64),
		KeyIDsAdded: []string{"fleet-2026-11"}, KeyIDsRemoved: []string{"fleet-2026-10"}}
}

func recordBytes(t *testing.T, record observability.Record) []byte {
	t.Helper()
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// builtRecords is every record emitter's builder returned.
func builtRecords(emitter *testRuntimeV8Emitter) []observability.Record {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	return append([]observability.Record(nil), emitter.built...)
}

// Every sink of a change gets the same record under its id: the record is
// built from the change event and its pin, which the first offer writes
// and flushes before any sink gets the record. Here the first offer goes
// to the destinations while the store refuses the write; then a restart
// (another run id, sidecar id and binary, and another config generation
// and digest) stores the row; a reload (another config), a power loss that
// took the row back, and a lost pin file follow. Every record built, the
// one a destination got first included, is byte for byte the first, and
// the row holds it. Before, every offer stamped the run, sidecar, binary
// and config of the process that made it, so the destination acknowledged
// one record and the store kept, or a later offer sent, another one under
// the same id.
func TestLogConfigChangeEveryOfferIsTheSameRecord(t *testing.T) {
	change := testAnchorChange()
	recordID := stableOccurrenceID("config.change", change.EventID)
	at, err := time.Parse(time.RFC3339Nano, change.ChangedAt)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	pins := testConfigChangePins(t)
	var sent []observability.Record
	offer := func(store *Store, emitter *testRuntimeV8Emitter, wantErr bool) {
		t.Helper()
		logger := NewLogger(store)
		logger.SetRuntimeV8Emitter(emitter)
		before := len(builtRecords(emitter))
		err := logger.LogConfigChange(change, nil, pins)
		if (err != nil) != wantErr {
			t.Fatalf("LogConfigChange error = %v, want an error %t", err, wantErr)
		}
		built := builtRecords(emitter)
		if len(built) != before+1 {
			t.Fatalf("the offer built %d records, want 1", len(built)-before)
		}
		sent = append(sent, built[before])
	}

	setTestProcess(t, "run-before-restart", "sidecar-before-restart", "1.0.4-dev.1")
	first := openTestStore(t, path)
	refusing := newTestRuntimeV8Emitter(t, first, router.AdmissionOrdinary)
	refusing.failWrite = errors.New("database or disk is full")
	offer(first, refusing, true)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	setTestProcess(t, "run-after-restart", "sidecar-after-restart", "1.0.4-dev.2")
	store := openTestStore(t, path)
	restarted := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
	restarted.generation, restarted.digest = 24, strings.Repeat("b", 64)
	offer(store, restarted, false)
	reloaded := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
	reloaded.generation, reloaded.digest = 25, strings.Repeat("c", 64)
	offer(store, reloaded, false)
	if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id = ?`, recordID); err != nil {
		t.Fatal(err)
	}
	offer(store, reloaded, false)
	pinPath := filepath.Join(pins.dir, change.EventID+".json")
	pinned, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	offer(store, reloaded, false)
	if again, err := os.ReadFile(pinPath); err != nil || !bytes.Equal(again, pinned) {
		t.Fatalf("the pin made from the stored row is %s (%v), want the first pin %s", again, err, pinned)
	}

	want := recordBytes(t, sent[0])
	for index, record := range sent {
		if got := recordBytes(t, record); !bytes.Equal(got, want) {
			t.Fatalf("offer %d built another record under %s:\n got %s\nwant %s", index, recordID, got, want)
		}
	}
	for _, part := range []string{
		`"record_id":"` + recordID + `"`, `"run_id":"run-before-restart"`,
		`"sidecar_instance_id":"sidecar-before-restart"`, `"binary_version":"1.0.4-dev.1"`,
		`"config_generation":23`, `"config_digest":"` + testEventHistoryGraphDigest + `"`,
		`"defenseclaw.config.change.id":"` + testConfigChangeID + `"`,
		`"defenseclaw.trust_anchors.key_ids.added":["fleet-2026-11"]`,
		`"defenseclaw.admin.actor_ref":"os:uid:0:root"`,
	} {
		if !strings.Contains(string(want), part) {
			t.Fatalf("the record lacks %s: %s", part, want)
		}
	}
	if !sent[0].Timestamp().Equal(at) {
		t.Fatalf("the record has the time %s, want the change's %s", sent[0].Timestamp(), at)
	}
	row, found, err := store.storedChangeRow(t.Context(), recordID)
	if err != nil || !found || !row.holds(sent[0], recordBytes(t, sent[0])) {
		t.Fatalf("the stored row (found %t, %v) does not hold the record: %s", found, err, row.envelope)
	}
	if row.digest != recordSHA256(want) {
		t.Fatalf("the stored row keeps the record digest %q, want the record's %s", row.digest, recordSHA256(want))
	}
	var rows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`, recordID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("%d stored rows (%v), want 1", rows, err)
	}
}

// An offer that cannot be built as the change's pinned record sends
// nothing, to any sink, and is an error, so the change stays in its spool:
// collection now admits another form, the pin was edited or does not read,
// the stored row is another record, or the first pin cannot be written.
// Before, nothing compared an offer with an earlier one.
func TestLogConfigChangeSendsNoOtherRecordUnderItsID(t *testing.T) {
	setTestProcess(t, "run-a", "sidecar-a", "1.0.4-dev.1")
	change := testAnchorChange()
	stored := func(t *testing.T, pins *ConfigChangePins) *Store {
		t.Helper()
		store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
		logger := NewLogger(store)
		logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary))
		if err := logger.LogConfigChange(change, nil, pins); err != nil {
			t.Fatal(err)
		}
		return store
	}
	refused := func(t *testing.T, store *Store, admission router.Admission, pins *ConfigChangePins) {
		t.Helper()
		emitter := newTestRuntimeV8Emitter(t, store, admission)
		emitter.generation, emitter.digest = 30, strings.Repeat("d", 64)
		logger := NewLogger(store)
		logger.SetRuntimeV8Emitter(emitter)
		err := logger.LogConfigChange(change, nil, pins)
		if err == nil {
			t.Fatal("the offer succeeded")
		}
		t.Logf("refused: %v", err)
		if built := builtRecords(emitter); len(built) != 0 {
			t.Fatalf("the offer built %d records for the sinks, want none", len(built))
		}
	}
	pinFile := func(pins *ConfigChangePins) string { return filepath.Join(pins.dir, change.EventID+".json") }

	t.Run("collection now admits only the floor", func(t *testing.T) {
		pins := testConfigChangePins(t)
		refused(t, stored(t, pins), router.AdmissionFloor, pins)
	})
	t.Run("the pin was edited", func(t *testing.T) {
		pins := testConfigChangePins(t)
		store := stored(t, pins)
		raw, err := os.ReadFile(pinFile(pins))
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(raw), `"run_id":"run-a"`, `"run_id":"run-z"`, 1)
		if edited == string(raw) {
			t.Fatalf("the pin has no run id: %s", raw)
		}
		if err := os.WriteFile(pinFile(pins), []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, store, router.AdmissionOrdinary, pins)
	})
	t.Run("the pin was edited and the row is gone", func(t *testing.T) {
		pins := testConfigChangePins(t)
		store := stored(t, pins)
		if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id = ?`,
			stableOccurrenceID("config.change", change.EventID)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(pinFile(pins))
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(raw), `"binary_version":"1.0.4-dev.1"`, `"binary_version":"1.0.4-dev.9"`, 1)
		if edited == string(raw) {
			t.Fatalf("the pin has no binary version: %s", raw)
		}
		if err := os.WriteFile(pinFile(pins), []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, store, router.AdmissionOrdinary, pins)
	})
	t.Run("the pin does not read", func(t *testing.T) {
		pins := testConfigChangePins(t)
		store := stored(t, pins)
		if err := os.WriteFile(pinFile(pins), []byte(`{"run_id":`), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, store, router.AdmissionOrdinary, pins)
	})
	t.Run("the stored row is another record", func(t *testing.T) {
		store := stored(t, testConfigChangePins(t))
		setTestProcess(t, "run-b", "sidecar-b", "1.0.4-dev.2")
		other := testConfigChangePins(t)
		stored(t, other)
		refused(t, store, router.AdmissionOrdinary, other)
	})
	t.Run("the first pin cannot be written", func(t *testing.T) {
		pins := testConfigChangePins(t)
		pins.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk I/O error") }
		store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
		refused(t, store, router.AdmissionOrdinary, pins)
		var rows int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`,
			stableOccurrenceID("config.change", change.EventID)).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("%d stored rows (%v), want none", rows, err)
		}
	})
	t.Run("no pin store", func(t *testing.T) {
		refused(t, openTestStore(t, filepath.Join(t.TempDir(), "audit.db")), router.AdmissionOrdinary, nil)
	})
}

// The audit store and the remote destinations are separate sinks of a
// change. While the store cannot say whether it holds the change's row
// (its lookup fails), every offer still goes to the destinations, skips
// the local write and records no metric, and fails, so the change stays
// in its spool. Once the store answers, the row is written once, its
// metrics are recorded once, and it is the record the destinations got.
// Before, a failed lookup returned before the record was built: no
// destination got the change, at every poll, until the spool filled.
func TestLogConfigChangeOffersTheDestinationsWhileTheStoreCannotAnswer(t *testing.T) {
	setTestProcess(t, "run-a", "sidecar-a", "1.0.4-dev.1")
	logger := newTestLogger(t)
	emitter := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(emitter)
	change, pins := testAnchorChange(), testConfigChangePins(t)
	// The change entered the spool while the gateway ran, so no earlier
	// offer of it exists.
	change.FirstOffer = true
	if _, err := logger.store.db.Exec(`ALTER TABLE audit_events RENAME TO audit_events_unreadable`); err != nil {
		t.Fatal(err)
	}
	for offer := 0; offer < 2; offer++ {
		if err := logger.LogConfigChange(change, nil, pins); err == nil {
			t.Fatalf("offer %d succeeded while the store could not answer", offer)
		}
	}
	if built := builtRecords(emitter); len(built) != 2 {
		t.Fatalf("the destinations got %d offers while the store could not answer, want 2", len(built))
	}
	emitter.mu.Lock()
	skipped := append([]bool(nil), emitter.skippedLocalWrite...)
	emitter.mu.Unlock()
	if len(skipped) != 2 || !skipped[0] || !skipped[1] {
		t.Fatalf("offers that skipped the local write = %v, want both", skipped)
	}
	if n := len(emitter.metricSnapshot()); n != 0 {
		t.Fatalf("%d metrics recorded for a change the store does not hold", n)
	}
	if _, err := logger.store.db.Exec(`ALTER TABLE audit_events_unreadable RENAME TO audit_events`); err != nil {
		t.Fatal(err)
	}
	if err := logger.LogConfigChange(change, nil, pins); err != nil {
		t.Fatalf("offer after the store recovered: %v", err)
	}
	if n := len(emitter.metricSnapshot()); n == 0 {
		t.Fatal("no metric was recorded with the row")
	}
	built := builtRecords(emitter)
	if len(built) != 3 {
		t.Fatalf("built %d records, want 3", len(built))
	}
	for index := range built {
		if !bytes.Equal(recordBytes(t, built[index]), recordBytes(t, built[0])) {
			t.Fatalf("offer %d is another record", index)
		}
	}
	var rows int
	if err := logger.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`,
		stableOccurrenceID("config.change", change.EventID)).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("%d stored rows (%v), want 1", rows, err)
	}
}

// The first offer of a change writes and flushes its pin before the
// runtime gets the record, so before the store or any destination has it.
func TestLogConfigChangePinsTheRecordBeforeAnySinkGetsIt(t *testing.T) {
	setTestProcess(t, "run-a", "sidecar-a", "1.0.4-dev.1")
	logger := newTestLogger(t)
	emitter := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(emitter)
	pins := testConfigChangePins(t)
	write := pins.writeFile
	writes, sinksAtWrite := 0, -1
	pins.writeFile = func(path string, data []byte, mode os.FileMode) error {
		writes++
		sinksAtWrite = len(builtRecords(emitter))
		var rows int
		if err := logger.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&rows); err != nil || rows != 0 {
			t.Errorf("the store had %d rows (%v) when the pin was written", rows, err)
		}
		return write(path, data, mode)
	}
	for offer := 0; offer < 2; offer++ {
		if err := logger.LogConfigChange(testAnchorChange(), nil, pins); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 || sinksAtWrite != 0 {
		t.Fatalf("pin writes = %d with %d records out, want one write before any record", writes, sinksAtWrite)
	}
}

// A change whose pin file is lost is rebuilt from its stored row only as
// the record that row was written from: the row keeps the digest of that
// record, and an offer whose record has another body (a later binary that
// builds the body of the same event differently, under the same id, run,
// sidecar, binary and config) is refused, as is an offer for a row that
// keeps no digest. A row whose digest is not the pinned record's refuses
// the offer too. No sink gets the record, and no pin is written. Before,
// the row's projection was compared without its body, so another body was
// pinned and sent under the change's id.
func TestLogConfigChangeRebuildsALostPinOnlyAsTheStoredRecord(t *testing.T) {
	recordID := stableOccurrenceID("config.change", testConfigChangeID)
	stored := func(t *testing.T) (*Store, *ConfigChangePins, string) {
		t.Helper()
		setTestProcess(t, "run-a", "sidecar-a", "1.0.4-dev.1")
		store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
		pins := testConfigChangePins(t)
		logger := NewLogger(store)
		emitter := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
		logger.SetRuntimeV8Emitter(emitter)
		if err := logger.LogConfigChange(testAnchorChange(), nil, pins); err != nil {
			t.Fatal(err)
		}
		built := builtRecords(emitter)
		if len(built) != 1 {
			t.Fatalf("built %d records, want 1", len(built))
		}
		row, found, err := store.storedChangeRow(t.Context(), recordID)
		if err != nil || !found || row.digest != recordSHA256(recordBytes(t, built[0])) {
			t.Fatalf("the stored row (found %t, %v) keeps the digest %q, want its record's", found, err, row.digest)
		}
		return store, pins, filepath.Join(pins.dir, testConfigChangeID+".json")
	}
	refused := func(t *testing.T, store *Store, pins *ConfigChangePins, change ConfigChange, pinFile string, pinWanted bool) {
		t.Helper()
		emitter := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
		logger := NewLogger(store)
		logger.SetRuntimeV8Emitter(emitter)
		if err := logger.LogConfigChange(change, nil, pins); err == nil {
			t.Fatal("the offer succeeded")
		} else {
			t.Logf("refused: %v", err)
		}
		if built := builtRecords(emitter); len(built) != 0 {
			t.Fatalf("the offer built %d records for the sinks, want none", len(built))
		}
		if _, err := os.Lstat(pinFile); (err == nil) != pinWanted {
			t.Fatalf("pin file present = %t, want %t", err == nil, pinWanted)
		}
	}
	otherBody := testAnchorChange()
	otherBody.KeyIDsAdded = []string{"fleet-2026-12"}

	t.Run("lost pin, the rebuild has another body", func(t *testing.T) {
		store, pins, pinFile := stored(t)
		if err := os.Remove(pinFile); err != nil {
			t.Fatal(err)
		}
		refused(t, store, pins, otherBody, pinFile, false)
	})
	t.Run("lost pin, the row keeps no digest", func(t *testing.T) {
		store, pins, pinFile := stored(t)
		if _, err := store.db.Exec(`UPDATE audit_events SET record_sha256 = NULL WHERE id = ?`, recordID); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(pinFile); err != nil {
			t.Fatal(err)
		}
		refused(t, store, pins, testAnchorChange(), pinFile, false)
	})
	t.Run("the row keeps another record's digest", func(t *testing.T) {
		store, pins, pinFile := stored(t)
		if _, err := store.db.Exec(`UPDATE audit_events SET record_sha256 = ? WHERE id = ?`,
			strings.Repeat("e", 64), recordID); err != nil {
			t.Fatal(err)
		}
		refused(t, store, pins, testAnchorChange(), pinFile, true)
	})
	t.Run("lost pin, the same record", func(t *testing.T) {
		store, pins, pinFile := stored(t)
		pinned, err := os.ReadFile(pinFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(pinFile); err != nil {
			t.Fatal(err)
		}
		setTestProcess(t, "run-b", "sidecar-b", "1.0.4-dev.2")
		logger := NewLogger(store)
		logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary))
		if err := logger.LogConfigChange(testAnchorChange(), nil, pins); err != nil {
			t.Fatal(err)
		}
		if again, err := os.ReadFile(pinFile); err != nil || !bytes.Equal(again, pinned) {
			t.Fatalf("the pin made from the stored row is %s (%v), want the first pin %s", again, err, pinned)
		}
	})
}

// The record digest column is added to an audit store an earlier release
// created, and adding it again is a no-op.
func TestAuditEventRecordDigestMigrationIsAdditive(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	exists, err := store.hasColumn("audit_events", "record_sha256")
	if err != nil || !exists {
		t.Fatalf("audit_events.record_sha256 exists=%t err=%v", exists, err)
	}
	if err := migrateAuditEventRecordDigest(store.db); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if got := migrations[len(migrations)-1].description; got != configChangeRecordDigestMigrationDescription {
		t.Fatalf("last migration = %q, want the record digest one", got)
	}
}

// A change without a record pin that an earlier gateway process may have
// offered (not its first offer) goes to no sink while the audit store
// cannot say whether it holds the change's row: with the pin file gone,
// the row is what is left of the record that offer sent. Here the first
// offer went to the destinations while the store kept its row, or refused
// it; the pin file is lost; the next gateway (another run, sidecar and
// binary) offers the change while the store cannot answer. No record is
// built and no pin is written. Once the store answers, the stored row
// rebuilds the first record. Before, the offer was taken as a first offer:
// it pinned the new run and sent another record under the change's id.
func TestLogConfigChangeWithoutAPinWaitsForTheStoreToAnswer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rowStored bool
	}{
		{"the store kept the row", true},
		{"the store refused the row", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTestProcess(t, "run-a", "sidecar-a", "1.0.4-dev.1")
			store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
			pins := testConfigChangePins(t)
			first := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
			logger := NewLogger(store)
			logger.SetRuntimeV8Emitter(first)
			if !tc.rowStored {
				if _, err := store.db.Exec(`CREATE TRIGGER test_refuse_change BEFORE INSERT ON audit_events
					BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if err := logger.LogConfigChange(testAnchorChange(), nil, pins); (err == nil) != tc.rowStored {
				t.Fatalf("first offer: %v, want stored %t", err, tc.rowStored)
			}
			sent := builtRecords(first)
			if len(sent) != 1 {
				t.Fatalf("the first offer built %d records, want 1", len(sent))
			}
			if _, err := store.db.Exec(`DROP TRIGGER IF EXISTS test_refuse_change`); err != nil {
				t.Fatal(err)
			}
			pinFile := filepath.Join(pins.dir, testConfigChangeID+".json")
			if err := os.Remove(pinFile); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`ALTER TABLE audit_events RENAME TO audit_events_unreadable`); err != nil {
				t.Fatal(err)
			}
			setTestProcess(t, "run-b", "sidecar-b", "1.0.4-dev.2")
			next := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
			logger = NewLogger(store)
			logger.SetRuntimeV8Emitter(next)
			if err := logger.LogConfigChange(testAnchorChange(), nil, pins); err == nil {
				t.Fatal("an offer without a pin succeeded while the store could not answer")
			} else {
				t.Logf("refused: %v", err)
			}
			if built := builtRecords(next); len(built) != 0 {
				t.Fatalf("the offer built %d records for the sinks while the store could not answer, want none", len(built))
			}
			if _, err := os.Lstat(pinFile); err == nil {
				t.Fatal("the offer pinned a new record while the store could not answer")
			}
			if _, err := store.db.Exec(`ALTER TABLE audit_events_unreadable RENAME TO audit_events`); err != nil {
				t.Fatal(err)
			}
			if !tc.rowStored {
				return
			}
			if err := logger.LogConfigChange(testAnchorChange(), nil, pins); err != nil {
				t.Fatalf("offer once the store answers: %v", err)
			}
			built := builtRecords(next)
			if len(built) != 1 || !bytes.Equal(recordBytes(t, built[0]), recordBytes(t, sent[0])) {
				t.Fatalf("once the store answers the offer built %d records, want the first record", len(built))
			}
		})
	}
}
