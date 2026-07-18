// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestUpgradeReceiptPendingNeverFabricatesSuccess(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("pending")
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pending receipt was removed: %v", err)
	}
	recorded, err := fixture.store.UpgradeReceiptEventRecorded(receipt.ReceiptID)
	if err != nil || recorded {
		t.Fatalf("pending receipt recorded=%t error=%v", recorded, err)
	}
}

func TestUpgradeReceiptTerminalStatesUseMandatoryCanonicalCompliance(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	tests := []struct {
		name        string
		status      string
		failureCode string
		wantOutcome string
	}{
		{name: "succeeded", status: "succeeded", wantOutcome: string(observability.OutcomeApplied)},
		{name: "partial", status: "partial", wantOutcome: string(observability.OutcomePartial)},
		{name: "failed-health", status: "failed", failureCode: "health_check_failed", wantOutcome: string(observability.OutcomeFailed)},
		{name: "rolled-back-detected", status: "rolled_back", failureCode: "rollback_detected", wantOutcome: string(observability.OutcomeRevoked)},
		{name: "rolled-back-install", status: "rolled_back", failureCode: "install_failed", wantOutcome: string(observability.OutcomeRevoked)},
		{name: "rolled-back-health", status: "rolled_back", failureCode: "health_check_failed", wantOutcome: string(observability.OutcomeRevoked)},
		{name: "rolled-back-interrupted", status: "rolled_back", failureCode: "interrupted", wantOutcome: string(observability.OutcomeRevoked)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := validUpgradeReceipt(test.status)
			receipt.FailureCode = test.failureCode
			if test.status == "partial" {
				receipt.MigrationStatus = "degraded"
			}
			path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
			if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("terminal receipt was not acknowledged: %v", err)
			}
			assertUpgradeReceiptRecord(t, fixture.store.DatabasePath(), receipt.ReceiptID, test.wantOutcome)
		})
	}
}

func TestUpgradeReceiptConsumerDefersWhileHardCutRecoveryJournalIsActive(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("rolled_back")
	receipt.FailureCode = "interrupted"
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	recoveryDirectory := filepath.Join(fixture.dataDir, upgradeRecoveryDirectory)
	if err := os.MkdirAll(recoveryDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(recoveryDirectory, hardCutRecoveryJournal)
	if err := os.WriteFile(journal, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active recovery journal did not preserve terminal receipt: %v", err)
	}
	recorded, err := fixture.store.UpgradeReceiptEventRecorded(receipt.ReceiptID)
	if err != nil || recorded {
		t.Fatalf("active recovery journal recorded=%t error=%v", recorded, err)
	}

	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed recovery journal did not acknowledge receipt: %v", err)
	}
	assertUpgradeReceiptRecord(
		t,
		fixture.store.DatabasePath(),
		receipt.ReceiptID,
		string(observability.OutcomeRevoked),
	)
}

func TestUpgradeReceiptCrashAfterPersistenceRetriesIdempotently(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("succeeded")
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	crash := errors.New("simulated crash after canonical persistence")
	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, func() error { return crash }); !errors.Is(err, crash) {
		t.Fatalf("first consume error=%v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("crash seam removed receipt: %v", err)
	}
	assertUpgradeReceiptRecord(t, fixture.store.DatabasePath(), receipt.ReceiptID, string(observability.OutcomeApplied))

	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatalf("retry consume: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry did not acknowledge receipt: %v", err)
	}
	database, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, receipt.ReceiptID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("canonical receipt rows=%d, want exactly one", count)
	}
}

func TestUpgradeReceiptRejectsUnknownOrUnboundedContent(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("succeeded")
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["raw_config"] = "api_key=must-not-cross-boundary"
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err == nil {
		t.Fatal("receipt with unknown content was accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("invalid receipt was removed: %v", err)
	}
}

func TestUpgradeReceiptReadinessUsesMandatorySQLiteNotExternalExporters(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	fixture.sidecar.health.SetTelemetry(
		StateError,
		"external exporter unavailable",
		map[string]interface{}{"local_sqlite": "healthy"},
	)
	if !fixture.sidecar.upgradeReceiptStartupReady() {
		t.Fatal("external exporter failure blocked mandatory SQLite receipt readiness")
	}

	store := fixture.sidecar.store
	fixture.sidecar.store = nil
	if fixture.sidecar.upgradeReceiptStartupReady() {
		t.Fatal("receipt readiness ignored unavailable mandatory SQLite")
	}
	fixture.sidecar.store = store
}

func upgradeReceiptFixture(t *testing.T) sidecarV8BootstrapFixture {
	t.Helper()
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.health.SetConfig(StateRunning, "", nil)
	fixture.sidecar.health.SetAPI(StateRunning, "", nil)
	if !fixture.sidecar.upgradeReceiptStartupReady() {
		t.Fatal("fixture did not reach upgrade-receipt startup readiness")
	}
	return fixture
}

func validUpgradeReceipt(status string) upgradeReceipt {
	created := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	completed := created.Add(time.Minute)
	receipt := upgradeReceipt{
		SchemaVersion: 1, ReceiptID: uuid.NewString(), CreatedAt: created,
		FromVersion: "7.9.0", TargetVersion: "8.0.0", Status: status,
		MigrationStatus: "completed", ArtifactsVerified: true,
	}
	count := int64(3)
	receipt.MigrationCount = &count
	if status != "pending" {
		receipt.CompletedAt = &completed
	} else {
		receipt.MigrationStatus = "pending"
		receipt.MigrationCount = nil
	}
	return receipt
}

func writeUpgradeReceipt(t *testing.T, dataDir string, receipt upgradeReceipt) string {
	t.Helper()
	directory := filepath.Join(dataDir, upgradeReceiptDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, receipt.ReceiptID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertUpgradeReceiptRecord(t *testing.T, databasePath, receiptID, wantOutcome string) {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var bucket, eventName, source, projected string
	var mandatory int
	if err := database.QueryRow(`SELECT bucket, event_name, source, mandatory, projected_record_json
		FROM audit_events WHERE id=?`, receiptID).Scan(
		&bucket, &eventName, &source, &mandatory, &projected,
	); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(projected), &record); err != nil {
		t.Fatal(err)
	}
	if bucket != "compliance.activity" || eventName != "legacy.audit.upgrade" ||
		source != "cli" || mandatory != 1 || record["outcome"] != wantOutcome {
		t.Fatalf("canonical receipt=%q/%q/%q/%d outcome=%v", bucket, eventName, source, mandatory, record["outcome"])
	}
}
