// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestUpgradeReceiptConsumerRetainsRecoverableFailureUntilHealthProvenRetry(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("failed")
	receipt.FailureCode = "health_check_failed"
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)

	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("recoverable failure was acknowledged before a retry: %v", err)
	}
	assertUpgradeReceiptRecord(
		t,
		fixture.store.DatabasePath(),
		receipt.ReceiptID,
		string(observability.OutcomeFailed),
	)

	replacementID := uuid.NewString()
	healthProven := false
	marker := upgradeReceiptSupersession{
		SchemaVersion: 1, ReceiptID: receipt.ReceiptID, TargetVersion: receipt.TargetVersion,
		SupersededByReceiptID: replacementID, HealthProven: &healthProven,
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := strings.TrimSuffix(path, ".json") + upgradeSupersessionSuffix
	if err := os.WriteFile(markerPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("delegated failure was acknowledged before retry health: %v", err)
	}
	healthProven = true
	marker.HealthProven = &healthProven
	raw, err = json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded failure was not acknowledged: %v", err)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supersession marker was not cleaned: %v", err)
	}
}

func TestUpgradeReceiptConsumerAcknowledgesDelegationAfterReplacementFailure(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	failed := validUpgradeReceipt("failed")
	failed.FailureCode = "migration_failed"
	failedPath := writeUpgradeReceipt(t, fixture.dataDir, failed)
	replacement := validUpgradeReceipt("pending")
	replacementPath := writeUpgradeReceipt(t, fixture.dataDir, replacement)
	healthProven := false
	marker := upgradeReceiptSupersession{
		SchemaVersion: 1, ReceiptID: failed.ReceiptID, TargetVersion: failed.TargetVersion,
		SupersededByReceiptID: replacement.ReceiptID, HealthProven: &healthProven,
	}
	raw, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := strings.TrimSuffix(failedPath, ".json") + upgradeSupersessionSuffix
	if err := os.WriteFile(markerPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), failedPath, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(failedPath); err != nil {
		t.Fatalf("pending replacement allowed predecessor acknowledgement: %v", err)
	}
	replacement = validUpgradeReceipt("failed")
	replacement.ReceiptID = strings.TrimSuffix(filepath.Base(replacementPath), ".json")
	replacement.FailureCode = "migration_failed"
	writeUpgradeReceipt(t, fixture.dataDir, replacement)
	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), failedPath, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(failedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed replacement did not assume delegated authority: %v", err)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delegation marker was not cleaned: %v", err)
	}
	if _, err := os.Stat(replacementPath); err != nil {
		t.Fatalf("pending replacement authority was removed: %v", err)
	}
}

func TestUpgradeReceiptDelegationsKeepTheBoundedQueueReclaimable(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	replacement := validUpgradeReceipt("failed")
	replacement.FailureCode = "migration_failed"
	replacementPath := writeUpgradeReceipt(t, fixture.dataDir, replacement)
	healthProven := false
	for range upgradeReceiptMaxFiles - 1 {
		failed := validUpgradeReceipt("failed")
		failed.FailureCode = "interrupted"
		failedPath := writeUpgradeReceipt(t, fixture.dataDir, failed)
		marker := upgradeReceiptSupersession{
			SchemaVersion: 1, ReceiptID: failed.ReceiptID, TargetVersion: failed.TargetVersion,
			SupersededByReceiptID: replacement.ReceiptID, HealthProven: &healthProven,
		}
		raw, err := json.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			strings.TrimSuffix(failedPath, ".json")+upgradeSupersessionSuffix,
			raw,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(fixture.dataDir, upgradeReceiptDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != replacementPath {
		t.Fatalf("bounded queue retained obsolete delegations: %v", matches)
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

func TestUpgradeReceiptConsumerRetainsReceiptWhileBundleRestartCustodyExists(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("succeeded")
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	intent := filepath.Join(
		filepath.Dir(path),
		receipt.ReceiptID+upgradeBundleIntentSuffix,
	)
	restartRequired := true
	raw, err := json.Marshal(upgradeBundleRestartIntent{
		SchemaVersion:   1,
		ReceiptID:       receipt.ReceiptID,
		TargetVersion:   receipt.TargetVersion,
		RestartRequired: &restartRequired,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(intent, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("restart custody did not retain receipt: %v", err)
	}
	assertUpgradeReceiptRecord(
		t,
		fixture.store.DatabasePath(),
		receipt.ReceiptID,
		string(observability.OutcomeApplied),
	)

	if err := os.Remove(intent); err != nil {
		t.Fatal(err)
	}
	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt remained after restart custody was released: %v", err)
	}
}

func TestUpgradeReceiptFalseBundleIntentDoesNotClaimRestartCustody(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	receipt := validUpgradeReceipt("succeeded")
	path := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	restartRequired := false
	raw, err := json.Marshal(upgradeBundleRestartIntent{
		SchemaVersion:   1,
		ReceiptID:       receipt.ReceiptID,
		TargetVersion:   receipt.TargetVersion,
		RestartRequired: &restartRequired,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent := strings.TrimSuffix(path, ".json") + upgradeBundleIntentSuffix
	if err := os.WriteFile(intent, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	custody, err := localBundleRestartCustodyActive(path, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if custody.active || custody.path != intent {
		t.Fatalf("restart custody active=%t path=%q, want false and %q", custody.active, custody.path, intent)
	}

	if err := fixture.sidecar.consumeUpgradeReceipt(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("false restart intent retained a terminal success: %v", err)
	}
}

func TestUpgradeReceiptConsumerCleansBoundedOrphanedRecoveryMetadata(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	directory := filepath.Join(fixture.dataDir, upgradeReceiptDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	base := uuid.NewString()
	paths := []string{
		filepath.Join(directory, base+upgradeBundleIntentSuffix),
		filepath.Join(directory, base+upgradeSupersessionSuffix),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphaned recovery metadata was not removed: %s: %v", path, err)
		}
	}
}

func TestUpgradeReceiptConsumerProcessesValidReceiptAfterOrphanCleanupErrors(t *testing.T) {
	fixture := upgradeReceiptFixture(t)
	directory := filepath.Join(fixture.dataDir, upgradeReceiptDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	invalidIdentity := filepath.Join(directory, "!invalid"+upgradeBundleIntentSuffix)
	if err := os.WriteFile(invalidIdentity, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	symlinkBase := "00000000-0000-4000-8000-000000000001"
	symlinkTarget := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(symlinkTarget, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, symlinkBase+upgradeSupersessionSuffix)
	symlinkCreated := true
	if err := os.Symlink(
		symlinkTarget,
		symlinkPath,
	); err != nil {
		symlinkCreated = false
		t.Logf("symlink unavailable; continuing with the other invalid metadata cases: %v", err)
	}

	oversizedBase := "00000000-0000-4000-8000-000000000002"
	oversized := filepath.Join(directory, oversizedBase+upgradeBundleIntentSuffix)
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), upgradeBundleIntentMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	validOrphanBase := "00000000-0000-4000-8000-000000000003"
	validOrphan := filepath.Join(directory, validOrphanBase+upgradeBundleIntentSuffix)
	if err := os.WriteFile(validOrphan, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	receipt := validUpgradeReceipt("succeeded")
	receipt.ReceiptID = "00000000-0000-4000-8000-000000000004"
	receiptPath := writeUpgradeReceipt(t, fixture.dataDir, receipt)
	if err := fixture.sidecar.consumeUpgradeReceipts(t.Context(), nil); err == nil {
		t.Fatal("invalid orphan metadata did not report an error")
	}
	if _, err := os.Stat(validOrphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("valid orphan after invalid entries was not cleaned: %v", err)
	}
	if _, err := os.Stat(invalidIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed orphan metadata was not removed: %v", err)
	}
	if symlinkCreated {
		if _, err := os.Lstat(symlinkPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphaned symlink metadata was not removed: %v", err)
		}
	}
	if _, err := os.Stat(oversized); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned oversized metadata was not removed: %v", err)
	}
	if _, err := os.Stat(receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("valid receipt was not acknowledged after cleanup error: %v", err)
	}
	assertUpgradeReceiptRecord(
		t,
		fixture.store.DatabasePath(),
		receipt.ReceiptID,
		string(observability.OutcomeApplied),
	)
}

func TestUpgradeReceiptOrphanCleanupToleratesStaleDirectoryEntry(t *testing.T) {
	directory := t.TempDir()
	stale := filepath.Join(
		directory,
		"00000000-0000-4000-8000-000000000001"+upgradeBundleIntentSuffix,
	)
	valid := filepath.Join(
		directory,
		"00000000-0000-4000-8000-000000000002"+upgradeBundleIntentSuffix,
	)
	for _, path := range []string{stale, valid} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stale); err != nil {
		t.Fatal(err)
	}
	if err := cleanupOrphanedUpgradeReceiptMetadata(directory, entries); err != nil {
		t.Fatalf("stale metadata entry should be a benign concurrent removal: %v", err)
	}
	if _, err := os.Stat(valid); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("valid orphan after stale entry was not cleaned: %v", err)
	}
}

func TestUpgradeReceiptPrivateBoundedReaderRejectsDuplicateKeys(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name    string
		maximum int64
		raw     string
	}{
		{
			name:    "receipt",
			maximum: upgradeReceiptMaxBytes,
			raw:     `{"schema_version":1,"schema_version":1}`,
		},
		{
			name:    "restart-intent",
			maximum: upgradeBundleIntentMaxBytes,
			raw:     `{"restart_required":true,"restart_required":false}`,
		},
		{
			name:    "supersession",
			maximum: upgradeSupersessionMaxBytes,
			raw:     `{"health_proven":false,"health_proven":true}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name+".json")
			if err := os.WriteFile(path, []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readPrivateBoundedUniqueJSON(path, test.maximum); err == nil {
				t.Fatal("duplicate JSON member was accepted")
			}
		})
	}
}

func TestReadUpgradeReceiptPreservesMissingFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), uuid.NewString()+".json")
	if _, _, err := readUpgradeReceipt(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing receipt error=%v, want os.ErrNotExist identity", err)
	}
}

func TestUpgradeReceiptDelegationDistinguishesMissingAndInvalidTarget(t *testing.T) {
	directory := t.TempDir()
	receiptPath := filepath.Join(directory, uuid.NewString()+".json")
	replacementID := uuid.NewString()
	valid, err := upgradeReceiptDelegationReplacementValid(receiptPath, "8.0.0", replacementID)
	if err != nil || valid {
		t.Fatalf("missing delegation target valid=%t error=%v, want false and nil", valid, err)
	}

	replacementPath := filepath.Join(directory, replacementID+".json")
	if err := os.WriteFile(replacementPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid, err = upgradeReceiptDelegationReplacementValid(receiptPath, "8.0.0", replacementID)
	if err == nil || valid || err.Error() != "upgrade receipt delegation target is invalid" {
		t.Fatalf("invalid delegation target valid=%t error=%v", valid, err)
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
