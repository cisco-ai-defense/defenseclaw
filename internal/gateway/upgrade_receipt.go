// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	upgradeReceiptDirectory  = ".upgrade-receipts"
	upgradeRecoveryDirectory = ".upgrade-recovery"
	hardCutRecoveryJournal   = "phase-two-active.json"
	upgradeReceiptMaxBytes   = 16 * 1024
	upgradeReceiptMaxFiles   = 64
	upgradeReceiptPoll       = 500 * time.Millisecond
)

var upgradeReceiptSemver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

type upgradeReceipt struct {
	SchemaVersion     int        `json:"schema_version"`
	ReceiptID         string     `json:"receipt_id"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	FromVersion       string     `json:"from_version"`
	TargetVersion     string     `json:"target_version"`
	Status            string     `json:"status"`
	MigrationStatus   string     `json:"migration_status"`
	MigrationCount    *int64     `json:"migration_count"`
	ArtifactsVerified bool       `json:"artifacts_verified"`
	FailureCode       string     `json:"failure_code"`
}

func (s *Sidecar) runUpgradeReceiptConsumer(ctx context.Context) {
	if s == nil || ctx == nil {
		return
	}
	ticker := time.NewTicker(upgradeReceiptPoll)
	defer ticker.Stop()
	reportedFailure := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.upgradeReceiptStartupReady() {
				continue
			}
			err := s.consumeUpgradeReceipts(ctx, nil)
			if err != nil && !reportedFailure {
				fmt.Fprintln(os.Stderr, "[sidecar] upgrade compliance receipt consumption deferred")
				reportedFailure = true
			} else if err == nil {
				reportedFailure = false
			}
		}
	}
}

func (s *Sidecar) upgradeReceiptStartupReady() bool {
	if s == nil || s.health == nil || s.logger == nil || s.store == nil || s.observabilityV8Emitter() == nil {
		return false
	}
	snapshot := s.health.Snapshot()
	return snapshot.API.State == StateRunning && snapshot.Config.State == StateRunning &&
		snapshot.Telemetry.State == StateRunning
}

// consumeUpgradeReceipts processes every bounded terminal receipt. afterPersist
// is a test-only crash seam: production passes nil. A retry first checks the
// canonical row identity, so a crash after persistence but before unlink does
// not emit a second occurrence.
func (s *Sidecar) consumeUpgradeReceipts(ctx context.Context, afterPersist func() error) error {
	if s == nil || ctx == nil || s.currentConfig() == nil || s.logger == nil || s.store == nil {
		return errors.New("upgrade receipt runtime unavailable")
	}
	dataDir := s.currentConfig().DataDir
	recoveryActive, err := hardCutRecoveryJournalActive(dataDir)
	if err != nil {
		return err
	}
	if recoveryActive {
		// A phase-two journal is authoritative until exact target health or an
		// exact healthy rollback has been proven and the controller durably
		// unlinks it. Pending receipts must remain untouched during that window;
		// terminal receipts are also deferred as defense in depth against stale
		// or manually recovered journal states.
		return nil
	}
	directory := filepath.Join(dataDir, upgradeReceiptDirectory)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("upgrade receipt directory unavailable")
	}
	var firstErr error
	seen := 0
	for _, entry := range entries {
		if seen >= upgradeReceiptMaxFiles {
			break
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		seen++
		path := filepath.Join(directory, entry.Name())
		if err := s.consumeUpgradeReceipt(ctx, path, afterPersist); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func hardCutRecoveryJournalActive(dataDir string) (bool, error) {
	journal := filepath.Join(dataDir, upgradeRecoveryDirectory, hardCutRecoveryJournal)
	_, err := os.Lstat(journal)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, errors.New("upgrade recovery journal state unavailable")
}

func (s *Sidecar) consumeUpgradeReceipt(ctx context.Context, path string, afterPersist func() error) error {
	receipt, terminal, err := readUpgradeReceipt(path)
	if err != nil || !terminal {
		return err
	}
	recorded, err := s.store.UpgradeReceiptEventRecorded(receipt.ReceiptID)
	if err != nil {
		return errors.New("upgrade receipt idempotency check failed")
	}
	if !recorded {
		input := audit.UpgradeReceiptInput{
			ReceiptID: receipt.ReceiptID, CompletedAt: receipt.CompletedAt.UTC(),
			FromVersion: receipt.FromVersion, TargetVersion: receipt.TargetVersion,
			Status: receipt.Status, MigrationStatus: receipt.MigrationStatus,
			MigrationCount: receipt.MigrationCount, ArtifactsVerified: receipt.ArtifactsVerified,
			FailureCode: receipt.FailureCode,
		}
		if err := s.logger.LogUpgradeReceipt(ctx, input); err != nil {
			return errors.New("upgrade receipt canonical persistence failed")
		}
		if afterPersist != nil {
			if err := afterPersist(); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("upgrade receipt acknowledgement failed")
	}
	return nil
}

func readUpgradeReceipt(path string) (upgradeReceipt, bool, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > upgradeReceiptMaxBytes {
		return upgradeReceipt{}, false, errors.New("invalid upgrade receipt file")
	}
	file, err := os.Open(path)
	if err != nil {
		return upgradeReceipt{}, false, errors.New("upgrade receipt unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return upgradeReceipt{}, false, errors.New("upgrade receipt changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, upgradeReceiptMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > upgradeReceiptMaxBytes || !utf8.Valid(raw) ||
		!cliObservabilityV8JSONHasUniqueKeys(raw) {
		return upgradeReceipt{}, false, errors.New("invalid upgrade receipt encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt upgradeReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return upgradeReceipt{}, false, errors.New("invalid upgrade receipt")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return upgradeReceipt{}, false, errors.New("invalid upgrade receipt trailing data")
	}
	terminal, err := validateUpgradeReceipt(receipt, filepath.Base(path))
	return receipt, terminal, err
}

func validateUpgradeReceipt(receipt upgradeReceipt, filename string) (bool, error) {
	parsed, err := uuid.Parse(receipt.ReceiptID)
	if receipt.SchemaVersion != 1 || err != nil || parsed.String() != receipt.ReceiptID ||
		filename != receipt.ReceiptID+".json" || receipt.CreatedAt.IsZero() ||
		len(receipt.FromVersion) > 32 || len(receipt.TargetVersion) > 32 ||
		!upgradeReceiptSemver.MatchString(receipt.FromVersion) ||
		!upgradeReceiptSemver.MatchString(receipt.TargetVersion) {
		return false, errors.New("invalid upgrade receipt identity")
	}
	if receipt.MigrationStatus != "pending" && receipt.MigrationStatus != "completed" &&
		receipt.MigrationStatus != "degraded" {
		return false, errors.New("invalid upgrade receipt migration state")
	}
	if receipt.MigrationCount != nil && (*receipt.MigrationCount < 0 || *receipt.MigrationCount > 10_000) {
		return false, errors.New("invalid upgrade receipt migration count")
	}
	if !validGatewayUpgradeFailureCode(receipt.FailureCode) {
		return false, errors.New("invalid upgrade receipt failure code")
	}
	switch receipt.Status {
	case "pending":
		if receipt.CompletedAt != nil || receipt.FailureCode != "" {
			return false, errors.New("invalid pending upgrade receipt")
		}
		return false, nil
	case "succeeded":
		if receipt.CompletedAt == nil || receipt.CompletedAt.IsZero() || receipt.FailureCode != "" ||
			receipt.CompletedAt.Before(receipt.CreatedAt) || receipt.MigrationStatus == "degraded" {
			return false, errors.New("invalid successful upgrade receipt")
		}
	case "partial":
		if receipt.CompletedAt == nil || receipt.CompletedAt.IsZero() ||
			receipt.CompletedAt.Before(receipt.CreatedAt) || receipt.FailureCode != "" {
			return false, errors.New("invalid partial upgrade receipt")
		}
	case "failed":
		if receipt.CompletedAt == nil || receipt.CompletedAt.IsZero() ||
			receipt.CompletedAt.Before(receipt.CreatedAt) || receipt.FailureCode == "" {
			return false, errors.New("invalid failed upgrade receipt")
		}
	case "rolled_back":
		if receipt.CompletedAt == nil || receipt.CompletedAt.IsZero() ||
			receipt.CompletedAt.Before(receipt.CreatedAt) || receipt.FailureCode == "" {
			return false, errors.New("invalid rollback upgrade receipt")
		}
	default:
		return false, errors.New("invalid upgrade receipt status")
	}
	return true, nil
}

func validGatewayUpgradeFailureCode(value string) bool {
	switch value {
	case "", "install_failed", "migration_failed", "required_migration_failed",
		"local_observability_failed", "startup_failed", "health_check_failed",
		"interrupted", "rollback_detected":
		return true
	default:
		return false
	}
}
