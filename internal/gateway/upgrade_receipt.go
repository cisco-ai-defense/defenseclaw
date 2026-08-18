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
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	upgradeReceiptDirectory     = ".upgrade-receipts"
	upgradeRecoveryDirectory    = ".upgrade-recovery"
	hardCutRecoveryJournal      = "phase-two-active.json"
	upgradeReceiptMaxBytes      = 16 * 1024
	upgradeReceiptMaxFiles      = 64
	upgradeReceiptPoll          = 500 * time.Millisecond
	upgradeBundleIntentSuffix   = ".local-bundle-intent"
	upgradeBundleIntentMaxBytes = 1024
	upgradeSupersessionSuffix   = ".superseded-by"
	upgradeSupersessionMaxBytes = 1024
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

type upgradeReceiptSupersession struct {
	SchemaVersion         int    `json:"schema_version"`
	ReceiptID             string `json:"receipt_id"`
	TargetVersion         string `json:"target_version"`
	SupersededByReceiptID string `json:"superseded_by_receipt_id"`
	HealthProven          *bool  `json:"health_proven"`
}

type upgradeBundleRestartIntent struct {
	SchemaVersion   int    `json:"schema_version"`
	ReceiptID       string `json:"receipt_id"`
	TargetVersion   string `json:"target_version"`
	RestartRequired *bool  `json:"restart_required"`
}

type upgradeReceiptSupersessionState struct {
	active        bool
	healthProven  bool
	replacementID string
	path          string
}

type localBundleRestartCustodyState struct {
	active bool
	path   string
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
	// Upgrade receipts have one mandatory destination: canonical local SQLite.
	// External exporters may be failing while that compliance store is fully
	// ready, and must not prevent the receipt from being admitted and
	// acknowledged. The logger/emitter checks above prove the v8 pipeline is
	// bound; Store.Ready proves its migrations, pragmas, durable-write canary,
	// and post-migration path checks completed.
	return snapshot.API.State == StateRunning && snapshot.Config.State == StateRunning && s.store.Ready()
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
	if err := cleanupOrphanedUpgradeReceiptMetadata(directory, entries); err != nil {
		firstErr = err
	}
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

func cleanupOrphanedUpgradeReceiptMetadata(directory string, entries []os.DirEntry) error {
	seen := 0
	removed := false
	var firstErr error
	rememberError := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		suffix := ""
		maximum := int64(0)
		switch {
		case strings.HasSuffix(name, upgradeBundleIntentSuffix):
			suffix, maximum = upgradeBundleIntentSuffix, upgradeBundleIntentMaxBytes
		case strings.HasSuffix(name, upgradeSupersessionSuffix):
			suffix, maximum = upgradeSupersessionSuffix, upgradeSupersessionMaxBytes
		default:
			continue
		}
		seen++
		if seen > upgradeReceiptMaxFiles*2 {
			rememberError(errors.New("upgrade receipt metadata exceeds its bound"))
			break
		}
		path := filepath.Join(directory, name)
		base := strings.TrimSuffix(name, suffix)
		parsed, err := uuid.Parse(base)
		if err != nil || parsed.String() != base {
			rememberError(errors.New("invalid orphaned upgrade receipt metadata identity"))
			if err := os.Remove(path); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					rememberError(errors.New("orphaned upgrade receipt metadata cleanup failed"))
				}
			} else {
				removed = true
			}
			continue
		}
		receiptPath := filepath.Join(directory, base+".json")
		if _, err := os.Lstat(receiptPath); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			rememberError(errors.New("upgrade receipt metadata owner unavailable"))
			continue
		}
		info, lstatErr := os.Lstat(path)
		if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
			rememberError(errors.New("orphaned upgrade receipt metadata lookup failed"))
			continue
		}
		if lstatErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			info.Size() <= 0 || info.Size() > maximum) {
			rememberError(errors.New("invalid orphaned upgrade receipt metadata"))
		}
		if err := os.Remove(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				rememberError(errors.New("orphaned upgrade receipt metadata cleanup failed"))
			}
			continue
		}
		removed = true
	}
	if removed {
		if err := syncUpgradeReceiptDirectory(directory); err != nil {
			rememberError(err)
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
	restartCustody, err := localBundleRestartCustodyActive(path, receipt)
	if err != nil {
		return err
	}
	supersession, err := upgradeReceiptSupersessionActive(
		path,
		receipt,
	)
	if err != nil {
		return err
	}
	if supersession.active && !upgradeReceiptRecoveryAuthority(receipt, restartCustody.active) {
		return errors.New("unexpected upgrade receipt supersession")
	}
	delegationDurable := false
	if supersession.active && !supersession.healthProven {
		delegationDurable, err = upgradeReceiptDelegationReplacementValid(
			path,
			receipt.TargetVersion,
			supersession.replacementID,
		)
		if err != nil {
			return err
		}
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
	if (!supersession.active || (!supersession.healthProven && !delegationDurable)) &&
		(restartCustody.active || upgradeReceiptRecoverableFailure(receipt)) {
		// The target bundle transaction has not yet proven restart/readiness.
		// Persist the compliance event above, but retain its local recovery
		// authority until a verified replacement assumes it or a retry proves health.
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("upgrade receipt acknowledgement failed")
	}
	if supersession.active && (supersession.healthProven || delegationDurable) {
		if err := syncUpgradeReceiptDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Remove(restartCustody.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("upgrade receipt restart metadata cleanup failed")
		}
		if err := os.Remove(supersession.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("upgrade receipt supersession cleanup failed")
		}
		if err := syncUpgradeReceiptDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

func syncUpgradeReceiptDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("upgrade receipt directory unavailable for sync")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("upgrade receipt directory sync failed")
	}
	return nil
}

func upgradeReceiptRecoverableFailure(receipt upgradeReceipt) bool {
	if receipt.Status != "failed" || !receipt.ArtifactsVerified {
		return false
	}
	switch receipt.FailureCode {
	case "migration_failed", "required_migration_failed", "local_observability_failed",
		"startup_failed", "health_check_failed", "interrupted":
		return true
	default:
		return false
	}
}

func upgradeReceiptRecoveryAuthority(receipt upgradeReceipt, restartCustody bool) bool {
	return upgradeReceiptRecoverableFailure(receipt) ||
		((receipt.Status == "succeeded" || receipt.Status == "partial") &&
			receipt.ArtifactsVerified && restartCustody)
}

func upgradeReceiptSupersessionActive(
	receiptPath string,
	receipt upgradeReceipt,
) (upgradeReceiptSupersessionState, error) {
	path := strings.TrimSuffix(receiptPath, ".json") + upgradeSupersessionSuffix
	raw, err := readPrivateBoundedUniqueJSON(path, upgradeSupersessionMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return upgradeReceiptSupersessionState{path: path}, nil
	}
	if err != nil {
		return upgradeReceiptSupersessionState{}, errors.New("invalid upgrade receipt supersession")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var marker upgradeReceiptSupersession
	if err := decoder.Decode(&marker); err != nil {
		return upgradeReceiptSupersessionState{}, errors.New("invalid upgrade receipt supersession")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return upgradeReceiptSupersessionState{}, errors.New("invalid upgrade receipt supersession trailing data")
	}
	replacement, err := uuid.Parse(marker.SupersededByReceiptID)
	if marker.SchemaVersion != 1 || marker.ReceiptID != receipt.ReceiptID ||
		marker.TargetVersion != receipt.TargetVersion || marker.HealthProven == nil || err != nil ||
		replacement.String() != marker.SupersededByReceiptID ||
		marker.SupersededByReceiptID == receipt.ReceiptID {
		return upgradeReceiptSupersessionState{}, errors.New("invalid upgrade receipt supersession identity")
	}
	return upgradeReceiptSupersessionState{
		active:        true,
		healthProven:  *marker.HealthProven,
		replacementID: marker.SupersededByReceiptID,
		path:          path,
	}, nil
}

func upgradeReceiptDelegationReplacementValid(
	receiptPath string,
	targetVersion string,
	replacementID string,
) (bool, error) {
	replacementPath := filepath.Join(filepath.Dir(receiptPath), replacementID+".json")
	replacement, terminal, err := readUpgradeReceipt(replacementPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("upgrade receipt delegation target is invalid")
	}
	if replacement.ReceiptID != replacementID || replacement.TargetVersion != targetVersion ||
		!replacement.ArtifactsVerified {
		return false, errors.New("upgrade receipt delegation target identity is invalid")
	}
	if !terminal {
		// Python promotes every predecessor only after this pending attempt
		// proves target health. Retaining the predecessors until then prevents
		// the gateway consumer from racing that fail-closed promotion scan.
		return false, nil
	}
	restartCustody, err := localBundleRestartCustodyActive(replacementPath, replacement)
	if err != nil {
		return false, err
	}
	return upgradeReceiptRecoveryAuthority(replacement, restartCustody.active), nil
}

func localBundleRestartCustodyActive(
	receiptPath string,
	receipt upgradeReceipt,
) (localBundleRestartCustodyState, error) {
	base := strings.TrimSuffix(filepath.Base(receiptPath), ".json")
	if base == filepath.Base(receiptPath) {
		return localBundleRestartCustodyState{}, errors.New("invalid upgrade receipt path")
	}
	path := filepath.Join(filepath.Dir(receiptPath), base+upgradeBundleIntentSuffix)
	raw, err := readPrivateBoundedUniqueJSON(path, upgradeBundleIntentMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return localBundleRestartCustodyState{path: path}, nil
	}
	if err != nil {
		return localBundleRestartCustodyState{}, errors.New("invalid local bundle restart custody")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var intent upgradeBundleRestartIntent
	if err := decoder.Decode(&intent); err != nil {
		return localBundleRestartCustodyState{}, errors.New("invalid local bundle restart custody")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localBundleRestartCustodyState{}, errors.New("invalid local bundle restart custody trailing data")
	}
	if intent.SchemaVersion != 1 || intent.ReceiptID != receipt.ReceiptID ||
		intent.TargetVersion != receipt.TargetVersion || intent.RestartRequired == nil {
		return localBundleRestartCustodyState{}, errors.New("invalid local bundle restart custody identity")
	}
	return localBundleRestartCustodyState{active: *intent.RestartRequired, path: path}, nil
}

func readUpgradeReceipt(path string) (upgradeReceipt, bool, error) {
	raw, err := readPrivateBoundedUniqueJSON(path, upgradeReceiptMaxBytes)
	if err != nil {
		return upgradeReceipt{}, false, fmt.Errorf("invalid upgrade receipt file: %w", err)
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

func readPrivateBoundedUniqueJSON(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if maximum <= 0 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > maximum ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("invalid private bounded JSON file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("private bounded JSON file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum || !utf8.Valid(raw) ||
		!cliObservabilityV8JSONHasUniqueKeys(raw) {
		return nil, errors.New("invalid private bounded JSON encoding")
	}
	return raw, nil
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
