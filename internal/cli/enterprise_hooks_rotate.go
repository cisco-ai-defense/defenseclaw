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

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	enterpriseHookRotationJournalVersion         = 1
	enterpriseHookRotationJournalFile            = "rotation-transaction.json"
	enterpriseHookRotationLockFile               = "rotation-transaction.lock"
	enterpriseHookRotationRollbackDir            = "rotation-rollback"
	enterpriseHookRotationPhasePreparing         = "preparing"
	enterpriseHookRotationPhasePrepared          = "prepared"
	enterpriseHookRotationPhaseCommitted         = "committed"
	enterpriseHookRotationPhaseRolledBack        = "rolled_back"
	enterpriseHookRotationJournalMaxBytes  int64 = 1 << 20
	enterpriseHookRotationSnapshotMaxBytes int64 = 64 << 10
)

var (
	enterpriseHookRotationLoadB            = loadEnterpriseHookScopedToken
	enterpriseHookRotationPublishB         = connector.PublishHookAPIToken
	enterpriseHookRotationReadPublished    = connector.LoadHookAPIToken
	enterpriseHookRotationPreflightExtra   = func(enterpriseHookRotationRequest) error { return nil }
	enterpriseHookRotationAfterTargetWrite = func(enterpriseHookRotationTarget) error { return nil }
	enterpriseHookRotationSpaceCheck       = checkEnterpriseHookRotationSpace
)

type enterpriseHookRotationRequest struct {
	OperationID  string
	Generation   string
	Manifest     string
	Fingerprints string
}

type enterpriseHookRotationFingerprintFile struct {
	Targets []enterpriseHookRotationTarget `json:"targets"`
}

type enterpriseHookRotationTarget struct {
	User             string `json:"user,omitempty"`
	UserHome         string `json:"user_home,omitempty"`
	SID              string `json:"sid,omitempty"`
	Connector        string `json:"connector"`
	TokenFingerprint string `json:"token_fingerprint"`
	DataDir          string `json:"data_dir,omitempty"`
}

type enterpriseHookRotationJournal struct {
	Version        int                            `json:"version"`
	OperationID    string                         `json:"operation_id"`
	Generation     string                         `json:"generation"`
	Manifest       string                         `json:"manifest"`
	ManifestSHA256 string                         `json:"manifest_sha256"`
	Phase          string                         `json:"phase"`
	Targets        []enterpriseHookRotationTarget `json:"targets"`
	UpdatedAt      string                         `json:"updated_at"`
}

type enterpriseHookRotationSnapshot struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    uint32 `json:"mode,omitempty"`
	UID     int    `json:"uid,omitempty"`
	GID     int    `json:"gid,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Bytes   []byte `json:"-"`
}

type enterpriseHookRotationTargetSnapshot struct {
	Target    enterpriseHookRotationTarget     `json:"target"`
	Artifacts []enterpriseHookRotationSnapshot `json:"artifacts"`
}

var enterpriseHooksRotatePrepareCmd = &cobra.Command{
	Use:   "rotate-prepare",
	Short: "Prepare generation B in every enabled Linux/macOS guardian target",
	Long: `Snapshot generation A and write generation B into the exact enabled
manifest roster. Public output contains only identities, the operation and
generation IDs, and canonical non-secret fingerprints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksRotatePrepareRunE(cmd, args)
	},
}

var enterpriseHooksRotateCommitCmd = &cobra.Command{
	Use:   "rotate-commit",
	Short: "Commit a prepared Linux/macOS guardian rotation",
	Long: `Retire protected rollback material after the coordinator has proved
every selected target authenticated with generation B.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksRotateCommitRunE(cmd, args)
	},
}

var enterpriseHooksRotateRollbackCmd = &cobra.Command{
	Use:   "rotate-rollback",
	Short: "Restore generation A for a Linux/macOS guardian rotation",
	Long: `Idempotently restore exact A bytes, absence, owner, and mode for every
already-mutated target. Readiness stays false unless restoration can be proved.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksRotateRollbackRunE(cmd, args)
	},
}

func runEnterpriseHooksRotatePrepare(cmd *cobra.Command, _ []string) error {
	report, err := executeEnterpriseHookRotationPrepare(enterpriseHookRotationRequest{
		OperationID:  enterpriseHookRotateOperationID,
		Generation:   enterpriseHookRotateGeneration,
		Manifest:     enterpriseHookManifest,
		Fingerprints: enterpriseHookRotateFingerprints,
	})
	return emitEnterpriseHookRotationResult(cmd, "prepare", report, err)
}

func runEnterpriseHooksRotateCommit(cmd *cobra.Command, _ []string) error {
	report, err := executeEnterpriseHookRotationCommit(enterpriseHookRotationRequest{
		OperationID: enterpriseHookRotateOperationID,
		Generation:  enterpriseHookRotateGeneration,
		Manifest:    enterpriseHookManifest,
	})
	return emitEnterpriseHookRotationResult(cmd, "commit", report, err)
}

func runEnterpriseHooksRotateRollback(cmd *cobra.Command, _ []string) error {
	report, err := executeEnterpriseHookRotationRollback(enterpriseHookRotationRequest{
		OperationID: enterpriseHookRotateOperationID,
		Generation:  enterpriseHookRotateGeneration,
		Manifest:    enterpriseHookManifest,
	})
	return emitEnterpriseHookRotationResult(cmd, "rollback", report, err)
}

func emitEnterpriseHookRotationResult(cmd *cobra.Command, action string, report enterpriseHookRotationJournal, err error) error {
	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":           err == nil,
			"action":       action,
			"operation_id": report.OperationID,
			"generation":   report.Generation,
			"phase":        report.Phase,
			"targets":      len(report.Targets),
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		return err
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s enterprise hook rotation %s (%d targets, generation bound)\n",
		Style("✓", "fg=green", "bold"), action, len(report.Targets))
	return nil
}

func executeEnterpriseHookRotationPrepare(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if err := enterpriseHookRotationPlatformSupported(); err != nil {
		return empty, err
	}
	if cfg == nil {
		return empty, fmt.Errorf("enterprise hooks rotate prepare: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	plan, err := preflightEnterpriseHookRotation(req, true)
	if err != nil {
		return empty, err
	}
	if err := enterpriseHookRotationPreflightExtra(req); err != nil {
		return empty, err
	}
	return withEnterpriseHookRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadEnterpriseHookRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if exists {
			if err := enterpriseHookRotationJournalConflicts(journal, plan.Journal); err != nil {
				return journal, err
			}
			switch journal.Phase {
			case enterpriseHookRotationPhasePrepared, enterpriseHookRotationPhaseCommitted:
				if err := verifyEnterpriseHookRotationCurrentB(plan); err != nil {
					return journal, err
				}
				return journal, nil
			case enterpriseHookRotationPhaseRolledBack:
				return journal, fmt.Errorf("enterprise hooks rotate prepare: operation already rolled back")
			}
		}
		if err := writeEnterpriseHookRotationJournal(cfg.DataDir, plan.Journal); err != nil {
			return empty, err
		}
		mutated := 0
		for i, target := range plan.Targets {
			if err := snapshotEnterpriseHookRotationTarget(cfg.DataDir, target); err != nil {
				_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets[:mutated])
				return plan.Journal, fmt.Errorf("enterprise hooks rotate prepare: snapshot %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
			if err := publishEnterpriseHookRotationTargetB(target, plan.Tokens[target.Connector]); err != nil {
				_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets[:i+1])
				return plan.Journal, fmt.Errorf("enterprise hooks rotate prepare: write B for %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
			mutated = i + 1
			if err := enterpriseHookRotationAfterTargetWrite(target); err != nil {
				_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets[:mutated])
				return plan.Journal, fmt.Errorf("enterprise hooks rotate prepare: post-write %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
		}
		if err := verifyEnterpriseHookRotationCurrentB(plan); err != nil {
			_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal, err
		}
		if err := publishEnterpriseHookRotationCurrent(plan); err != nil {
			_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal, err
		}
		plan.Journal.Phase = enterpriseHookRotationPhasePrepared
		plan.Journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeEnterpriseHookRotationJournal(cfg.DataDir, plan.Journal); err != nil {
			_ = restoreEnterpriseHookRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal, err
		}
		return plan.Journal, nil
	})
}

func executeEnterpriseHookRotationCommit(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if err := enterpriseHookRotationPlatformSupported(); err != nil {
		return empty, err
	}
	if cfg == nil {
		return empty, fmt.Errorf("enterprise hooks rotate commit: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	plan, err := preflightEnterpriseHookRotation(req, false)
	if err != nil {
		return empty, err
	}
	return withEnterpriseHookRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadEnterpriseHookRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if !exists {
			return empty, fmt.Errorf("enterprise hooks rotate commit: no prepared rotation exists")
		}
		if err := enterpriseHookRotationJournalConflicts(journal, plan.Journal); err != nil {
			return journal, err
		}
		if journal.Phase == enterpriseHookRotationPhaseCommitted {
			return journal, nil
		}
		if journal.Phase != enterpriseHookRotationPhasePrepared {
			return journal, fmt.Errorf("enterprise hooks rotate commit: phase %s is not prepared", journal.Phase)
		}
		if err := verifyEnterpriseHookRotationCurrentB(plan); err != nil {
			return journal, err
		}
		if err := removeEnterpriseHookRotationRollbackDir(cfg.DataDir); err != nil {
			return journal, fmt.Errorf("enterprise hooks rotate commit: retire rollback material: %w", err)
		}
		journal.Phase = enterpriseHookRotationPhaseCommitted
		journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeEnterpriseHookRotationJournal(cfg.DataDir, journal); err != nil {
			return journal, err
		}
		return journal, nil
	})
}

func executeEnterpriseHookRotationRollback(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if err := enterpriseHookRotationPlatformSupported(); err != nil {
		return empty, err
	}
	if cfg == nil {
		return empty, fmt.Errorf("enterprise hooks rotate rollback: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	if err := validateEnterpriseHookRotationIdentity(req.OperationID, req.Generation); err != nil {
		return empty, err
	}
	return withEnterpriseHookRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadEnterpriseHookRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if exists {
			want := enterpriseHookRotationJournal{
				OperationID: strings.TrimSpace(req.OperationID),
				Generation:  strings.TrimSpace(req.Generation),
				Manifest:    strings.TrimSpace(req.Manifest),
			}
			if err := enterpriseHookRotationJournalConflicts(journal, want); err != nil {
				return journal, err
			}
			if journal.Phase == enterpriseHookRotationPhaseRolledBack || journal.Phase == enterpriseHookRotationPhaseCommitted {
				return journal, nil
			}
		}
		targets := []enterpriseHookRotationTarget{}
		if exists {
			targets = journal.Targets
		}
		if err := restoreEnterpriseHookRotationMutated(cfg.DataDir, targets); err != nil {
			if exists {
				journal.Phase = enterpriseHookRotationPhasePreparing
				_ = writeEnterpriseHookRotationJournal(cfg.DataDir, journal)
			}
			return journal, fmt.Errorf("enterprise hooks rotate rollback: exact A restoration could not be proved: %w", err)
		}
		if exists {
			journal.Phase = enterpriseHookRotationPhaseRolledBack
			journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := writeEnterpriseHookRotationJournal(cfg.DataDir, journal); err != nil {
				return journal, err
			}
			if err := publishEnterpriseHookRotationRestoredCurrent(cfg.DataDir, journal, targets); err != nil {
				return journal, err
			}
			return journal, nil
		}
		if err := markEnterpriseHookRotationUnready(cfg.DataDir); err != nil {
			return journal, err
		}
		return empty, nil
	})
}

type enterpriseHookRotationPlan struct {
	Journal enterpriseHookRotationJournal
	Targets []enterpriseHookRotationTarget
	Tokens  map[string]string
}

func preflightEnterpriseHookRotation(req enterpriseHookRotationRequest, requireFingerprints bool) (enterpriseHookRotationPlan, error) {
	var plan enterpriseHookRotationPlan
	if err := validateEnterpriseHookRotationIdentity(req.OperationID, req.Generation); err != nil {
		return plan, err
	}
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return plan, fmt.Errorf("enterprise hooks rotate: managed enterprise deployment is required")
	}
	manifestPath := strings.TrimSpace(req.Manifest)
	if err := enterpriseHookManifestFileTrustCheck(manifestPath); err != nil {
		return plan, fmt.Errorf("enterprise hooks rotate: manifest trust check failed: %w", err)
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		return plan, err
	}
	authorization, exists, err := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	if err != nil {
		return plan, err
	}
	if !exists || authorization.Version != enterpriseHookGuardianAuthorizationVersionV2 || authorization.Current == nil {
		return plan, fmt.Errorf("enterprise hooks rotate: guardian authorization lacks current per-target attestations")
	}
	enabled := enabledEnterpriseHookRotationTargets(manifest)
	if len(enabled) == 0 {
		return plan, fmt.Errorf("enterprise hooks rotate: manifest has no enabled targets")
	}
	expected := enabled
	if requireFingerprints {
		expected, err = loadEnterpriseHookRotationFingerprints(req.Fingerprints)
		if err != nil {
			return plan, err
		}
		if err := compareEnterpriseHookRotationRosters(enabled, expected); err != nil {
			return plan, err
		}
	} else {
		journal, journalExists, journalErr := loadEnterpriseHookRotationJournal(cfg.DataDir)
		if journalErr != nil {
			return plan, journalErr
		}
		if journalExists {
			expected = journal.Targets
		}
	}
	if err := enterpriseHookRotationSpaceCheck(cfg.DataDir); err != nil {
		return plan, err
	}
	tokens := map[string]string{}
	for _, target := range expected {
		if !connector.ConnectorSupportedOnHostOS(target.Connector) {
			return plan, fmt.Errorf("enterprise hooks rotate: connector %s is not supported on this host", target.Connector)
		}
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if home == "" || !filepath.IsAbs(home) {
			return plan, fmt.Errorf("enterprise hooks rotate: target %s is missing a canonical home", enterpriseHookRotationTargetLabel(target))
		}
		if err := refuseEnterpriseHookRotationSymlink(home, "target home"); err != nil {
			return plan, err
		}
		userDataDir := enterpriseHookRotationUserDataDir(target)
		if err := refuseEnterpriseHookRotationSymlink(userDataDir, "target data dir"); err != nil {
			return plan, err
		}
		token, err := enterpriseHookRotationLoadB(cfg.DataDir, target.Connector)
		if err != nil {
			return plan, fmt.Errorf("enterprise hooks rotate: load generation B for %s: %w", target.Connector, err)
		}
		fingerprint := managed.ScopedTokenFingerprint(token)
		if requireFingerprints && fingerprint != target.TokenFingerprint {
			return plan, fmt.Errorf("enterprise hooks rotate: service token fingerprint does not match expected B for %s", target.Connector)
		}
		tokens[target.Connector] = token
	}
	plan.Targets = expected
	plan.Tokens = tokens
	plan.Journal = enterpriseHookRotationJournal{
		Version:        enterpriseHookRotationJournalVersion,
		OperationID:    strings.TrimSpace(req.OperationID),
		Generation:     strings.TrimSpace(req.Generation),
		Manifest:       manifestPath,
		ManifestSHA256: manifestSHA256,
		Phase:          enterpriseHookRotationPhasePreparing,
		Targets:        expected,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	return plan, nil
}

func enabledEnterpriseHookRotationTargets(manifest enterprisehooks.Manifest) []enterpriseHookRotationTarget {
	targets := make([]enterpriseHookRotationTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		targets = append(targets, enterpriseHookRotationTarget{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.ToLower(strings.TrimSpace(target.Connector)),
			DataDir:   strings.TrimSpace(target.DataDir),
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		return enterpriseHookRotationTargetKey(targets[i]) < enterpriseHookRotationTargetKey(targets[j])
	})
	return targets
}

func loadEnterpriseHookRotationFingerprints(path string) ([]enterpriseHookRotationTarget, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("enterprise hooks rotate: --expected-fingerprints is required")
	}
	if err := refuseEnterpriseHookRotationSymlink(path, "expected fingerprints"); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks rotate: inspect expected fingerprints: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > enterpriseHookRotationJournalMaxBytes {
		return nil, fmt.Errorf("enterprise hooks rotate: expected fingerprints file is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks rotate: read expected fingerprints: %w", err)
	}
	var file enterpriseHookRotationFingerprintFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("enterprise hooks rotate: parse expected fingerprints: %w", err)
	}
	if len(file.Targets) == 0 {
		return nil, fmt.Errorf("enterprise hooks rotate: expected fingerprints omit targets")
	}
	seen := map[string]struct{}{}
	for i, target := range file.Targets {
		file.Targets[i].Connector = strings.ToLower(strings.TrimSpace(target.Connector))
		file.Targets[i].User = strings.TrimSpace(target.User)
		file.Targets[i].UserHome = strings.TrimSpace(target.UserHome)
		file.Targets[i].SID = strings.TrimSpace(target.SID)
		file.Targets[i].TokenFingerprint = strings.TrimSpace(target.TokenFingerprint)
		key := enterpriseHookRotationTargetKey(file.Targets[i])
		if key == "" || !managed.ValidScopedTokenFingerprint(file.Targets[i].TokenFingerprint) {
			return nil, fmt.Errorf("enterprise hooks rotate: expected fingerprints contain an incomplete target")
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("enterprise hooks rotate: expected fingerprints contain a duplicate target")
		}
		seen[key] = struct{}{}
	}
	sort.Slice(file.Targets, func(i, j int) bool {
		return enterpriseHookRotationTargetKey(file.Targets[i]) < enterpriseHookRotationTargetKey(file.Targets[j])
	})
	return file.Targets, nil
}

func compareEnterpriseHookRotationRosters(enabled, expected []enterpriseHookRotationTarget) error {
	if len(enabled) != len(expected) {
		return fmt.Errorf("enterprise hooks rotate: expected fingerprints do not match the enabled manifest roster")
	}
	for i := range enabled {
		if enterpriseHookRotationTargetKey(enabled[i]) != enterpriseHookRotationTargetKey(expected[i]) {
			return fmt.Errorf("enterprise hooks rotate: expected fingerprints do not match the enabled manifest roster")
		}
	}
	return nil
}

func publishEnterpriseHookRotationTargetB(target enterpriseHookRotationTarget, token string) error {
	dataDir := enterpriseHookRotationUserDataDir(target)
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		return err
	}
	return enterpriseHookRotationPublishB(dataDir, target.Connector, token)
}

func verifyEnterpriseHookRotationCurrentB(plan enterpriseHookRotationPlan) error {
	for _, target := range plan.Targets {
		dataDir := enterpriseHookRotationUserDataDir(target)
		token, err := enterpriseHookRotationReadPublished(dataDir, target.Connector)
		if err != nil {
			return fmt.Errorf("enterprise hooks rotate: re-read B for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		if managed.ScopedTokenFingerprint(token) != target.TokenFingerprint {
			return fmt.Errorf("enterprise hooks rotate: persisted B fingerprint mismatch for %s", enterpriseHookRotationTargetLabel(target))
		}
	}
	return nil
}

func publishEnterpriseHookRotationCurrent(plan enterpriseHookRotationPlan) error {
	rows := make([]enterpriseHookReconcileRow, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		rows = append(rows, enterpriseHookReconcileRow{
			User:             target.User,
			UserHome:         target.UserHome,
			SID:              target.SID,
			Connector:        target.Connector,
			OK:               true,
			TokenFingerprint: target.TokenFingerprint,
		})
	}
	return writeEnterpriseHookGuardianStateIdentified(
		cfg.DataDir,
		plan.Journal.Manifest,
		plan.Journal.ManifestSHA256,
		plan.Journal.Generation,
		rows,
		0,
		true,
	)
}

func publishEnterpriseHookRotationRestoredCurrent(dataDir string, journal enterpriseHookRotationJournal, targets []enterpriseHookRotationTarget) error {
	rows, err := restoredEnterpriseHookRotationAttestationRows(dataDir, targets)
	if err != nil {
		return err
	}
	return writeEnterpriseHookGuardianStateIdentified(
		dataDir,
		journal.Manifest,
		journal.ManifestSHA256,
		"",
		rows,
		0,
		true,
	)
}

func restoredEnterpriseHookRotationAttestationRows(dataDir string, targets []enterpriseHookRotationTarget) ([]enterpriseHookReconcileRow, error) {
	rows := make([]enterpriseHookReconcileRow, 0, len(targets))
	for _, target := range targets {
		snapshot, err := decodeEnterpriseHookRotationSnapshotSidecar(enterpriseHookRotationTargetSnapshotPath(dataDir, target))
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks rotate rollback: load A snapshot for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		if !snapshot.Present {
			return nil, fmt.Errorf("enterprise hooks rotate rollback: restored A snapshot missing for %s", enterpriseHookRotationTargetLabel(target))
		}
		token, err := enterpriseHookRotationReadPublished(enterpriseHookRotationUserDataDir(target), target.Connector)
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks rotate rollback: re-read A for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		fingerprint := managed.ScopedTokenFingerprint(token)
		if !managed.ValidScopedTokenFingerprint(fingerprint) {
			return nil, fmt.Errorf("enterprise hooks rotate rollback: restored A fingerprint missing for %s", enterpriseHookRotationTargetLabel(target))
		}
		rows = append(rows, enterpriseHookReconcileRow{
			User:             target.User,
			UserHome:         target.UserHome,
			SID:              target.SID,
			Connector:        target.Connector,
			OK:               true,
			TokenFingerprint: fingerprint,
		})
	}
	return rows, nil
}

func markEnterpriseHookRotationUnready(dataDir string) error {
	authorization, exists, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil || !exists || authorization.Current == nil {
		return err
	}
	authorization.Current.OK = false
	authorization.OK = false
	activation, exists, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil {
		return err
	}
	manifest := ""
	if exists {
		manifest = strings.TrimSpace(activation.Manifest)
	}
	if manifest == "" {
		return fmt.Errorf("enterprise hooks rotate: cannot mark unready without the current manifest path")
	}
	return writeEnterpriseHookGuardianStateIdentified(
		dataDir,
		manifest,
		authorization.Current.ManifestSHA256,
		authorization.Current.ReconcileID,
		authorization.ProtectedTargets,
		0,
		false,
	)
}

func snapshotEnterpriseHookRotationTarget(dataDir string, target enterpriseHookRotationTarget) error {
	userDataDir := enterpriseHookRotationUserDataDir(target)
	tokenPath, err := connector.HookAPITokenFilePath(userDataDir, target.Connector)
	if err != nil {
		return err
	}
	snapshot, err := captureEnterpriseHookRotationArtifact(tokenPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(enterpriseHookRotationRollbackPath(dataDir), 0o700); err != nil {
		return err
	}
	return encodeEnterpriseHookRotationSnapshotSidecar(
		enterpriseHookRotationTargetSnapshotPath(dataDir, target),
		target,
		snapshot,
	)
}

func restoreEnterpriseHookRotationMutated(dataDir string, targets []enterpriseHookRotationTarget) error {
	var errs []error
	for _, target := range targets {
		if err := restoreEnterpriseHookRotationTarget(dataDir, target); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func restoreEnterpriseHookRotationTarget(dataDir string, target enterpriseHookRotationTarget) error {
	path := enterpriseHookRotationTargetSnapshotPath(dataDir, target)
	snapshot, err := decodeEnterpriseHookRotationSnapshotSidecar(path)
	if err != nil {
		return err
	}
	return restoreEnterpriseHookRotationArtifact(snapshot)
}

func enterpriseHookRotationUserDataDir(target enterpriseHookRotationTarget) string {
	if strings.TrimSpace(target.DataDir) != "" {
		return filepath.Clean(target.DataDir)
	}
	return filepath.Join(filepath.Clean(target.UserHome), ".defenseclaw")
}

func enterpriseHookRotationTargetKey(target enterpriseHookRotationTarget) string {
	return enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{
		User:      target.User,
		UserHome:  target.UserHome,
		SID:       target.SID,
		Connector: target.Connector,
	})
}

func enterpriseHookRotationTargetLabel(target enterpriseHookRotationTarget) string {
	return enterpriseHookTargetLabel(enterpriseHookReconcileRow{
		User:      target.User,
		UserHome:  target.UserHome,
		SID:       target.SID,
		Connector: target.Connector,
	})
}

func validateEnterpriseHookRotationIdentity(operationID, generation string) error {
	if !validEnterpriseHookHex(strings.TrimSpace(operationID), 16) {
		return fmt.Errorf("enterprise hooks rotate: --operation-id must be 32 lowercase hex characters")
	}
	if !validEnterpriseHookHex(strings.TrimSpace(generation), 16) {
		return fmt.Errorf("enterprise hooks rotate: --generation must be 32 lowercase hex characters")
	}
	return nil
}

func enterpriseHookRotationJournalConflicts(actual, want enterpriseHookRotationJournal) error {
	if actual.OperationID != "" && want.OperationID != "" && actual.OperationID != want.OperationID {
		return fmt.Errorf("enterprise hooks rotate: conflicting operation ID")
	}
	if actual.Generation != "" && want.Generation != "" && actual.Generation != want.Generation {
		return fmt.Errorf("enterprise hooks rotate: conflicting generation")
	}
	if actual.Manifest != "" && want.Manifest != "" && !sameEnterpriseHookPath(actual.Manifest, want.Manifest) {
		return fmt.Errorf("enterprise hooks rotate: conflicting target set")
	}
	if len(actual.Targets) > 0 && len(want.Targets) > 0 {
		if err := compareEnterpriseHookRotationRosters(actual.Targets, want.Targets); err != nil {
			return fmt.Errorf("enterprise hooks rotate: conflicting target set")
		}
	}
	return nil
}

func enterpriseHookRotationBusy(dataDir string) error {
	journal, exists, err := loadEnterpriseHookRotationJournal(dataDir)
	if err != nil {
		return err
	}
	if exists && (journal.Phase == enterpriseHookRotationPhasePreparing || journal.Phase == enterpriseHookRotationPhasePrepared) {
		return fmt.Errorf("enterprise hooks: a rotation transaction holds the guardian roster")
	}
	if held, err := enterpriseHookRotationLockHeld(dataDir); err != nil {
		return err
	} else if held {
		return fmt.Errorf("enterprise hooks: a rotation transaction holds the guardian lock")
	}
	return nil
}

func enterpriseHookRotationJournalPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterpriseHookRotationJournalFile)
}

func enterpriseHookRotationLockPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterpriseHookRotationLockFile)
}

func enterpriseHookRotationRollbackPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterpriseHookRotationRollbackDir)
}

func enterpriseHookRotationTargetSnapshotPath(dataDir string, target enterpriseHookRotationTarget) string {
	sum := sha256.Sum256([]byte(enterpriseHookRotationTargetKey(target)))
	return filepath.Join(enterpriseHookRotationRollbackPath(dataDir), hex.EncodeToString(sum[:])+".snapshot")
}

func loadEnterpriseHookRotationJournal(dataDir string) (enterpriseHookRotationJournal, bool, error) {
	path := enterpriseHookRotationJournalPath(dataDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return enterpriseHookRotationJournal{}, false, nil
	}
	if err != nil {
		return enterpriseHookRotationJournal{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > enterpriseHookRotationJournalMaxBytes {
		return enterpriseHookRotationJournal{}, true, fmt.Errorf("enterprise hooks rotate: journal is not a trusted regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return enterpriseHookRotationJournal{}, true, err
	}
	var journal enterpriseHookRotationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return enterpriseHookRotationJournal{}, true, fmt.Errorf("enterprise hooks rotate: parse journal: %w", err)
	}
	if journal.Version != enterpriseHookRotationJournalVersion {
		return journal, true, fmt.Errorf("enterprise hooks rotate: unsupported journal version %d", journal.Version)
	}
	return journal, true, nil
}

func writeEnterpriseHookRotationJournal(dataDir string, journal enterpriseHookRotationJournal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return writeEnterpriseHookProtectedFile(enterpriseHookRotationJournalPath(dataDir), append(data, '\n'))
}

func removeEnterpriseHookRotationRollbackDir(dataDir string) error {
	path := enterpriseHookRotationRollbackPath(dataDir)
	if err := refuseEnterpriseHookRotationSymlink(path, "rotation rollback directory"); err != nil && !errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(path)
}

func refuseEnterpriseHookRotationSymlink(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("enterprise hooks rotate: inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks rotate: refusing symlink %s", label)
	}
	return nil
}

func enterpriseHookRotationPlatformSupported() error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
	}
	return nil
}

func captureEnterpriseHookRotationArtifact(path string) (enterpriseHookRotationSnapshot, error) {
	snapshot := enterpriseHookRotationSnapshot{Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return snapshot, fmt.Errorf("artifact is not a regular file")
	}
	if info.Size() > enterpriseHookRotationSnapshotMaxBytes {
		return snapshot, fmt.Errorf("artifact exceeds snapshot bound")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	snapshot.Present = true
	snapshot.Mode = uint32(info.Mode().Perm())
	snapshot.Bytes = data
	snapshot.Digest = managed.ScopedTokenFingerprint(string(data))
	uid, gid, err := enterpriseHookRotationFileOwner(info)
	if err != nil {
		return snapshot, err
	}
	snapshot.UID = uid
	snapshot.GID = gid
	return snapshot, nil
}

func restoreEnterpriseHookRotationArtifact(snapshot enterpriseHookRotationSnapshot) error {
	if !snapshot.Present {
		err := os.Remove(snapshot.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(snapshot.Path), 0o700); err != nil {
		return err
	}
	if err := safefile.Write(snapshot.Path, snapshot.Bytes); err != nil {
		return err
	}
	if snapshot.Mode != 0 {
		if err := os.Chmod(snapshot.Path, os.FileMode(snapshot.Mode)); err != nil {
			return err
		}
	}
	return enterpriseHookRotationRestoreOwner(snapshot)
}

type enterpriseHookRotationSecretRecord struct {
	enterpriseHookRotationTargetSnapshot
	Payloads [][]byte `json:"payloads"`
}

func encodeEnterpriseHookRotationSnapshotSidecar(path string, target enterpriseHookRotationTarget, snapshot enterpriseHookRotationSnapshot) error {
	record := enterpriseHookRotationSecretRecord{
		enterpriseHookRotationTargetSnapshot: enterpriseHookRotationTargetSnapshot{
			Target: target,
			Artifacts: []enterpriseHookRotationSnapshot{{
				Path:    snapshot.Path,
				Present: snapshot.Present,
				Mode:    snapshot.Mode,
				UID:     snapshot.UID,
				GID:     snapshot.GID,
				Digest:  snapshot.Digest,
			}},
		},
		Payloads: [][]byte{snapshot.Bytes},
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return safefile.Write(path, data)
}

func decodeEnterpriseHookRotationSnapshotSidecar(path string) (enterpriseHookRotationSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return enterpriseHookRotationSnapshot{}, err
	}
	var record enterpriseHookRotationSecretRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return enterpriseHookRotationSnapshot{}, err
	}
	if len(record.Artifacts) != 1 {
		return enterpriseHookRotationSnapshot{}, fmt.Errorf("rotation snapshot is malformed")
	}
	snapshot := record.Artifacts[0]
	if len(record.Payloads) == 1 {
		snapshot.Bytes = record.Payloads[0]
	}
	return snapshot, nil
}
