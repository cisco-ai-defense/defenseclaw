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

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsManagedRotationSchema           = "windows-guardian-rotation.v1"
	windowsManagedRotationJournalFile      = "windows-rotation-transaction.json"
	windowsManagedRotationLockFile         = "windows-rotation-transaction.lock"
	windowsManagedRotationRollbackDir      = "windows-rotation-rollback"
	windowsManagedRotationMinFreeBytes     = 4 << 20
	windowsManagedRotationSnapshotMaxBytes = 64 << 10
	windowsManagedRotationJournalMaxBytes  = 1 << 20
)

var (
	windowsManagedRotationSessionCheck = func(sid, home string) error {
		return enterprisehooks.RequireWindowsEnterpriseTargetSession(sid, home)
	}
	windowsManagedRotationImpersonate = func(sid *windows.SID, home string, fn func() error) error {
		return enterprisehooks.RunWithWindowsEnterpriseTargetImpersonation(sid, home, fn)
	}
	windowsManagedRotationAfterTargetWrite = func(enterpriseHookRotationTarget) error { return nil }
	windowsManagedRotationSpaceCheck       = checkWindowsManagedRotationSpace
	windowsManagedRotationLoadB            = loadEnterpriseHookScopedToken
	windowsManagedRotationPublishB         = connector.PublishHookAPIToken
	windowsManagedRotationReadPublished    = connector.LoadHookAPIToken
	windowsManagedRotationInspectPath      = inspectWindowsManagedRotationPath
)

type windowsManagedRotationJournal struct {
	Schema         string                         `json:"schema"`
	Version        int                            `json:"version"`
	OperationID    string                         `json:"operation_id"`
	Generation     string                         `json:"generation"`
	Manifest       string                         `json:"manifest"`
	ManifestSHA256 string                         `json:"manifest_sha256"`
	Phase          string                         `json:"phase"`
	Targets        []enterpriseHookRotationTarget `json:"targets"`
	UpdatedAt      string                         `json:"updated_at"`
}

type windowsManagedRotationPlan struct {
	Journal windowsManagedRotationJournal
	Targets []enterpriseHookRotationTarget
	Tokens  map[string]string
}

type windowsManagedRotationFileIdentity struct {
	VolumeSerial  uint32 `json:"volume_serial"`
	FileIndexHigh uint32 `json:"file_index_high"`
	FileIndexLow  uint32 `json:"file_index_low"`
	NumberOfLinks uint32 `json:"number_of_links"`
	CanonicalPath string `json:"canonical_path,omitempty"`
}

type windowsManagedRotationSnapshot struct {
	Path          string                             `json:"path"`
	Present       bool                               `json:"present"`
	Digest        string                             `json:"digest,omitempty"`
	OwnerSID      string                             `json:"owner_sid,omitempty"`
	ProtectedDACL bool                               `json:"protected_dacl,omitempty"`
	Identity      windowsManagedRotationFileIdentity `json:"identity,omitempty"`
	Bytes         []byte                             `json:"-"`
}

type windowsManagedRotationSecretRecord struct {
	Target   enterpriseHookRotationTarget   `json:"target"`
	Artifact windowsManagedRotationSnapshot `json:"artifact"`
	Payloads [][]byte                       `json:"payloads"`
}

func executeManagedRotationPrepare(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeWindowsManagedRotationPrepare(req)
}

func executeManagedRotationCommit(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeWindowsManagedRotationCommit(req)
}

func executeManagedRotationRollback(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeWindowsManagedRotationRollback(req)
}

func withEnterpriseHookRotationLock(
	_ string,
	_ func() (enterpriseHookRotationJournal, error),
) (enterpriseHookRotationJournal, error) {
	return enterpriseHookRotationJournal{}, fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func enterpriseHookRotationLockHeld(string) (bool, error) {
	return false, nil
}

func enterpriseHookRotationFileOwner(os.FileInfo) (int, int, error) {
	return -1, -1, fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func enterpriseHookRotationRestoreOwner(enterpriseHookRotationSnapshot) error {
	return fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func checkEnterpriseHookRotationSpace(string) error {
	return fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func executeWindowsManagedRotationPrepare(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if cfg == nil {
		return empty, fmt.Errorf("windows managed rotation prepare: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	plan, err := preflightWindowsManagedRotation(req, true)
	if err != nil {
		return empty, err
	}
	return withWindowsManagedRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadWindowsManagedRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if exists {
			if err := windowsManagedRotationJournalConflicts(journal, plan.Journal); err != nil {
				return journal.public(), err
			}
			switch journal.Phase {
			case enterpriseHookRotationPhasePrepared, enterpriseHookRotationPhaseCommitted:
				if err := verifyWindowsManagedRotationCurrentB(plan); err != nil {
					return journal.public(), err
				}
				return journal.public(), nil
			case enterpriseHookRotationPhaseRolledBack:
				return journal.public(), fmt.Errorf("windows managed rotation prepare: operation already rolled back")
			}
		}
		if err := refusePOSIXRotationJournal(cfg.DataDir); err != nil {
			return empty, err
		}
		if err := writeWindowsManagedRotationJournal(cfg.DataDir, plan.Journal); err != nil {
			return empty, err
		}
		mutated := 0
		for i, target := range plan.Targets {
			if err := snapshotWindowsManagedRotationTarget(cfg.DataDir, target); err != nil {
				_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets[:mutated])
				return plan.Journal.public(), fmt.Errorf("windows managed rotation prepare: snapshot %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
			if err := publishWindowsManagedRotationTargetB(target, plan.Tokens[target.Connector]); err != nil {
				_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets[:i+1])
				return plan.Journal.public(), fmt.Errorf("windows managed rotation prepare: write B for %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
			mutated = i + 1
			if err := windowsManagedRotationAfterTargetWrite(target); err != nil {
				_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets[:mutated])
				return plan.Journal.public(), fmt.Errorf("windows managed rotation prepare: post-write %s: %w", enterpriseHookRotationTargetLabel(target), err)
			}
		}
		if err := verifyWindowsManagedRotationCurrentB(plan); err != nil {
			_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal.public(), err
		}
		if err := publishWindowsManagedRotationCurrent(plan); err != nil {
			_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal.public(), err
		}
		plan.Journal.Phase = enterpriseHookRotationPhasePrepared
		plan.Journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeWindowsManagedRotationJournal(cfg.DataDir, plan.Journal); err != nil {
			_ = restoreWindowsManagedRotationMutated(cfg.DataDir, plan.Targets)
			return plan.Journal.public(), err
		}
		return plan.Journal.public(), nil
	})
}

func executeWindowsManagedRotationCommit(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if cfg == nil {
		return empty, fmt.Errorf("windows managed rotation commit: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	plan, err := preflightWindowsManagedRotation(req, false)
	if err != nil {
		return empty, err
	}
	return withWindowsManagedRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadWindowsManagedRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if !exists {
			return empty, fmt.Errorf("windows managed rotation commit: no prepared rotation exists")
		}
		if err := windowsManagedRotationJournalConflicts(journal, plan.Journal); err != nil {
			return journal.public(), err
		}
		if journal.Phase == enterpriseHookRotationPhaseCommitted {
			return journal.public(), nil
		}
		if journal.Phase != enterpriseHookRotationPhasePrepared {
			return journal.public(), fmt.Errorf("windows managed rotation commit: phase %s is not prepared", journal.Phase)
		}
		if err := verifyWindowsManagedRotationCurrentB(plan); err != nil {
			return journal.public(), err
		}
		if err := removeWindowsManagedRotationRollbackDir(cfg.DataDir); err != nil {
			return journal.public(), fmt.Errorf("windows managed rotation commit: retire rollback material: %w", err)
		}
		journal.Phase = enterpriseHookRotationPhaseCommitted
		journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeWindowsManagedRotationJournal(cfg.DataDir, journal); err != nil {
			return journal.public(), err
		}
		return journal.public(), nil
	})
}

func executeWindowsManagedRotationRollback(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	if cfg == nil {
		return empty, fmt.Errorf("windows managed rotation rollback: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return empty, err
	}
	if err := validateEnterpriseHookRotationIdentity(req.OperationID, req.Generation); err != nil {
		return empty, err
	}
	return withWindowsManagedRotationLock(cfg.DataDir, func() (enterpriseHookRotationJournal, error) {
		journal, exists, err := loadWindowsManagedRotationJournal(cfg.DataDir)
		if err != nil {
			return empty, err
		}
		if exists {
			want := windowsManagedRotationJournal{
				OperationID: strings.TrimSpace(req.OperationID),
				Generation:  strings.TrimSpace(req.Generation),
				Manifest:    strings.TrimSpace(req.Manifest),
			}
			if err := windowsManagedRotationJournalConflicts(journal, want); err != nil {
				return journal.public(), err
			}
			if journal.Phase == enterpriseHookRotationPhaseRolledBack || journal.Phase == enterpriseHookRotationPhaseCommitted {
				return journal.public(), nil
			}
		}
		targets := []enterpriseHookRotationTarget{}
		if exists {
			targets = journal.Targets
		}
		if err := restoreWindowsManagedRotationMutated(cfg.DataDir, targets); err != nil {
			if exists {
				journal.Phase = enterpriseHookRotationPhasePreparing
				_ = writeWindowsManagedRotationJournal(cfg.DataDir, journal)
			}
			return journal.public(), fmt.Errorf("windows managed rotation rollback: exact A restoration could not be proved: %w", err)
		}
		if exists {
			if err := publishWindowsManagedRotationRestoredCurrent(cfg.DataDir, journal, targets); err != nil {
				return journal.public(), err
			}
			journal.Phase = enterpriseHookRotationPhaseRolledBack
			journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := writeWindowsManagedRotationJournal(cfg.DataDir, journal); err != nil {
				return journal.public(), err
			}
			return journal.public(), nil
		}
		if err := markEnterpriseHookRotationUnready(cfg.DataDir); err != nil {
			return journal.public(), err
		}
		return empty, nil
	})
}

func preflightWindowsManagedRotation(req enterpriseHookRotationRequest, requireFingerprints bool) (windowsManagedRotationPlan, error) {
	var plan windowsManagedRotationPlan
	if err := validateEnterpriseHookRotationIdentity(req.OperationID, req.Generation); err != nil {
		return plan, err
	}
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return plan, fmt.Errorf("windows managed rotation: managed enterprise deployment is required")
	}
	if err := refusePOSIXRotationJournal(cfg.DataDir); err != nil {
		return plan, err
	}
	manifestPath := strings.TrimSpace(req.Manifest)
	if err := enterpriseHookManifestFileTrustCheck(manifestPath); err != nil {
		return plan, fmt.Errorf("windows managed rotation: manifest trust check failed: %w", err)
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
		return plan, fmt.Errorf("windows managed rotation: guardian authorization lacks current per-target attestations")
	}
	enabled := enabledEnterpriseHookRotationTargets(manifest)
	if len(enabled) == 0 {
		return plan, fmt.Errorf("windows managed rotation: manifest has no enabled targets")
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
		journal, journalExists, journalErr := loadWindowsManagedRotationJournal(cfg.DataDir)
		if journalErr != nil {
			return plan, journalErr
		}
		if journalExists {
			expected = journal.Targets
		}
	}
	if err := windowsManagedRotationSpaceCheck(cfg.DataDir); err != nil {
		return plan, err
	}
	tokens := map[string]string{}
	for _, target := range expected {
		if err := preflightWindowsManagedRotationTarget(target); err != nil {
			return plan, err
		}
		token, err := windowsManagedRotationLoadB(cfg.DataDir, target.Connector)
		if err != nil {
			return plan, fmt.Errorf("windows managed rotation: load generation B for %s: %w", target.Connector, err)
		}
		fingerprint := managed.ScopedTokenFingerprint(token)
		if requireFingerprints && fingerprint != target.TokenFingerprint {
			return plan, fmt.Errorf("windows managed rotation: service token fingerprint does not match expected B for %s", target.Connector)
		}
		tokens[target.Connector] = token
	}
	plan.Targets = expected
	plan.Tokens = tokens
	plan.Journal = windowsManagedRotationJournal{
		Schema:         windowsManagedRotationSchema,
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

func preflightWindowsManagedRotationTarget(target enterpriseHookRotationTarget) error {
	if !windowsManagedRotationQualifiedConnector(target.Connector) {
		return fmt.Errorf("windows managed rotation: connector %s is not in the certified Claude/Codex set", target.Connector)
	}
	sid := strings.TrimSpace(target.SID)
	if sid == "" {
		return fmt.Errorf("windows managed rotation: target %s is missing a manifest-pinned SID", enterpriseHookRotationTargetLabel(target))
	}
	parsed, err := windows.StringToSid(sid)
	if err != nil || parsed == nil {
		return fmt.Errorf("windows managed rotation: target %s has an invalid SID", enterpriseHookRotationTargetLabel(target))
	}
	home := filepath.Clean(strings.TrimSpace(target.UserHome))
	if home == "" || !filepath.IsAbs(home) {
		return fmt.Errorf("windows managed rotation: target %s is missing a canonical home", enterpriseHookRotationTargetLabel(target))
	}
	if err := refuseWindowsManagedRotationReparse(home, "target home"); err != nil {
		return err
	}
	userDataDir := enterpriseHookRotationUserDataDir(target)
	if err := refuseWindowsManagedRotationReparse(userDataDir, "target data dir"); err != nil {
		return err
	}
	if err := windowsManagedRotationSessionCheck(sid, home); err != nil {
		if enterprisehooks.IsWindowsTargetSessionUnavailable(err) {
			return fmt.Errorf("windows managed rotation: no active interactive session for %s", enterpriseHookRotationTargetLabel(target))
		}
		return fmt.Errorf("windows managed rotation: session preflight for %s: %w", enterpriseHookRotationTargetLabel(target), err)
	}
	tokenPath, err := connector.HookAPITokenFilePath(userDataDir, target.Connector)
	if err != nil {
		return err
	}
	info, err := windowsManagedRotationInspectPath(tokenPath)
	if err != nil {
		return fmt.Errorf("windows managed rotation: inspect current artifact for %s: %w", enterpriseHookRotationTargetLabel(target), err)
	}
	if info.Present && !strings.EqualFold(info.OwnerSID, sid) {
		return fmt.Errorf("windows managed rotation: current artifact owner SID does not match the manifest for %s", enterpriseHookRotationTargetLabel(target))
	}
	return nil
}

func windowsManagedRotationQualifiedConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex":
		return true
	default:
		return false
	}
}

func publishWindowsManagedRotationTargetB(target enterpriseHookRotationTarget, token string) error {
	sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
	if err != nil || sid == nil {
		return fmt.Errorf("invalid target SID")
	}
	dataDir := enterpriseHookRotationUserDataDir(target)
	return windowsManagedRotationImpersonate(sid, strings.TrimSpace(target.UserHome), func() error {
		if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
			return err
		}
		if err := windowsManagedRotationPublishB(dataDir, target.Connector, token); err != nil {
			return err
		}
		published, err := windowsManagedRotationReadPublished(dataDir, target.Connector)
		if err != nil {
			return err
		}
		if managed.ScopedTokenFingerprint(published) != managed.ScopedTokenFingerprint(token) {
			return fmt.Errorf("persisted B fingerprint mismatch")
		}
		path, err := connector.HookAPITokenFilePath(dataDir, target.Connector)
		if err != nil {
			return err
		}
		info, err := windowsManagedRotationInspectPath(path)
		if err != nil {
			return err
		}
		if !info.Present || !info.ProtectedDACL || info.Identity.NumberOfLinks != 1 {
			return fmt.Errorf("published B is not a single-link protected artifact")
		}
		if !strings.EqualFold(info.OwnerSID, strings.TrimSpace(target.SID)) {
			return fmt.Errorf("published B owner SID does not match the manifest")
		}
		return nil
	})
}

func verifyWindowsManagedRotationCurrentB(plan windowsManagedRotationPlan) error {
	for _, target := range plan.Targets {
		dataDir := enterpriseHookRotationUserDataDir(target)
		token, err := windowsManagedRotationReadPublished(dataDir, target.Connector)
		if err != nil {
			return fmt.Errorf("windows managed rotation: re-read B for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		if managed.ScopedTokenFingerprint(token) != target.TokenFingerprint {
			return fmt.Errorf("windows managed rotation: persisted B fingerprint mismatch for %s", enterpriseHookRotationTargetLabel(target))
		}
		path, err := connector.HookAPITokenFilePath(dataDir, target.Connector)
		if err != nil {
			return err
		}
		info, err := windowsManagedRotationInspectPath(path)
		if err != nil || !info.Present {
			return fmt.Errorf("windows managed rotation: B handle proof missing for %s", enterpriseHookRotationTargetLabel(target))
		}
		if !strings.EqualFold(info.OwnerSID, strings.TrimSpace(target.SID)) || !info.ProtectedDACL {
			return fmt.Errorf("windows managed rotation: B DACL/owner proof failed for %s", enterpriseHookRotationTargetLabel(target))
		}
	}
	return nil
}

func publishWindowsManagedRotationCurrent(plan windowsManagedRotationPlan) error {
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

func publishWindowsManagedRotationRestoredCurrent(dataDir string, journal windowsManagedRotationJournal, targets []enterpriseHookRotationTarget) error {
	rows := make([]enterpriseHookReconcileRow, 0, len(targets))
	for _, target := range targets {
		snapshot, err := decodeWindowsManagedRotationSnapshot(windowsManagedRotationSnapshotPath(dataDir, target))
		if err != nil {
			return fmt.Errorf("windows managed rotation rollback: load A snapshot for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		if !snapshot.Present {
			return fmt.Errorf("windows managed rotation rollback: restored A snapshot missing for %s", enterpriseHookRotationTargetLabel(target))
		}
		token, err := windowsManagedRotationReadPublished(enterpriseHookRotationUserDataDir(target), target.Connector)
		if err != nil {
			return fmt.Errorf("windows managed rotation rollback: re-read A for %s: %w", enterpriseHookRotationTargetLabel(target), err)
		}
		fingerprint := managed.ScopedTokenFingerprint(token)
		if !managed.ValidScopedTokenFingerprint(fingerprint) {
			return fmt.Errorf("windows managed rotation rollback: restored A fingerprint missing for %s", enterpriseHookRotationTargetLabel(target))
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

func snapshotWindowsManagedRotationTarget(dataDir string, target enterpriseHookRotationTarget) error {
	userDataDir := enterpriseHookRotationUserDataDir(target)
	tokenPath, err := connector.HookAPITokenFilePath(userDataDir, target.Connector)
	if err != nil {
		return err
	}
	snapshot, err := windowsManagedRotationInspectPath(tokenPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(windowsManagedRotationRollbackPath(dataDir), 0o700); err != nil {
		return err
	}
	return encodeWindowsManagedRotationSnapshot(windowsManagedRotationSnapshotPath(dataDir, target), target, snapshot)
}

func restoreWindowsManagedRotationMutated(dataDir string, targets []enterpriseHookRotationTarget) error {
	var errs []error
	for _, target := range targets {
		if err := restoreWindowsManagedRotationTarget(dataDir, target); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func restoreWindowsManagedRotationTarget(dataDir string, target enterpriseHookRotationTarget) error {
	snapshot, err := decodeWindowsManagedRotationSnapshot(windowsManagedRotationSnapshotPath(dataDir, target))
	if err != nil {
		return err
	}
	sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
	if err != nil || sid == nil {
		return fmt.Errorf("invalid target SID")
	}
	return windowsManagedRotationImpersonate(sid, strings.TrimSpace(target.UserHome), func() error {
		return restoreWindowsManagedRotationArtifact(target, snapshot)
	})
}

func restoreWindowsManagedRotationArtifact(target enterpriseHookRotationTarget, snapshot windowsManagedRotationSnapshot) error {
	if !snapshot.Present {
		err := os.Remove(snapshot.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		info, err := windowsManagedRotationInspectPath(snapshot.Path)
		if err != nil {
			return err
		}
		if info.Present {
			return fmt.Errorf("absent A restoration left an artifact")
		}
		return nil
	}
	if snapshot.Digest == "" || snapshot.Digest != managed.ScopedTokenFingerprint(string(snapshot.Bytes)) {
		return fmt.Errorf("rotation snapshot digest does not match captured bytes")
	}
	if err := os.MkdirAll(filepath.Dir(snapshot.Path), 0o700); err != nil {
		return err
	}
	if err := safefile.Write(snapshot.Path, snapshot.Bytes); err != nil {
		return err
	}
	info, err := windowsManagedRotationInspectPath(snapshot.Path)
	if err != nil {
		return err
	}
	if !info.Present || info.Digest != snapshot.Digest {
		return fmt.Errorf("rotation snapshot restore did not reproduce the captured digest")
	}
	if info.Identity.VolumeSerial != snapshot.Identity.VolumeSerial {
		return fmt.Errorf("rotation snapshot restore crossed a volume boundary")
	}
	if !strings.EqualFold(info.OwnerSID, strings.TrimSpace(target.SID)) || !info.ProtectedDACL {
		return fmt.Errorf("rotation snapshot restore lost owner SID or protected DACL")
	}
	return nil
}

func inspectWindowsManagedRotationPath(path string) (windowsManagedRotationSnapshot, error) {
	snapshot := windowsManagedRotationSnapshot{Path: path}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return snapshot, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return snapshot, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return snapshot, fmt.Errorf("artifact is a directory or reparse point")
	}
	if info.NumberOfLinks != 1 {
		return snapshot, fmt.Errorf("artifact is not a single-link regular file")
	}
	canonical, err := windowsManagedRotationFinalPath(handle)
	if err != nil {
		return snapshot, err
	}
	owner, protected, err := windowsManagedRotationHandleSecurity(handle)
	if err != nil {
		return snapshot, err
	}
	data, err := windowsManagedRotationReadHandle(handle, windowsManagedRotationSnapshotMaxBytes)
	if err != nil {
		return snapshot, err
	}
	var after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &after); err != nil {
		return snapshot, err
	}
	if windowsManagedRotationFileID(info) != windowsManagedRotationFileID(after) ||
		after.NumberOfLinks != 1 ||
		after.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return snapshot, fmt.Errorf("artifact identity changed while reading")
	}
	snapshot.Present = true
	snapshot.Bytes = data
	snapshot.Digest = managed.ScopedTokenFingerprint(string(data))
	snapshot.OwnerSID = owner
	snapshot.ProtectedDACL = protected
	snapshot.Identity = windowsManagedRotationFileIdentity{
		VolumeSerial:  info.VolumeSerialNumber,
		FileIndexHigh: info.FileIndexHigh,
		FileIndexLow:  info.FileIndexLow,
		NumberOfLinks: info.NumberOfLinks,
		CanonicalPath: canonical,
	}
	return snapshot, nil
}

func windowsManagedRotationFileID(info windows.ByHandleFileInformation) string {
	return fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
}

func windowsManagedRotationFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			final := windows.UTF16ToString(buffer[:length])
			if strings.HasPrefix(final, `\\?\UNC\`) {
				final = `\\` + strings.TrimPrefix(final, `\\?\UNC\`)
			} else {
				final = strings.TrimPrefix(final, `\\?\`)
			}
			return filepath.Clean(final), nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func windowsManagedRotationHandleSecurity(handle windows.Handle) (string, bool, error) {
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", false, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", false, fmt.Errorf("artifact owner SID is unavailable")
	}
	control, _, err := sd.Control()
	if err != nil {
		return "", false, err
	}
	return owner.String(), control&windows.SE_DACL_PROTECTED != 0, nil
}

func windowsManagedRotationReadHandle(handle windows.Handle, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(&windowsManagedRotationHandleReader{handle: handle}, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("artifact exceeds snapshot bound")
	}
	return data, nil
}

type windowsManagedRotationHandleReader struct {
	handle windows.Handle
}

func (r *windowsManagedRotationHandleReader) Read(p []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(r.handle, p, &done, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return int(done), io.EOF
		}
		if done == 0 {
			return 0, err
		}
	}
	if done == 0 {
		return 0, io.EOF
	}
	return int(done), nil
}

func refuseWindowsManagedRotationReparse(path, label string) error {
	if err := winpath.RejectReparseChain(path); err != nil {
		return fmt.Errorf("windows managed rotation: refusing reparse %s: %w", label, err)
	}
	return nil
}

func refusePOSIXRotationJournal(dataDir string) error {
	path := enterpriseHookRotationJournalPath(dataDir)
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("windows managed rotation: POSIX guardian journal is forbidden on Windows")
}

func (journal windowsManagedRotationJournal) public() enterpriseHookRotationJournal {
	return enterpriseHookRotationJournal{
		Version:        journal.Version,
		OperationID:    journal.OperationID,
		Generation:     journal.Generation,
		Manifest:       journal.Manifest,
		ManifestSHA256: journal.ManifestSHA256,
		Phase:          journal.Phase,
		Targets:        journal.Targets,
		UpdatedAt:      journal.UpdatedAt,
	}
}

func windowsManagedRotationJournalConflicts(actual, want windowsManagedRotationJournal) error {
	return enterpriseHookRotationJournalConflicts(actual.public(), want.public())
}

func windowsManagedRotationBusy(dataDir string) error {
	if err := refusePOSIXRotationJournal(dataDir); err != nil {
		return err
	}
	journal, exists, err := loadWindowsManagedRotationJournal(dataDir)
	if err != nil {
		return err
	}
	if exists && (journal.Phase == enterpriseHookRotationPhasePreparing || journal.Phase == enterpriseHookRotationPhasePrepared) {
		return fmt.Errorf("%w: roster", errEnterpriseHookRotationBusy)
	}
	held, err := windowsManagedRotationLockHeld(dataDir)
	if err != nil {
		return err
	}
	if held {
		return fmt.Errorf("%w: lock", errEnterpriseHookRotationBusy)
	}
	return nil
}

func windowsManagedRotationJournalPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), windowsManagedRotationJournalFile)
}

func windowsManagedRotationLockPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), windowsManagedRotationLockFile)
}

func windowsManagedRotationRollbackPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), windowsManagedRotationRollbackDir)
}

func windowsManagedRotationSnapshotPath(dataDir string, target enterpriseHookRotationTarget) string {
	sum := sha256.Sum256([]byte(enterpriseHookRotationTargetKey(target)))
	return filepath.Join(windowsManagedRotationRollbackPath(dataDir), hex.EncodeToString(sum[:])+".snapshot")
}

func loadWindowsManagedRotationJournal(dataDir string) (windowsManagedRotationJournal, bool, error) {
	path := windowsManagedRotationJournalPath(dataDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return windowsManagedRotationJournal{}, false, nil
	}
	if err != nil {
		return windowsManagedRotationJournal{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > windowsManagedRotationJournalMaxBytes {
		return windowsManagedRotationJournal{}, true, fmt.Errorf("windows managed rotation: journal is not a trusted regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return windowsManagedRotationJournal{}, true, err
	}
	var journal windowsManagedRotationJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return windowsManagedRotationJournal{}, true, fmt.Errorf("windows managed rotation: parse journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return windowsManagedRotationJournal{}, true, fmt.Errorf("windows managed rotation: journal has trailing content")
	}
	if err := validateWindowsManagedRotationJournal(journal); err != nil {
		return journal, true, err
	}
	return journal, true, nil
}

func validateWindowsManagedRotationJournal(journal windowsManagedRotationJournal) error {
	if journal.Schema != windowsManagedRotationSchema {
		return fmt.Errorf("windows managed rotation: unsupported journal schema")
	}
	if journal.Version != enterpriseHookRotationJournalVersion {
		return fmt.Errorf("windows managed rotation: unsupported journal version %d", journal.Version)
	}
	if !validEnterpriseHookHex(journal.OperationID, 16) || !validEnterpriseHookHex(journal.Generation, 16) {
		return fmt.Errorf("windows managed rotation: journal identity is invalid")
	}
	if strings.TrimSpace(journal.Manifest) == "" || !validEnterpriseHookHex(journal.ManifestSHA256, sha256.Size) {
		return fmt.Errorf("windows managed rotation: journal manifest binding is invalid")
	}
	switch journal.Phase {
	case enterpriseHookRotationPhasePreparing, enterpriseHookRotationPhasePrepared,
		enterpriseHookRotationPhaseCommitted, enterpriseHookRotationPhaseRolledBack:
	default:
		return fmt.Errorf("windows managed rotation: journal phase %q is invalid", journal.Phase)
	}
	return nil
}

func writeWindowsManagedRotationJournal(dataDir string, journal windowsManagedRotationJournal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return writeEnterpriseHookProtectedFile(windowsManagedRotationJournalPath(dataDir), append(data, '\n'))
}

func encodeWindowsManagedRotationSnapshot(path string, target enterpriseHookRotationTarget, snapshot windowsManagedRotationSnapshot) error {
	record := windowsManagedRotationSecretRecord{
		Target:   target,
		Artifact: snapshot,
		Payloads: [][]byte{snapshot.Bytes},
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeEnterpriseHookProtectedFile(path, data)
}

func decodeWindowsManagedRotationSnapshot(path string) (windowsManagedRotationSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return windowsManagedRotationSnapshot{}, err
	}
	var record windowsManagedRotationSecretRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return windowsManagedRotationSnapshot{}, err
	}
	snapshot := record.Artifact
	if len(record.Payloads) == 1 {
		snapshot.Bytes = record.Payloads[0]
	}
	return snapshot, nil
}

func removeWindowsManagedRotationRollbackDir(dataDir string) error {
	path := windowsManagedRotationRollbackPath(dataDir)
	if err := refuseWindowsManagedRotationReparse(path, "rotation rollback directory"); err != nil {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(path)
}

func withWindowsManagedRotationLock(
	dataDir string,
	fn func() (enterpriseHookRotationJournal, error),
) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	lockPath := windowsManagedRotationLockPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return empty, fmt.Errorf("windows managed rotation: create lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return empty, fmt.Errorf("windows managed rotation: open lock: %w", err)
	}
	defer file.Close()
	ol := &windows.Overlapped{}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1,
		0,
		ol,
	); err != nil {
		return empty, fmt.Errorf("windows managed rotation: acquire lock: %w", err)
	}
	defer func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, ol)
	}()
	return fn()
}

func windowsManagedRotationLockHeld(dataDir string) (bool, error) {
	lockPath := windowsManagedRotationLockPath(dataDir)
	file, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	ol := &windows.Overlapped{}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		ol,
	); err != nil {
		return true, nil
	}
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, ol)
	return false, nil
}

func checkWindowsManagedRotationSpace(dataDir string) error {
	path := filepath.Dir(windowsManagedRotationLockPath(dataDir))
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		path = dataDir
	}
	var free uint64
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("windows managed rotation: inspect free space: %w", err)
	}
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &free, nil, nil); err != nil {
		return fmt.Errorf("windows managed rotation: inspect free space: %w", err)
	}
	if free < windowsManagedRotationMinFreeBytes {
		return fmt.Errorf("windows managed rotation: insufficient free space")
	}
	return nil
}
