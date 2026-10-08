// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const managedBackupVersion = 1
const managedBackupMissingHash = "missing"

type managedFileBackup struct {
	Version        int    `json:"version"`
	Connector      string `json:"connector"`
	LogicalName    string `json:"logical_name"`
	Path           string `json:"path"`
	Existed        bool   `json:"existed"`
	Mode           uint32 `json:"mode,omitempty"`
	PristineSHA256 string `json:"pristine_sha256"`
	PostSHA256     string `json:"post_sha256,omitempty"`
	PristineBytes  []byte `json:"pristine_bytes,omitempty"`
	CapturedAt     string `json:"captured_at"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

func managedFileBackupPath(dataDir, connectorName, logicalName string) string {
	name := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(logicalName)
	if name == "" {
		name = "config"
	}
	return filepath.Join(dataDir, "connector_backups", connectorName, name+".json")
}

// migrateManagedFileBackupLogicalName moves one connector-owned backup record
// to its canonical logical name without recapturing the vendor file. This
// preserves the original bytes and post-write hash used for exact restoration.
// A duplicate legacy record is discarded only when its custody metadata is
// identical; conflicting records fail closed.
func migrateManagedFileBackupLogicalName(
	dataDir, connectorName, legacyLogicalName, canonicalLogicalName string,
) error {
	if legacyLogicalName == canonicalLogicalName {
		return nil
	}
	legacyPath := managedFileBackupPath(dataDir, connectorName, legacyLogicalName)
	canonicalPath := managedFileBackupPath(dataDir, connectorName, canonicalLogicalName)

	legacy, legacyErr := loadManagedFileBackupPath(legacyPath)
	if legacyErr != nil && !os.IsNotExist(legacyErr) {
		return fmt.Errorf("load legacy managed backup: %w", legacyErr)
	}
	canonical, canonicalErr := loadManagedFileBackupPath(canonicalPath)
	if canonicalErr != nil && !os.IsNotExist(canonicalErr) {
		return fmt.Errorf("load canonical managed backup: %w", canonicalErr)
	}
	if os.IsNotExist(legacyErr) {
		return nil
	}
	legacyTarget, err := validateManagedFileBackupTarget(
		legacy, connectorName, legacyLogicalName, legacy.Path,
	)
	if err != nil {
		return fmt.Errorf("validate legacy managed backup: %w", err)
	}

	if canonicalErr == nil {
		canonicalTarget, err := validateManagedFileBackupTarget(
			canonical, connectorName, canonicalLogicalName, canonical.Path,
		)
		if err != nil {
			return fmt.Errorf("validate canonical managed backup: %w", err)
		}
		if !sameManagedBackupCustody(&legacy, legacyTarget, &canonical, canonicalTarget) {
			return fmt.Errorf(
				"%s has conflicting %s and %s managed backup custody",
				connectorName, legacyLogicalName, canonicalLogicalName,
			)
		}
		return removeManagedBackupFile(legacyPath)
	}

	migrated := legacy
	migrated.LogicalName = canonicalLogicalName
	if err := writeManagedFileBackup(canonicalPath, migrated); err != nil {
		return fmt.Errorf("write canonical managed backup: %w", err)
	}
	return removeManagedBackupFile(legacyPath)
}

func sameManagedBackupCustody(
	left *managedFileBackup,
	leftTarget string,
	right *managedFileBackup,
	rightTarget string,
) bool {
	return left.Version == right.Version &&
		sameManagedTargetPath(leftTarget, rightTarget) &&
		left.Existed == right.Existed &&
		left.Mode == right.Mode &&
		left.PristineSHA256 == right.PristineSHA256 &&
		left.PostSHA256 == right.PostSHA256 &&
		bytes.Equal(left.PristineBytes, right.PristineBytes)
}

func sameManagedTargetPath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func removeManagedBackupFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove legacy managed backup: %w", err)
	}
	return nil
}

func managedFileBackupTargetPath(dataDir, connectorName, logicalName, fallback string) string {
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err == nil && b.Connector == connectorName && b.LogicalName == logicalName && strings.TrimSpace(b.Path) != "" {
		return b.Path
	}
	return fallback
}

func captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath string) error {
	boundPath, err := normalizeManagedTargetPath(targetPath)
	if err != nil {
		return fmt.Errorf("bind managed backup target: %w", err)
	}
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	existing, err := loadManagedFileBackupPath(backupPath)
	if err == nil {
		_, err = validateManagedFileBackupTarget(existing, connectorName, logicalName, boundPath)
		return err
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("load managed backup: %w", err)
	}

	b := managedFileBackup{
		Version:     managedBackupVersion,
		Connector:   connectorName,
		LogicalName: logicalName,
		Path:        boundPath,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return err
	}
	if info != nil {
		b.Existed = true
		b.Mode = uint32(info.Mode().Perm())
		b.PristineBytes = data
		b.PristineSHA256 = sha256Hex(data)
	} else {
		b.PristineSHA256 = managedBackupMissingHash
	}
	return writeManagedFileBackup(backupPath, b)
}

func updateManagedFileBackupPostHash(dataDir, connectorName, logicalName, targetPath string) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	boundPath, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath)
	if err != nil {
		return err
	}
	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return err
	}
	nextHash := managedFileSnapshotHash(nil, false)
	if info != nil {
		nextHash = managedFileSnapshotHash(data, true)
	}
	return updateManagedFileBackupPostHashValue(dataDir, connectorName, logicalName, boundPath, nextHash)
}

// updateManagedFileBackupPostHashValue records the exact bytes the connector
// committed, rather than re-reading a path that an external editor can change
// between replacement and backup publication. If the path later drifts, its
// hash no longer matches and teardown automatically uses surgical cleanup.
func updateManagedFileBackupPostHashValue(
	dataDir, connectorName, logicalName, targetPath, nextHash string,
) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if _, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath); err != nil {
		return err
	}
	if nextHash == "" {
		return fmt.Errorf("managed backup post hash is empty")
	}
	if b.PostSHA256 == nextHash {
		return nil
	}
	b.PostSHA256 = nextHash
	b.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeManagedFileBackup(backupPath, b)
}

func managedFileSnapshotHash(data []byte, exists bool) string {
	if !exists {
		return managedBackupMissingHash
	}
	return sha256Hex(data)
}

func managedFileBackupExpectedHash(b *managedFileBackup) string {
	if b == nil {
		return ""
	}
	if b.PostSHA256 != "" {
		return b.PostSHA256
	}
	return b.PristineSHA256
}

func managedFileBackupMatchesSnapshot(b *managedFileBackup, data []byte, exists bool) bool {
	return b != nil && managedFileBackupExpectedHash(b) == managedFileSnapshotHash(data, exists)
}

// managedRestoreError is a backup that could not be written back over its
// target. Its message is the whole cause ("could not restore <path>: <why>"),
// so callers report it as is instead of adding their own prefix.
type managedRestoreError struct {
	Path string
	Err  error
}

func (e *managedRestoreError) Error() string {
	return fmt.Sprintf("could not restore %s: %v", e.Path, e.Err)
}
func (e *managedRestoreError) Unwrap() error { return e.Err }

// newManagedRestoreError keeps only the operating system's cause: the staged
// temp file the write went through is gone, so naming it only confuses.
func newManagedRestoreError(path string, err error) error {
	var publish *atomicPublishError
	var link *os.LinkError
	var pathErr *os.PathError
	switch {
	case errors.As(err, &publish):
		err = publish.Err
	case errors.As(err, &link) && link.Err != nil:
		err = link.Err
	case errors.As(err, &pathErr) && pathErr.Err != nil:
		err = pathErr.Err
	}
	return &managedRestoreError{Path: path, Err: err}
}

// restoreBackupFailure words a restore failure for a teardown report.
func restoreBackupFailure(err error) string {
	var restore *managedRestoreError
	if errors.As(err, &restore) {
		return err.Error()
	}
	return fmt.Sprintf("restore config backup: %v", err)
}

func restoreManagedFileBackupIfUnchanged(dataDir, connectorName, logicalName, targetPath string) (bool, error) {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	boundPath, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath)
	if err != nil {
		return false, err
	}

	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return false, err
	}
	currentHash := managedBackupMissingHash
	if info != nil {
		currentHash = sha256Hex(data)
	}
	expectedHash := b.PostSHA256
	if expectedHash == "" {
		expectedHash = b.PristineSHA256
	}
	if currentHash != expectedHash {
		return false, nil
	}

	if b.Existed {
		mode := os.FileMode(b.Mode)
		if mode == 0 {
			mode = 0o600
		}
		if err := atomicWriteFile(boundPath, b.PristineBytes, mode); err != nil {
			return false, newManagedRestoreError(boundPath, err)
		}
	} else if err := os.Remove(boundPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func normalizeManagedTargetPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("target path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve target path %q: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

// validateManagedFileBackupTarget binds restore metadata to both its logical
// owner and the exact lexical target captured during setup. It deliberately
// does not resolve symlinks: following a retargeted link during teardown would
// weaken the same-file invariant this check protects.
func validateManagedFileBackupTarget(b managedFileBackup, connectorName, logicalName, targetPath string) (string, error) {
	if b.Connector != connectorName || b.LogicalName != logicalName {
		return "", fmt.Errorf(
			"managed backup identity mismatch: captured %s/%s, requested %s/%s",
			b.Connector, b.LogicalName, connectorName, logicalName,
		)
	}
	captured, err := normalizeManagedTargetPath(b.Path)
	if err != nil {
		return "", fmt.Errorf("invalid managed backup target: %w", err)
	}
	requested, err := normalizeManagedTargetPath(targetPath)
	if err != nil {
		return "", fmt.Errorf("invalid requested restore target: %w", err)
	}
	equal := captured == requested
	if runtime.GOOS == "windows" {
		equal = strings.EqualFold(captured, requested)
	}
	if !equal {
		return "", fmt.Errorf("managed backup target mismatch: captured %q, requested %q", captured, requested)
	}
	return captured, nil
}

// managedFileBackupDrifted reports whether a backup exists and its target no
// longer holds the bytes the connector last committed: the user (or the agent)
// edited the file since. A later Setup must not refresh the post hash over
// that edit, or teardown would restore the pre-setup snapshot and silently
// revert it (GAP-1463).
func managedFileBackupDrifted(dataDir, connectorName, logicalName, targetPath string) (bool, error) {
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if b.PostSHA256 == "" {
		return false, nil
	}
	boundPath, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath)
	if err != nil {
		return false, err
	}
	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return false, err
	}
	return !managedFileBackupMatchesSnapshot(&b, data, info != nil), nil
}

// recaptureManagedFileBackup replaces a drifted record with one whose
// snapshot is the target's current bytes (raw), so drift detection stays on
// after the agent itself edits the file. Only connectors whose teardown
// filters their own fields out of an exact restore may use it: the outside
// edit then survives teardown just as it does with surgical cleanup. It
// returns the new record, or nil (leaving none) when the target no longer
// holds raw.
func recaptureManagedFileBackup(
	dataDir, connectorName, logicalName, targetPath string, raw []byte, exists bool,
) *managedFileBackup {
	discardManagedFileBackup(dataDir, connectorName, logicalName)
	if err := captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath); err != nil {
		discardManagedFileBackup(dataDir, connectorName, logicalName)
		return nil
	}
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err != nil || !managedFileBackupMatchesSnapshot(&b, raw, exists) {
		discardManagedFileBackup(dataDir, connectorName, logicalName)
		return nil
	}
	return &b
}

func discardManagedFileBackup(dataDir, connectorName, logicalName string) {
	_ = os.Remove(managedFileBackupPath(dataDir, connectorName, logicalName))
}

func loadManagedFileBackupPath(path string) (managedFileBackup, error) {
	var b managedFileBackup
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	if b.Version != managedBackupVersion {
		return b, fmt.Errorf("unsupported managed backup version %d", b.Version)
	}
	if moved, ok := managedBackupTargetAfterHomeMove(path, b.Path); ok {
		b.Path = moved
	}
	return b, nil
}

// managedBackupTargetAfterHomeMove maps a record captured before the account
// home moved (a rename with usermod -m, or a directory service that changed
// the home path) onto the same file under the current home. Without it every
// setup, gateway start and uninstall stopped at "managed backup target
// mismatch" and no product command could repair the install (GAP-0543).
//
// The mapping only applies when the record itself lives under the current
// home, the captured target is outside it, the old root of the captured
// target no longer exists at all, and the same relative file exists under
// the current home. Restore still compares the hash of the file with the
// one setup recorded before it writes anything.
func managedBackupTargetAfterHomeMove(recordPath, captured string) (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" || strings.TrimSpace(captured) == "" {
		return "", false
	}
	home = filepath.Clean(home)
	captured = filepath.Clean(captured)
	record, err := filepath.Abs(recordPath)
	if err != nil || !filepath.IsAbs(captured) || !managedPathWithin(record, home) || managedPathWithin(captured, home) {
		return "", false
	}
	oldRoot := shallowestMissingAncestor(captured)
	if oldRoot == "" || managedPathWithin(home, oldRoot) || managedPathWithin(oldRoot, home) {
		return "", false
	}
	rel, err := filepath.Rel(oldRoot, captured)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", false
	}
	candidate := filepath.Join(home, rel)
	if _, err := os.Lstat(candidate); err != nil {
		return "", false
	}
	return candidate, true
}

// shallowestMissingAncestor returns the first directory on the way down to
// path that does not exist (the old home when an account home moved), or ""
// when every parent of path exists.
func shallowestMissingAncestor(path string) string {
	var chain []string
	for current := path; ; {
		chain = append(chain, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	for i := len(chain) - 1; i > 0; i-- {
		if _, err := os.Lstat(chain[i]); err != nil {
			if os.IsNotExist(err) {
				return chain[i]
			}
			return ""
		}
	}
	return ""
}

func managedPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		rel = strings.ToLower(rel)
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func writeManagedFileBackup(path string, b managedFileBackup) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// Ensure the per-connector backup directory is owner-only (0o700)
	// before atomicWriteFile lays down the file. atomicWriteFile uses
	// MkdirAll(_, 0o755) by design — that perm is right for parent
	// dirs of user-owned config files (e.g. ~/.codex/) but wrong for
	// our own ${data_dir}/connector_backups/<connector>/ tree, which
	// would otherwise be world-readable. Listing the connector_backups
	// dir leaks which connectors the operator has installed; the
	// payload itself already has 0o600 from atomicWriteFile.
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

// ensureManagedBackupDirRestricted creates *dir* with mode 0o700 if it
// does not exist, and tightens an existing dir down to 0o700 if a prior
// install (or umask) left it world-readable. Failures are returned
// rather than swallowed because the per-connector dir is the parent of
// every backup; if we cannot guarantee 0o700 here, the operator should
// see the error rather than discover later that the backup payload was
// listable.
func ensureManagedBackupDirRestricted(dir string) error {
	if dir == "" {
		return nil
	}
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("create managed backup dir %s: %w", dir, err)
	}
	return nil
}

func readManagedTarget(path string) ([]byte, os.FileInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("stat %s: %w", path, err)
	}
	return data, info, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RestoreManagedFileBackups puts every agent file that a connector setup
// recorded in dataDir's connector_backups back the way setup found it: the
// captured bytes, or no file when setup created it. A file that changed since
// DefenseClaw last wrote it, or whose record names a path outside home, is
// left in place and returned in kept. Each record it restores from is
// removed. The rollback of a failed first Windows install runs it as the
// account, before the data directory the install created is removed.
func RestoreManagedFileBackups(dataDir, home string) (restored, kept []string, err error) {
	err = forEachManagedFileBackup(dataDir, func(b managedFileBackup) error {
		if !managedBackupTargetInside(home, b.Path) {
			kept = append(kept, b.Path)
			return nil
		}
		ok, restoreErr := restoreManagedFileBackupIfUnchanged(dataDir, b.Connector, b.LogicalName, b.Path)
		switch {
		case restoreErr != nil:
			return fmt.Errorf("restore %s: %w", b.Path, restoreErr)
		case ok:
			restored = append(restored, b.Path)
		default:
			kept = append(kept, b.Path)
		}
		return nil
	})
	return restored, kept, err
}

// ManagedFileBackupTargets lists the agent file each connector backup record
// in dataDir names.
func ManagedFileBackupTargets(dataDir string) ([]string, error) {
	var targets []string
	err := forEachManagedFileBackup(dataDir, func(b managedFileBackup) error {
		targets = append(targets, b.Path)
		return nil
	})
	return targets, err
}

// forEachManagedFileBackup calls fn for each record in dataDir's
// connector_backups that sits where its connector and logical name put it.
func forEachManagedFileBackup(dataDir string, fn func(managedFileBackup) error) error {
	root := filepath.Join(dataDir, "connector_backups")
	connectors, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, dir := range connectors {
		if !dir.IsDir() {
			continue
		}
		entries, readErr := os.ReadDir(filepath.Join(root, dir.Name()))
		if readErr != nil {
			errs = append(errs, readErr)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				continue
			}
			recordPath := filepath.Join(root, dir.Name(), entry.Name())
			b, loadErr := loadManagedFileBackupPath(recordPath)
			if loadErr != nil {
				errs = append(errs, fmt.Errorf("load managed backup %s: %w", recordPath, loadErr))
				continue
			}
			if b.Connector != dir.Name() ||
				!sameManagedTargetPath(managedFileBackupPath(dataDir, b.Connector, b.LogicalName), recordPath) {
				errs = append(errs, fmt.Errorf("managed backup %s does not match its location", recordPath))
				continue
			}
			if err := fn(b); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func managedBackupTargetInside(home, path string) bool {
	if strings.TrimSpace(home) == "" || !filepath.IsAbs(path) {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(path))
	return err == nil && rel != "." && !filepath.IsAbs(rel) &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
