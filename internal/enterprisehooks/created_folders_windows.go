//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone created-folder record (GAP-0091). Every vendor folder
// DefenseClaw creates under ProgramData or Program Files (C:\ProgramData\Cisco,
// C:\ProgramData\Cursor, C:\ProgramData\OpenAI\Codex, C:\Program Files\ClaudeCode,
// ...) gets one administrator-only file in
// <LifecycleDir>\created-folders, named by the SHA-256 of the lower-case path.
// The record is write-once, so the lifecycle (DefenseClawEnterprise.psm1,
// Add-DefenseClawStandaloneCreatedFolderRecord) and the Go writers never race
// on it. A purge that leaves no deployment removes each recorded folder that
// is empty, deepest first, and never a folder it has no record of: one that
// existed before the install, or that holds anyone else's files, stays
// (Remove-DefenseClawStandaloneCreatedFolders). The record lives outside the
// state root so it outlives the purge of that root. Secure Client keeps no
// record.
const (
	windowsCreatedFolderRecordDirName = "created-folders"
	windowsCreatedFolderRecordSchema  = 1
	// Administrator-only, like the lifecycle directory it lives in.
	windowsCreatedFolderRecordSDDL  = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	windowsCreatedFolderRecordLimit = 4096
)

type windowsCreatedFolderRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Path          string `json:"path"`
	// Origin is "upgrade" on a record the lifecycle back-filled on a
	// computer installed before 1.0.9 (GAP-0704); the hooks never write
	// one, and no code here reads it: a record of either origin lets a purge
	// remove the folder once it is empty, which is all
	// RemoveWindowsCreatedFolderIfEmpty does with any record. The field
	// documents the on-disk schema for a reader that wires the records into
	// ownership (the g582 integrator), which must skip every record with an
	// origin (CLASS-g091-g582.md): such a record never gives ownership for a
	// repair, a re-stamp or a takeover.
	Origin string `json:"origin,omitempty"`
}

// windowsCreatedFolderRoots returns the trusted Program Files and ProgramData
// roots and the standalone lifecycle directory. Tests replace it.
var windowsCreatedFolderRoots = func() (programFiles, programData, lifecycleDir string, err error) {
	if programFiles, err = winpath.TrustedProgramFiles(); err != nil {
		return "", "", "", err
	}
	if programData, err = winpath.TrustedProgramData(); err != nil {
		return "", "", "", err
	}
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, programFiles, programData)
	if err != nil {
		return "", "", "", err
	}
	return programFiles, programData, roots.LifecycleDir, nil
}

// windowsCreatedFolderRecorder records folders a writer created; tests
// replace it.
var windowsCreatedFolderRecorder = recordWindowsCreatedFolders

// recordWindowsCreatedFolders records each folder in created that lies under
// ProgramData or Program Files, on the standalone profile only. It is best
// effort: a folder it cannot record is left in place by a purge, which is the
// safe side, so a recording failure never fails the write that created it.
func recordWindowsCreatedFolders(created []string) error {
	if len(created) == 0 || !windowsEnterpriseStandaloneProcess() {
		return nil
	}
	programFiles, programData, lifecycleDir, err := windowsCreatedFolderRoots()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve the created-folder record: %w", err)
	}
	var errs []error
	for _, path := range created {
		if !windowsCreatedFolderRecordable(path, programFiles, programData) {
			continue
		}
		if err := writeWindowsCreatedFolderRecord(lifecycleDir, path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// windowsCreatedFolderRecordable keeps machine vendor folders: an absolute
// path strictly below ProgramData or Program Files, outside DefenseClaw's own
// folders there (Cisco\DefenseClaw, Cisco\DefenseClaw-HookRuntime, ...). The
// purge removes those with the deployment, and the hooks remove the hook
// runtime folders at teardown, so a record of one would outlive its folder
// (GAP-0091 review 2 S1: a record goes with its folder).
func windowsCreatedFolderRecordable(path string, roots ...string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	path = filepath.Clean(path)
	for _, root := range roots {
		root = strings.TrimRight(filepath.Clean(strings.TrimSpace(root)), `\`)
		if root != "" && isWindowsManagedPolicyAncestorOf(root, path) {
			return !windowsDefenseClawOwnFolder(path, root)
		}
	}
	return false
}

// windowsDefenseClawOwnFolderName is the name of a DefenseClaw folder in
// the Cisco vendor folder: DefenseClaw or DefenseClaw-<letters>.
var windowsDefenseClawOwnFolderName = regexp.MustCompile(`(?i)^DefenseClaw(-[A-Za-z]+)?$`)

// windowsDefenseClawOwnFolder reports whether path is root\Cisco\DefenseClaw*
// or lies below one.
func windowsDefenseClawOwnFolder(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(relative, `\`)
	return len(parts) >= 2 && strings.EqualFold(parts[0], "Cisco") &&
		windowsDefenseClawOwnFolderName.MatchString(parts[1])
}

// windowsCreatedFolderRecordName is the record file name for path: the
// SHA-256 of its clean form with the ASCII letters A-Z in lower case. The
// lifecycle (Get-DefenseClawCreatedFolderRecordName) folds the same way;
// strings.ToLower and .NET ToLowerInvariant disagree on some other letters
// (U+0130 for one), so a full Unicode fold would let one side refuse the
// other's record.
func windowsCreatedFolderRecordName(path string) string {
	sum := sha256.Sum256([]byte(asciiLowerCase(filepath.Clean(path))))
	return hex.EncodeToString(sum[:]) + ".json"
}

// asciiLowerCase folds A-Z to a-z and leaves every other rune as it is.
func asciiLowerCase(value string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

func writeWindowsCreatedFolderRecord(lifecycleDir, path string) error {
	// The lifecycle creates its directory before any lifecycle run; a writer
	// never creates it (that would create ProgramData\Cisco unrecorded).
	if err := rejectWindowsReparseChain(lifecycleDir); err != nil {
		return err
	}
	if info, err := os.Lstat(lifecycleDir); err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return fmt.Errorf("enterprise hooks: created-folder record needs the lifecycle directory %s: %w", lifecycleDir, err)
	}
	if err := windowsManagedPolicyAncestorTrustCheck(lifecycleDir); err != nil {
		return fmt.Errorf("enterprise hooks: the lifecycle directory is untrusted, so %s is not recorded: %w", path, err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsCreatedFolderRecordSDDL)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	dir := filepath.Join(lifecycleDir, windowsCreatedFolderRecordDirName)
	dirPointer, err := winpath.UTF16Ptr(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(dirPointer, attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("enterprise hooks: create the created-folder record directory: %w", err)
	}
	if err := rejectWindowsReparseChain(dir); err != nil {
		return err
	}
	if err := windowsManagedPolicyAncestorTrustCheck(dir); err != nil {
		return fmt.Errorf("enterprise hooks: the created-folder record directory is untrusted: %w", err)
	}
	body, err := json.Marshal(windowsCreatedFolderRecord{
		SchemaVersion: windowsCreatedFolderRecordSchema,
		Path:          filepath.Clean(path),
	})
	if err != nil {
		return err
	}
	if len(body) > windowsCreatedFolderRecordLimit {
		return fmt.Errorf("enterprise hooks: created-folder record for %s is too large", path)
	}
	recordPath := filepath.Join(dir, windowsCreatedFolderRecordName(path))
	recordPointer, err := winpath.UTF16Ptr(recordPath)
	if err != nil {
		return err
	}
	// Write-once: the first writer's record stands.
	handle, err := windows.CreateFile(recordPointer, windows.GENERIC_WRITE, 0, attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: create the created-folder record for %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), recordPath)
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(recordPath)
		return fmt.Errorf("enterprise hooks: write the created-folder record for %s: %w", path, err)
	}
	return nil
}

// RemoveWindowsCreatedFolderIfEmpty removes path, and then its record, when
// DefenseClaw recorded creating it and it is an empty plain folder that
// SYSTEM, Administrators or TrustedInstaller own and alone can write, with no
// reparse point on its path (the purge's rule,
// Remove-DefenseClawStandaloneCreatedFolder). It reports whether path is gone
// now. An unrecorded folder, one that holds anything and any failed check
// leave the folder and its record; a missing folder leaves an unused record
// for the purge, which deletes it. It does not test the process's profile pin
// (GAP-0091 review 3 L2): its one caller is the standalone lifecycle's result
// handler in the CLI, which runs in a process that carries no
// DEFENSECLAW_ENTERPRISE_PROFILE (only the helpers it starts do), and
// windowsCreatedFolderRoots names the standalone lifecycle folder, as the
// caller's TrustedEnterpriseRoots(standalone) does. A Secure Client computer
// keeps no record, so nothing is removed there.
func RemoveWindowsCreatedFolderIfEmpty(path string) (bool, error) {
	if !filepath.IsAbs(path) {
		return false, nil
	}
	path = filepath.Clean(path)
	programFiles, programData, lifecycleDir, err := windowsCreatedFolderRoots()
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: resolve the created-folder record: %w", err)
	}
	if !windowsCreatedFolderRecordable(path, programFiles, programData) {
		return false, nil
	}
	dir := filepath.Join(lifecycleDir, windowsCreatedFolderRecordDirName)
	recordPath := filepath.Join(dir, windowsCreatedFolderRecordName(path))
	if recorded, err := readWindowsCreatedFolderRecord(dir, recordPath, path); err != nil || !recorded {
		return false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return false, fmt.Errorf("enterprise hooks: recorded folder %s is not a plain folder", path)
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		return false, err
	}
	for _, folder := range []string{path, filepath.Dir(path)} {
		if err := windowsManagedPolicyAncestorTrustCheck(folder); err != nil {
			return false, fmt.Errorf("enterprise hooks: recorded folder %s stays: %w", path, err)
		}
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
			return false, nil
		}
		return false, err
	}
	if err := os.Remove(recordPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("enterprise hooks: remove the record of %s: %w", path, err)
	}
	return true, nil
}

// readWindowsCreatedFolderRecord reports whether recordPath is a trusted
// record naming path: an administrator-only regular file in an
// administrator-only record folder, schema 1, naming path.
func readWindowsCreatedFolderRecord(dir, recordPath, path string) (bool, error) {
	if _, err := os.Lstat(recordPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	for _, check := range []func() error{
		func() error { return rejectWindowsReparseChain(recordPath) },
		func() error { return windowsManagedPolicyAncestorTrustCheck(dir) },
		func() error { return windowsManagedPolicyFileTrustCheck(recordPath) },
	} {
		if err := check(); err != nil {
			return false, fmt.Errorf("enterprise hooks: the created-folder record of %s is untrusted: %w", path, err)
		}
	}
	file, err := os.Open(recordPath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, windowsCreatedFolderRecordLimit+1))
	if err != nil {
		return false, err
	}
	var record windowsCreatedFolderRecord
	if len(body) > windowsCreatedFolderRecordLimit || json.Unmarshal(body, &record) != nil ||
		record.SchemaVersion != windowsCreatedFolderRecordSchema ||
		windowsCreatedFolderRecordName(record.Path) != windowsCreatedFolderRecordName(path) {
		return false, fmt.Errorf("enterprise hooks: the created-folder record of %s is not one", path)
	}
	return true, nil
}
