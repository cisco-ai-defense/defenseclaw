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
	"os"
	"path/filepath"
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
// path strictly below ProgramData or Program Files.
func windowsCreatedFolderRecordable(path string, roots ...string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	path = filepath.Clean(path)
	for _, root := range roots {
		root = strings.TrimRight(filepath.Clean(strings.TrimSpace(root)), `\`)
		if root != "" && isWindowsManagedPolicyAncestorOf(root, path) {
			return true
		}
	}
	return false
}

// windowsCreatedFolderRecordName is the record file name for path: the
// SHA-256 of its lower-case clean form. The lifecycle computes the same name.
func windowsCreatedFolderRecordName(path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return hex.EncodeToString(sum[:]) + ".json"
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
