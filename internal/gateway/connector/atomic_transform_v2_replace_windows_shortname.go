// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	atomicTransformV2FileAlternateNameInformation      = uint32(21)
	atomicTransformV2ReplaceBoundaryBackupShortCleared = "backup-short-name-cleared"
	atomicTransformV2ReplaceBoundaryTargetShortSet     = "target-short-name-set"
	atomicTransformV2ReplaceBoundaryShortFlushed       = "short-name-flushed-and-verified"
)

func atomicTransformV2WindowsShortNameFromOpen(file *os.File) (string, error) {
	// FILE_SHORT_NAME_INFORMATION is ULONG byte length followed by the UTF-16
	// leaf. A DOS 8.3 leaf is tiny; the larger buffer makes malformed kernel or
	// filesystem responses fail closed without a retry-by-path.
	buffer := make([]byte, 4+1024)
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtQueryInformationFile(
		windows.Handle(file.Fd()), &status, &buffer[0], uint32(len(buffer)),
		atomicTransformV2FileAlternateNameInformation,
	); err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
			return "", nil
		}
		return "", fmt.Errorf("query exact Windows short name: %w", err)
	}
	length := binary.LittleEndian.Uint32(buffer[:4])
	if length == 0 {
		return "", nil
	}
	if length%2 != 0 || int(length) > len(buffer)-4 {
		return "", fmt.Errorf("invalid exact Windows short-name length %d", length)
	}
	units := make([]uint16, int(length)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(buffer[4+index*2:])
	}
	name := strings.ToUpper(string(utf16.Decode(units)))
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return "", fmt.Errorf("invalid exact Windows short name: %w", err)
	}
	return name, nil
}

func setAtomicTransformV2WindowsShortNameOnOpen(file *os.File, name string) error {
	if name != "" {
		name = strings.ToUpper(name)
		if err := validateAtomicTransformBoundLeaf(name); err != nil {
			return err
		}
	}
	units := utf16.Encode([]rune(name))
	if len(units) > 12 {
		return fmt.Errorf("Windows short name exceeds 12 UTF-16 code units")
	}
	// FILE_SHORT_NAME_INFORMATION has a fixed WCHAR ShortName[12] member;
	// NtSetInformationFile rejects a variable/zero-length record.
	buffer := make([]byte, 4+12*2)
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(units)*2))
	for index, unit := range units {
		binary.LittleEndian.PutUint16(buffer[4+index*2:], unit)
	}
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(
		windows.Handle(file.Fd()), &status, &buffer[0], uint32(len(buffer)),
		windows.FileShortNameInformation,
	); err != nil {
		return fmt.Errorf("set exact Windows short name %q: %w", name, err)
	}
	return nil
}

func atomicTransformV2ShortNameExpectedState(
	state atomicTransformArtifactState, expected atomicTransformArtifactState,
) bool {
	return state.exists && expected.exists && atomicTransformArtifactStatesEqualExact(state, expected)
}

// repairAtomicTransformV2ReplacementShortName idempotently moves the recorded
// Old DOS leaf from the exact backup inode to exact New (commit), or verifies it
// on restored Old (abort). An empty recorded Old leaf is also exact state: only
// the recorded Stage leaf may be cleared from exact New. A foreign occupant or
// unrecorded alias is never cleared or replaced.
func repairAtomicTransformV2ReplacementShortName(
	dir *atomicTransformBoundDirectory,
	targetName, backupName, shortName, stageShortName string,
	targetExpected, backupExpected atomicTransformArtifactState,
	progress ...atomicTransformV2ReplaceProgress,
) error {
	shortName = strings.ToUpper(shortName)
	stageShortName = strings.ToUpper(stageShortName)
	if shortName != "" {
		if err := validateAtomicTransformBoundLeaf(shortName); err != nil {
			return err
		}
	}
	if atomicTransformPathsEqual(shortName, targetName) {
		return nil
	}
	if err := dir.validate(); err != nil {
		return err
	}
	var alias atomicTransformArtifactState
	var err error
	if shortName != "" {
		alias, err = atomicTransformBoundInspect(dir, shortName, atomicTransformMaxConfigBytes)
		if err != nil {
			return err
		}
		if alias.exists && !atomicTransformV2ShortNameExpectedState(alias, targetExpected) &&
			!atomicTransformV2ShortNameExpectedState(alias, backupExpected) {
			return fmt.Errorf("recorded Windows short name is occupied by a foreign inode: %s", shortName)
		}
	}

	if shortName != "" && alias.exists && atomicTransformV2ShortNameExpectedState(alias, backupExpected) {
		backup, err := openAtomicTransformV2ReplaceGuard(dir, backupName, true)
		if err != nil {
			return err
		}
		backupState, stateErr := atomicTransformBoundStateFromOpen(
			backup, backupName, atomicTransformMaxConfigBytes,
		)
		if stateErr != nil || !atomicTransformV2ShortNameExpectedState(backupState, backupExpected) {
			_ = backup.Close()
			if stateErr == nil {
				stateErr = fmt.Errorf("short-name backup inode changed")
			}
			return stateErr
		}
		currentShort, queryErr := atomicTransformV2WindowsShortNameFromOpen(backup)
		if queryErr != nil || !atomicTransformPathsEqual(currentShort, shortName) {
			_ = backup.Close()
			if queryErr == nil {
				queryErr = fmt.Errorf("recorded short alias does not match exact backup short name")
			}
			return queryErr
		}
		if err := setAtomicTransformV2WindowsShortNameOnOpen(backup, ""); err != nil {
			_ = backup.Close()
			return err
		}
		if err := reportAtomicTransformV2ReplaceProgress(
			progress, atomicTransformV2ReplaceBoundaryBackupShortCleared,
		); err != nil {
			_ = backup.Close()
			return err
		}
		if err := windows.FlushFileBuffers(windows.Handle(backup.Fd())); err != nil {
			_ = backup.Close()
			return fmt.Errorf("flush cleared backup short name: %w", err)
		}
		if err := backup.Close(); err != nil {
			return err
		}
	}

	target, err := openAtomicTransformV2ReplaceGuard(dir, targetName, true)
	if err != nil {
		return err
	}
	defer target.Close()
	targetState, err := atomicTransformBoundStateFromOpen(target, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2ShortNameExpectedState(targetState, targetExpected) {
		if err == nil {
			err = fmt.Errorf("short-name target inode changed")
		}
		return err
	}
	currentShort, err := atomicTransformV2WindowsShortNameFromOpen(target)
	if err != nil {
		return err
	}
	if !atomicTransformPathsEqual(currentShort, shortName) {
		if currentShort != "" && (stageShortName == "" ||
			!atomicTransformPathsEqual(currentShort, stageShortName)) {
			// Only the exact Stage alias recorded in Rp is transaction-owned.
			// Replacing any other alias could make an operator locator disappear.
			return fmt.Errorf("exact target already has a different Windows short name %q", currentShort)
		}
		if err := setAtomicTransformV2WindowsShortNameOnOpen(target, shortName); err != nil {
			return err
		}
		if err := reportAtomicTransformV2ReplaceProgress(
			progress, atomicTransformV2ReplaceBoundaryTargetShortSet,
		); err != nil {
			return err
		}
	}
	if err := windows.FlushFileBuffers(windows.Handle(target.Fd())); err != nil {
		return fmt.Errorf("flush exact target short name: %w", err)
	}
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return fmt.Errorf("sync target directory after short-name repair: %w", err)
	}
	verifiedShort, err := atomicTransformV2WindowsShortNameFromOpen(target)
	if err != nil || !atomicTransformPathsEqual(verifiedShort, shortName) {
		if err == nil {
			err = fmt.Errorf("exact target short-name verification failed")
		}
		return err
	}
	if shortName != "" {
		verifiedAlias, err := atomicTransformBoundInspect(dir, shortName, atomicTransformMaxConfigBytes)
		if err != nil || !atomicTransformV2ShortNameExpectedState(verifiedAlias, targetExpected) {
			if err == nil {
				err = fmt.Errorf("recorded short alias does not resolve to exact target inode")
			}
			return err
		}
	}
	if err := reportAtomicTransformV2ReplaceProgress(
		progress, atomicTransformV2ReplaceBoundaryShortFlushed,
	); err != nil {
		return err
	}
	return nil
}

func atomicTransformV2CaptureWindowsShortName(
	dir *atomicTransformBoundDirectory, targetName string,
	expected atomicTransformArtifactState,
) (string, error) {
	file, err := openAtomicTransformV2ReplaceGuard(dir, filepath.Base(targetName), false)
	if err != nil {
		return "", err
	}
	defer file.Close()
	identity, err := atomicTransformOpenFileIdentity(file)
	if err != nil || identity != expected.identity {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return "", err
	}
	named, err := atomicTransformBoundInspect(dir, filepath.Base(targetName), atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(named, expected) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return "", err
	}
	return atomicTransformV2WindowsShortNameFromOpen(file)
}
