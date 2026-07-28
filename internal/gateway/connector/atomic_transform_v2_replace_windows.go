// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var atomicTransformV2ReplaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

type atomicTransformV2ReplaceCode uint8

const (
	atomicTransformV2ReplaceSuccess atomicTransformV2ReplaceCode = iota
	atomicTransformV2ReplaceUnableToRemoveReplaced
	atomicTransformV2ReplaceUnableToMoveReplacement
	atomicTransformV2ReplaceUnableToMoveReplacement2
	atomicTransformV2ReplaceOtherFailure
)

func atomicTransformV2ReplaceCodeForError(err error) atomicTransformV2ReplaceCode {
	switch {
	case err == nil:
		return atomicTransformV2ReplaceSuccess
	case errors.Is(err, windows.ERROR_UNABLE_TO_REMOVE_REPLACED):
		return atomicTransformV2ReplaceUnableToRemoveReplaced
	case errors.Is(err, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT):
		return atomicTransformV2ReplaceUnableToMoveReplacement
	case errors.Is(err, windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2):
		return atomicTransformV2ReplaceUnableToMoveReplacement2
	default:
		return atomicTransformV2ReplaceOtherFailure
	}
}

func replaceAtomicTransformV2ExistingFile(targetPath, stagePath, backupPath string) error {
	target, err := winpath.UTF16Ptr(targetPath)
	if err != nil {
		return err
	}
	stage, err := winpath.UTF16Ptr(stagePath)
	if err != nil {
		return err
	}
	backup, err := winpath.UTF16Ptr(backupPath)
	if err != nil {
		return err
	}
	result, _, callErr := atomicTransformV2ReplaceFileW.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(stage)),
		uintptr(unsafe.Pointer(backup)),
		0, // REPLACEFILE_WRITE_THROUGH is documented as unsupported.
		0,
		0,
	)
	if result != 0 {
		return nil
	}
	if callErr == nil || callErr == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return callErr
}

// A ReplaceFileW return code is only a hint. Microsoft documents partial
// namespace transitions for 1177 and permits partial metadata merging for a
// generic error. Recovery therefore acts only on the exact identities and main
// stream bytes observed after the call.
type atomicTransformV2ReplaceObservation struct {
	Target          atomicTransformArtifactState
	Backup          atomicTransformArtifactState
	Stage           atomicTransformArtifactState
	PreservedDetail string
}

type atomicTransformV2ReplaceDisposition uint8

const (
	atomicTransformV2ReplaceAmbiguous atomicTransformV2ReplaceDisposition = iota
	atomicTransformV2ReplaceReadyForPublication
	atomicTransformV2ReplaceRetryUntouched
	atomicTransformV2ReplaceRestoreOldThenRetry
	atomicTransformV2ReplaceRetryForeignLive
)

func atomicTransformV2StageContentMatches(
	record atomicTransformV2Artifact, state atomicTransformArtifactState,
) bool {
	return state.exists && record.Identity != "" && state.identity == record.Identity &&
		state.digest == record.SHA256 && state.size == record.Size
}

func atomicTransformV2OldExactMatches(
	record atomicTransformV2Artifact, state atomicTransformArtifactState,
) bool {
	return atomicTransformV2StateMatches(record, state, true)
}

// ReplaceFileW can force ARCHIVE on the backup, so its raw/full metadata digest
// is not an exact copy of the pre-call Old witness. Authenticate the documented
// Old-owned composition plus exact inode/main/owner-group/DACL/times/link
// topology. The raw full protection digest is deliberately not required:
// canonical owner/group and DACL witnesses cover its semantic content without
// unstable optional SDDL component/provenance formatting.
func atomicTransformV2BackupOldMatches(
	record atomicTransformV2Artifact, state atomicTransformArtifactState,
) bool {
	return state.exists && record.Identity != "" && state.identity == record.Identity &&
		state.digest == record.SHA256 && state.size == record.Size &&
		state.info.Mode() == os.FileMode(record.Mode) &&
		record.OwnerGroupSHA256 != "" && state.ownerGroupDigest == record.OwnerGroupSHA256 &&
		record.PreservedMetadataSHA256 != "" &&
		state.preservedMetadataDigest == record.PreservedMetadataSHA256 &&
		record.CreationTime != 0 && state.creationTime == record.CreationTime &&
		record.LastWriteTime != 0 && state.lastWriteTime == record.LastWriteTime &&
		record.LinkCount == 1 && state.linkCount == 1
}

func classifyAtomicTransformV2ReplaceObservation(
	receipt atomicTransformV2Receipt, _ atomicTransformV2ReplaceCode,
	observed atomicTransformV2ReplaceObservation,
) atomicTransformV2ReplaceDisposition {
	targetOld := atomicTransformV2OldExactMatches(receipt.Old, observed.Target)
	targetStageContent := atomicTransformV2StageContentMatches(receipt.Stage, observed.Target)
	targetPublished := atomicTransformV2PublishedTargetMatches(receipt, observed.Target)
	backupOld := atomicTransformV2BackupOldMatches(receipt.Old, observed.Backup)
	stageExact := atomicTransformV2StateMatches(receipt.Stage, observed.Stage, true)
	stageRecordedContent := atomicTransformV2StageContentMatches(receipt.Stage, observed.Stage) &&
		receipt.Stage.OwnerGroupSHA256 != "" &&
		observed.Stage.ownerGroupDigest == receipt.Stage.OwnerGroupSHA256 &&
		receipt.Stage.LinkCount == 1 && observed.Stage.linkCount == 1

	// Normal success. ReplaceFileW preserves Old's metadata on the Stage file,
	// so the target matcher intentionally ignores mode/protection metadata.
	if targetPublished && backupOld && !observed.Stage.exists {
		return atomicTransformV2ReplaceReadyForPublication
	}
	// An exact Old backup with an absent live leaf can be restored safely only
	// while the other leaf is still the recorded, single-link Stage identity,
	// main stream, and owner/group. ReplaceFileW may have partially merged its
	// Old-owned metadata; a wholly foreign Stage is ambiguous and never authorizes
	// namespace mutation.
	if !observed.Target.exists && backupOld && stageRecordedContent {
		return atomicTransformV2ReplaceRestoreOldThenRetry
	}
	// 1175, 1176-with-backup, and generic errors retain both original names.
	// Only a completely exact Stage is retryable: metadata-only foreign edits
	// are ownership changes, not transaction-owned state.
	if targetOld && stageExact && !observed.Backup.exists {
		return atomicTransformV2ReplaceRetryUntouched
	}
	// A foreign writer won the validate-to-ReplaceFileW path window. If Stage is
	// still staged, its foreign live file is already authoritative and can be
	// retried without touching it.
	if observed.Target.exists && !targetOld && !targetStageContent &&
		!observed.Backup.exists && stageExact {
		return atomicTransformV2ReplaceRetryForeignLive
	}
	// Every other physical outcome is ambiguous. In particular, a consumed
	// Stage with a non-published target, or a non-Old backup, may reflect an
	// operator mutation concurrent with ReplaceFileW. Preserve all names and
	// inodes exactly as observed; a retry may not move, quarantine, or delete them.
	return atomicTransformV2ReplaceAmbiguous
}

func atomicTransformV2ReplaceObservationSummary(
	receipt atomicTransformV2Receipt, observed atomicTransformV2ReplaceObservation,
) string {
	return fmt.Sprintf(
		"target{exists=%t id=%q links=%d creation=%d write=%d stage_content=%t stage_owner_group=%t old_preserved=%t old_creation=%t published=%t} "+
			"backup{exists=%t id=%q links=%d creation=%d write=%d old_identity=%t old_content=%t old_protection=%t old_preserved=%t old_creation=%t old_write=%t old=%t} "+
			"stage{exists=%t id=%q links=%d creation=%d write=%d exact=%t} preserved_detail={%s}",
		observed.Target.exists, observed.Target.identity, observed.Target.linkCount,
		observed.Target.creationTime, observed.Target.lastWriteTime,
		atomicTransformV2StageContentMatches(receipt.Stage, observed.Target),
		receipt.Stage.OwnerGroupSHA256 != "" &&
			observed.Target.ownerGroupDigest == receipt.Stage.OwnerGroupSHA256,
		receipt.Old.PreservedMetadataSHA256 != "" &&
			observed.Target.preservedMetadataDigest == receipt.Old.PreservedMetadataSHA256,
		receipt.Old.CreationTime != 0 && observed.Target.creationTime == receipt.Old.CreationTime,
		atomicTransformV2PublishedTargetMatches(receipt, observed.Target),
		observed.Backup.exists, observed.Backup.identity, observed.Backup.linkCount,
		observed.Backup.creationTime, observed.Backup.lastWriteTime,
		receipt.Old.Identity != "" && observed.Backup.identity == receipt.Old.Identity,
		observed.Backup.digest == receipt.Old.SHA256 && observed.Backup.size == receipt.Old.Size,
		observed.Backup.protectionDigest == receipt.Old.ProtectionSHA256,
		receipt.Old.PreservedMetadataSHA256 != "" &&
			observed.Backup.preservedMetadataDigest == receipt.Old.PreservedMetadataSHA256,
		receipt.Old.CreationTime != 0 && observed.Backup.creationTime == receipt.Old.CreationTime,
		receipt.Old.LastWriteTime != 0 && observed.Backup.lastWriteTime == receipt.Old.LastWriteTime,
		atomicTransformV2BackupOldMatches(receipt.Old, observed.Backup),
		observed.Stage.exists, observed.Stage.identity, observed.Stage.linkCount,
		observed.Stage.creationTime, observed.Stage.lastWriteTime,
		atomicTransformV2StateMatches(receipt.Stage, observed.Stage, true),
		observed.PreservedDetail,
	)
}

func atomicTransformV2ReplacementPreservedDetail(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
	observed atomicTransformV2ReplaceObservation,
) string {
	readExact := func(name string, expected atomicTransformArtifactState) (
		atomicTransformV2WindowsMetadataWitness, bool,
	) {
		var witness atomicTransformV2WindowsMetadataWitness
		file, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
		if err != nil {
			return witness, false
		}
		defer file.Close()
		state, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
		// Intentionally do not compare protection/preserved/full metadata here:
		// one of those fields is exactly what this second held-handle read is
		// diagnosing. Still prove the same stable inode, main stream, owner/group,
		// timestamps, mode, and hard-link topology before reporting components.
		if err != nil || !state.exists || state.identity != expected.identity ||
			state.digest != expected.digest || state.size != expected.size ||
			state.info.Mode() != expected.info.Mode() ||
			state.ownerGroupDigest != expected.ownerGroupDigest ||
			state.creationTime != expected.creationTime ||
			state.lastWriteTime != expected.lastWriteTime ||
			state.linkCount != expected.linkCount {
			return witness, false
		}
		witness, err = atomicTransformV2WindowsMetadataFromOpen(file)
		return witness, err == nil
	}
	target, targetOK := readExact(filepath.Base(receipt.TargetPath), observed.Target)
	backup, backupOK := readExact(receipt.TombstoneName, observed.Backup)
	if !targetOK || !backupOK {
		return fmt.Sprintf("exact_witness_available=false target=%t backup=%t", targetOK, backupOK)
	}
	return atomicTransformV2WindowsPreservedComparison(target, backup)
}

func observeAtomicTransformV2Replacement(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
) (atomicTransformV2ReplaceObservation, error) {
	var observed atomicTransformV2ReplaceObservation
	var err error
	observed.Target, err = atomicTransformBoundInspect(
		dir, filepath.Base(receipt.TargetPath), atomicTransformMaxConfigBytes,
	)
	if err != nil {
		return observed, err
	}
	observed.Backup, err = atomicTransformBoundInspect(
		dir, receipt.TombstoneName, atomicTransformMaxConfigBytes,
	)
	if err != nil {
		return observed, err
	}
	observed.Stage, err = atomicTransformBoundInspect(
		dir, receipt.StageFinalName, atomicTransformMaxConfigBytes,
	)
	if err == nil && observed.Target.exists && observed.Backup.exists &&
		receipt.Old.PreservedMetadataSHA256 != "" &&
		observed.Target.preservedMetadataDigest != receipt.Old.PreservedMetadataSHA256 {
		observed.PreservedDetail = atomicTransformV2ReplacementPreservedDetail(dir, receipt, observed)
	}
	return observed, err
}

// repairAtomicTransformV2ReplacementDACL handles a narrow native
// ReplaceFileW normalization seen on Windows: the exact Stage inode is
// published and the exact Old inode is moved to the backup, but Old's protected
// explicit ACE is represented on the target as the same inherited ACE.  Only
// that one-way P/ID representation change is repairable. Every namespace,
// identity, content, owner/group, recorded creation-time, link, and non-DACL
// metadata witness is revalidated through bound handles before Old's exact
// DACL is restored. Any substantive ACL or metadata difference remains
// ambiguous.
func repairAtomicTransformV2ReplacementDACL(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
	observed atomicTransformV2ReplaceObservation,
	beforeDescriptor ...func(target, backup *os.File) error,
) (bool, error) {
	if len(beforeDescriptor) > 1 {
		return false, fmt.Errorf("multiple ReplaceFileW DACL repair test hooks")
	}
	if receipt.Old.PreservedMetadataSHA256 != "" &&
		observed.Target.preservedMetadataDigest == receipt.Old.PreservedMetadataSHA256 {
		return false, nil
	}
	if observed.Stage.exists || !atomicTransformV2BackupOldMatches(receipt.Old, observed.Backup) ||
		!atomicTransformV2StageContentMatches(receipt.Stage, observed.Target) ||
		receipt.Stage.OwnerGroupSHA256 == "" ||
		observed.Target.ownerGroupDigest != receipt.Stage.OwnerGroupSHA256 ||
		receipt.Stage.LinkCount != 1 || observed.Target.linkCount != 1 ||
		receipt.Old.CreationTime == 0 || observed.Target.creationTime != receipt.Old.CreationTime {
		return false, nil
	}

	targetName := filepath.Base(receipt.TargetPath)
	target, err := openAtomicTransformV2DACLRepairGuard(dir, targetName, true)
	if err != nil {
		return false, err
	}
	defer target.Close()
	backup, err := openAtomicTransformV2DACLRepairGuard(dir, receipt.TombstoneName, false)
	if err != nil {
		return false, err
	}
	defer backup.Close()

	targetState, err := atomicTransformBoundStateFromOpen(target, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(targetState, observed.Target) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return false, err
	}
	backupState, err := atomicTransformBoundStateFromOpen(
		backup, receipt.TombstoneName, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformArtifactStatesEqualExact(backupState, observed.Backup) ||
		!atomicTransformV2BackupOldMatches(receipt.Old, backupState) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return false, err
	}

	targetMetadata, err := atomicTransformV2WindowsMetadataFromOpen(target)
	if err != nil {
		return false, err
	}
	oldMetadata, err := atomicTransformV2WindowsMetadataFromOpen(backup)
	if err != nil {
		return false, err
	}
	if !atomicTransformV2WindowsPreservedMatchesExceptDACL(targetMetadata, oldMetadata) {
		return false, nil
	}
	normalized, err := atomicTransformV2WindowsDACLIsReplaceNormalization(
		targetMetadata.DACLCanonical, oldMetadata.DACLCanonical,
	)
	if err != nil {
		return false, err
	}
	if !normalized {
		return false, nil
	}
	if len(beforeDescriptor) == 1 && beforeDescriptor[0] != nil {
		if err := beforeDescriptor[0](target, backup); err != nil {
			return false, fmt.Errorf("before ReplaceFileW DACL repair descriptor: %w", err)
		}
	}

	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(backup.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, fmt.Errorf("read authenticated prior DACL: %w", err)
	}
	descriptorDACL, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(descriptor.String())
	if err != nil {
		return false, fmt.Errorf("canonicalize authenticated prior DACL: %w", err)
	}
	if descriptorDACL != oldMetadata.DACLCanonical {
		return false, fmt.Errorf("authenticated prior DACL changed before repair: %w", errAtomicTransformConflict)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false, fmt.Errorf("read authenticated prior DACL entries: %w", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return false, fmt.Errorf("read authenticated prior DACL control: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	currentTarget, err := atomicTransformV2WindowsDACLCanonicalFromOpen(target)
	if err != nil {
		return false, fmt.Errorf("revalidate normalized target DACL: %w", err)
	}
	if currentTarget != targetMetadata.DACLCanonical {
		return false, fmt.Errorf("normalized target DACL changed before repair: %w", errAtomicTransformConflict)
	}
	// Windows exposes no conditional SetSecurityInfo primitive. The bound file
	// lives under an ACL-validated directory and this final exact read narrows the
	// unavoidable syscall window; a substantive change observed before the call
	// is never overwritten.
	if err := windows.SetSecurityInfo(
		windows.Handle(target.Fd()), windows.SE_FILE_OBJECT, securityInformation,
		nil, nil, dacl, nil,
	); err != nil {
		return false, fmt.Errorf("restore authenticated prior DACL after ReplaceFileW: %w", err)
	}
	repaired, err := atomicTransformV2WindowsDACLCanonicalFromOpen(target)
	if err != nil {
		return false, err
	}
	if repaired != oldMetadata.DACLCanonical {
		return false, fmt.Errorf("restored ReplaceFileW DACL does not match authenticated prior DACL")
	}
	return true, nil
}

func openAtomicTransformV2DACLRepairGuard(
	dir *atomicTransformBoundDirectory, name string, writeDACL bool,
) (*os.File, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return nil, err
	}
	if err := dir.validate(); err != nil {
		return nil, err
	}
	attributes, err := atomicTransformBoundObjectAttributes(dir.file, name, nil)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if writeDACL {
		access |= windows.WRITE_DAC
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, access, attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap exact ReplaceFileW DACL repair guard for %s", name)
	}
	return file, nil
}

type atomicTransformV2ReplaceInvoker func(targetPath, stagePath, backupPath string) error

// atomicTransformV2PrePublicationTestHook is an unexported, path-scoped test
// seam. A hook runs after ReplaceFileW has the expected physical composition,
// but before exact flush, directory sync, short-name repair, and durable P.
// Exact target and backup handles are re-opened and revalidated before the hook
// receives them; production never installs a hook.
type atomicTransformV2PrePublicationTestHook func(
	dir *atomicTransformBoundDirectory, target, backup *os.File,
	receipt atomicTransformV2Receipt,
) error

var atomicTransformV2PrePublicationTestState = struct {
	sync.RWMutex
	byPath map[string]atomicTransformV2PrePublicationTestHook
}{byPath: make(map[string]atomicTransformV2PrePublicationTestHook)}

func installAtomicTransformV2PrePublicationHookForTest(
	path string, hook atomicTransformV2PrePublicationTestHook,
) func() {
	if hook == nil {
		panic("install nil atomic Transform V2 pre-publication test hook")
	}
	key := filepath.Clean(path)
	atomicTransformV2PrePublicationTestState.Lock()
	previous := atomicTransformV2PrePublicationTestState.byPath[key]
	atomicTransformV2PrePublicationTestState.byPath[key] = hook
	atomicTransformV2PrePublicationTestState.Unlock()
	return func() {
		atomicTransformV2PrePublicationTestState.Lock()
		defer atomicTransformV2PrePublicationTestState.Unlock()
		if previous == nil {
			delete(atomicTransformV2PrePublicationTestState.byPath, key)
			return
		}
		atomicTransformV2PrePublicationTestState.byPath[key] = previous
	}
}

func runAtomicTransformV2PrePublicationHookForTest(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
	observed atomicTransformV2ReplaceObservation,
) error {
	key := filepath.Clean(receipt.TargetPath)
	atomicTransformV2PrePublicationTestState.RLock()
	hook := atomicTransformV2PrePublicationTestState.byPath[key]
	atomicTransformV2PrePublicationTestState.RUnlock()
	if hook == nil {
		return nil
	}
	targetName := filepath.Base(receipt.TargetPath)
	target, err := openAtomicTransformV2ReplaceGuard(dir, targetName, true)
	if err != nil {
		return err
	}
	defer target.Close()
	targetState, err := atomicTransformBoundStateFromOpen(
		target, targetName, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformArtifactStatesEqualExact(targetState, observed.Target) {
		if err == nil {
			err = fmt.Errorf("pre-publication test target changed before exact hook")
		}
		return err
	}
	backup, err := openAtomicTransformV2ReplaceGuard(dir, receipt.TombstoneName, true)
	if err != nil {
		return err
	}
	defer backup.Close()
	backupState, err := atomicTransformBoundStateFromOpen(
		backup, receipt.TombstoneName, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformArtifactStatesEqualExact(backupState, observed.Backup) {
		if err == nil {
			err = fmt.Errorf("pre-publication test backup changed before exact hook")
		}
		return err
	}
	return hook(dir, target, backup, receipt)
}

type atomicTransformV2ReplaceAttempt struct {
	Code        atomicTransformV2ReplaceCode
	CallError   error
	Observed    atomicTransformV2ReplaceObservation
	Disposition atomicTransformV2ReplaceDisposition
}

type atomicTransformV2ReplaceProgress func(boundary string) error

func reportAtomicTransformV2ReplaceProgress(
	progress []atomicTransformV2ReplaceProgress, boundary string,
) error {
	if len(progress) == 0 || progress[0] == nil {
		return nil
	}
	return progress[0](boundary)
}

func firstAtomicTransformV2ReplaceProgress(
	progress []atomicTransformV2ReplaceProgress,
) atomicTransformV2ReplaceProgress {
	if len(progress) == 0 {
		return nil
	}
	return progress[0]
}

const (
	atomicTransformV2ReplaceBoundaryBeforeTargetFlush   = "before-target-flush"
	atomicTransformV2ReplaceBoundaryAfterTargetFlush    = "after-target-flush"
	atomicTransformV2ReplaceBoundaryBeforeBackupFlush   = "before-backup-flush"
	atomicTransformV2ReplaceBoundaryAfterBackupFlush    = "after-backup-flush"
	atomicTransformV2ReplaceBoundaryBeforeDirectorySync = "before-directory-sync"
	atomicTransformV2ReplaceBoundaryAfterDirectorySync  = "after-directory-sync"
	atomicTransformV2ReplaceBoundaryBefore1177Restore   = "before-1177-old-restore"
	atomicTransformV2ReplaceBoundary1177OldRestored     = "1177-old-restored"
)

func openAtomicTransformV2ReplaceGuard(
	dir *atomicTransformBoundDirectory, name string, write bool,
) (*os.File, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return nil, err
	}
	if err := dir.validate(); err != nil {
		return nil, err
	}
	attributes, err := atomicTransformBoundObjectAttributes(dir.file, name, nil)
	if err != nil {
		return nil, err
	}
	// ReplaceFileW takes internal opens that conflict with a GENERIC_READ gate.
	// A minimal attribute/ACL/identity handle with all sharing modes remains
	// compatible while pinning the exact inode across the path-based call.
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if write {
		access |= windows.GENERIC_READ | windows.GENERIC_WRITE | windows.DELETE
		share = windows.FILE_SHARE_READ
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, access, attributes, &status, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH,
		0, 0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap exact ReplaceFileW guard for %s", name)
	}
	return file, nil
}

// invokeAtomicTransformV2Replacement is deliberately injectable. Tests use the
// seam to reproduce all documented partial errors and the otherwise tiny
// validate-to-ReplaceFileW target-swap window deterministically.
func invokeAtomicTransformV2Replacement(
	dir *atomicTransformBoundDirectory,
	receipt atomicTransformV2Receipt,
	invoke atomicTransformV2ReplaceInvoker,
) (atomicTransformV2ReplaceAttempt, error) {
	var attempt atomicTransformV2ReplaceAttempt
	if invoke == nil {
		invoke = replaceAtomicTransformV2ExistingFile
	}
	if err := dir.validate(); err != nil {
		return attempt, err
	}
	targetName := filepath.Base(receipt.TargetPath)
	target, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2OldExactMatches(receipt.Old, target) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return attempt, err
	}
	targetGuard, err := openAtomicTransformV2ReplaceGuard(dir, targetName, false)
	if err != nil {
		return attempt, errAtomicTransformConflict
	}
	defer targetGuard.Close()
	targetGuardID, err := atomicTransformOpenFileIdentity(targetGuard)
	if err != nil || targetGuardID != target.identity {
		return attempt, errAtomicTransformConflict
	}
	targetShortName, err := atomicTransformV2WindowsShortNameFromOpen(targetGuard)
	if err != nil || !strings.EqualFold(targetShortName, receipt.TargetShortName) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return attempt, fmt.Errorf("existing target short-name binding changed before ReplaceFileW: %w", err)
	}
	stage, err := atomicTransformBoundInspectFilePrivate(
		dir, receipt.StageFinalName, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformV2StateMatches(receipt.Stage, stage, true) {
		if err == nil {
			err = fmt.Errorf("prepared stage changed before ReplaceFileW publication")
		}
		return attempt, err
	}
	stageGuard, err := openAtomicTransformV2ReplaceGuard(dir, receipt.StageFinalName, false)
	if err != nil {
		return attempt, err
	}
	defer stageGuard.Close()
	if err := validateAtomicTransformBoundFilePrivatePlatform(stageGuard); err != nil {
		return attempt, err
	}
	stageGuardID, err := atomicTransformOpenFileIdentity(stageGuard)
	if err != nil || stageGuardID != stage.identity || stageGuardID != receipt.Stage.Identity {
		return attempt, errAtomicTransformConflict
	}
	stageShortName, err := atomicTransformV2WindowsShortNameFromOpen(stageGuard)
	if err != nil || !strings.EqualFold(stageShortName, receipt.StageShortName) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return attempt, fmt.Errorf("ready-stage short-name binding changed before ReplaceFileW: %w", err)
	}
	backup, err := atomicTransformBoundInspect(dir, receipt.TombstoneName, atomicTransformMaxConfigBytes)
	if err != nil {
		return attempt, err
	}
	if backup.exists {
		return attempt, fmt.Errorf("ReplaceFileW backup slot is already occupied")
	}
	if err := dir.validate(); err != nil {
		return attempt, err
	}
	namedTarget, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(namedTarget, target) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return attempt, err
	}
	namedStage, err := atomicTransformBoundInspectFilePrivate(
		dir, receipt.StageFinalName, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformArtifactStatesEqualExact(namedStage, stage) {
		if err == nil {
			err = errAtomicTransformConflict
		}
		return attempt, err
	}
	targetPath := filepath.Join(dir.path, targetName)
	if !atomicTransformPathsEqual(targetPath, receipt.TargetPath) {
		return attempt, fmt.Errorf("ReplaceFileW target is not the bound canonical leaf")
	}
	stagePath := filepath.Join(dir.path, receipt.StageFinalName)
	backupPath := filepath.Join(dir.path, receipt.TombstoneName)
	attempt.CallError = invoke(targetPath, stagePath, backupPath)
	attempt.Code = atomicTransformV2ReplaceCodeForError(attempt.CallError)
	attempt.Observed, err = observeAtomicTransformV2Replacement(dir, receipt)
	if err != nil {
		return attempt, err
	}
	// The path-based API may have consumed a foreign file installed at the Stage
	// name after final validation. The held minimal gate pins the intended Stage
	// inode; only that identity can ever become ready for durable publication.
	gateID, gateErr := atomicTransformOpenFileIdentity(stageGuard)
	if gateErr != nil {
		return attempt, fmt.Errorf("revalidate held ReplaceFileW Stage identity: %w", gateErr)
	}
	if gateID != receipt.Stage.Identity {
		return attempt, fmt.Errorf("held ReplaceFileW Stage identity changed")
	}
	if repaired, repairErr := repairAtomicTransformV2ReplacementDACL(
		dir, receipt, attempt.Observed,
	); repairErr != nil {
		return attempt, repairErr
	} else if repaired {
		attempt.Observed, err = observeAtomicTransformV2Replacement(dir, receipt)
		if err != nil {
			return attempt, err
		}
	}
	attempt.Disposition = classifyAtomicTransformV2ReplaceObservation(receipt, attempt.Code, attempt.Observed)
	if attempt.Disposition == atomicTransformV2ReplaceReadyForPublication {
		if err := runAtomicTransformV2PrePublicationHookForTest(
			dir, receipt, attempt.Observed,
		); err != nil {
			return attempt, fmt.Errorf("pre-publication test hook: %w", err)
		}
	}
	return attempt, nil
}

func flushAtomicTransformV2ReplaceArtifact(
	dir *atomicTransformBoundDirectory, name string, expected atomicTransformArtifactState,
	before, after string, progress atomicTransformV2ReplaceProgress,
) error {
	file, err := openAtomicTransformV2ReplaceGuard(dir, name, true)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(current, expected) {
		if err == nil {
			err = fmt.Errorf("ReplaceFileW flush target changed: %s", name)
		}
		return err
	}
	if progress != nil {
		if err := progress(before); err != nil {
			return err
		}
	}
	current, err = atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(current, expected) {
		if err == nil {
			err = fmt.Errorf("ReplaceFileW flush target changed at boundary: %s", name)
		}
		return err
	}
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("flush exact ReplaceFileW artifact %s: %w", name, err)
	}
	if progress != nil {
		if err := progress(after); err != nil {
			return err
		}
	}
	return nil
}

func flushAtomicTransformV2ReplacementForPublication(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
	observed atomicTransformV2ReplaceObservation, progress ...atomicTransformV2ReplaceProgress,
) error {
	if classifyAtomicTransformV2ReplaceObservation(
		receipt, atomicTransformV2ReplaceSuccess, observed,
	) != atomicTransformV2ReplaceReadyForPublication {
		return fmt.Errorf("refusing to flush a non-publication-ready ReplaceFileW outcome")
	}
	if err := flushAtomicTransformV2ReplaceArtifact(
		dir, filepath.Base(receipt.TargetPath), observed.Target,
		atomicTransformV2ReplaceBoundaryBeforeTargetFlush,
		atomicTransformV2ReplaceBoundaryAfterTargetFlush, firstAtomicTransformV2ReplaceProgress(progress),
	); err != nil {
		return err
	}
	if err := flushAtomicTransformV2ReplaceArtifact(
		dir, receipt.TombstoneName, observed.Backup,
		atomicTransformV2ReplaceBoundaryBeforeBackupFlush,
		atomicTransformV2ReplaceBoundaryAfterBackupFlush, firstAtomicTransformV2ReplaceProgress(progress),
	); err != nil {
		return err
	}
	if err := reportAtomicTransformV2ReplaceProgress(
		progress, atomicTransformV2ReplaceBoundaryBeforeDirectorySync,
	); err != nil {
		return err
	}
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return fmt.Errorf("sync ReplaceFileW parent directory: %w", err)
	}
	if err := reportAtomicTransformV2ReplaceProgress(
		progress, atomicTransformV2ReplaceBoundaryAfterDirectorySync,
	); err != nil {
		return err
	}
	after, err := observeAtomicTransformV2Replacement(dir, receipt)
	if err != nil || classifyAtomicTransformV2ReplaceObservation(
		receipt, atomicTransformV2ReplaceSuccess, after,
	) != atomicTransformV2ReplaceReadyForPublication {
		if err == nil {
			err = fmt.Errorf("ReplaceFileW outcome changed after durability barriers")
		}
		return err
	}
	return nil
}

// restoreAtomicTransformV2Replace1177 handles Microsoft's documented 1177
// namespace: live is absent, exact Old is at the backup name, and Stage remains
// staged (possibly with Old's metadata merged into it). The no-replace rename
// is made through an exact opened backup handle; an editor recreating live wins
// and the transaction remains fail-closed.
func restoreAtomicTransformV2Replace1177(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
	observed atomicTransformV2ReplaceObservation, progress ...atomicTransformV2ReplaceProgress,
) error {
	if classifyAtomicTransformV2ReplaceObservation(
		receipt, atomicTransformV2ReplaceUnableToMoveReplacement2, observed,
	) != atomicTransformV2ReplaceRestoreOldThenRetry {
		return fmt.Errorf("ReplaceFileW 1177 rollback state changed: %w", errAtomicTransformConflict)
	}
	if err := reportAtomicTransformV2ReplaceProgress(
		progress, atomicTransformV2ReplaceBoundaryBefore1177Restore,
	); err != nil {
		return err
	}
	_, err := atomicTransformBoundRenameNoReplace(
		dir, receipt.TombstoneName, filepath.Base(receipt.TargetPath), observed.Backup,
	)
	if err != nil {
		return fmt.Errorf("restore exact prior config after ReplaceFileW 1177: %w", err)
	}
	return reportAtomicTransformV2ReplaceProgress(progress, atomicTransformV2ReplaceBoundary1177OldRestored)
}

// convergeAtomicTransformV2ExistingProtection runs before the snapshot and Ra
// receipt are created. This guarantees that a requested private replacement
// can inherit only a safe DACL while keeping already-safe custom DACLs intact.
// The caller restarts the attempt after changed=true so all receipt witnesses
// describe the converged object.
func convergeAtomicTransformV2ExistingProtection(
	path string, requested os.FileMode, snapshot atomicFileSnapshot,
) (bool, error) {
	if requested.Perm()&0o077 != 0 {
		return false, nil
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir, err := bindAtomicTransformDirectory(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	name := filepath.Base(path)
	attributes, err := atomicTransformBoundObjectAttributes(dir.file, name, nil)
	if err != nil {
		return false, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.SYNCHRONIZE,
		attributes, &status, nil, 0, windows.FILE_SHARE_READ, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH,
		0, 0,
	)
	if err != nil {
		return false, fmt.Errorf("open exact config for protection convergence: %w", err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return false, fmt.Errorf("wrap existing config protection handle")
	}
	defer file.Close()
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return false, err
	}
	before, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, err
	}
	if !atomicTransformSnapshotMatchesState(snapshot, before) {
		return false, errAtomicTransformConflict
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err == nil {
		return false, nil
	}
	current, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	owner, _, err := current.Owner()
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("resolve current user while converging config protection: %w", err)
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return false, fmt.Errorf("refusing to rewrite protection on a config not owned by the current user")
	}
	private, err := atomicTransformPrivateSecurityDescriptor()
	if err != nil {
		return false, err
	}
	privateDACL, _, err := private.DACL()
	if err != nil || privateDACL == nil {
		return false, fmt.Errorf("construct private config DACL: %w", err)
	}
	if err := windows.SetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, privateDACL, nil,
	); err != nil {
		return false, fmt.Errorf("set exact config private protection: %w", err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return false, fmt.Errorf("flush exact config protection convergence: %w", err)
	}
	after, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, err
	}
	if before.identity != after.identity || before.digest != after.digest || before.size != after.size {
		return false, fmt.Errorf("config changed identity or contents while converging protection")
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return false, fmt.Errorf("validate converged private config protection: %w", err)
	}
	named, err := atomicTransformBoundInspect(dir, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, err
	}
	if !atomicTransformArtifactStatesEqualExact(named, after) {
		return false, fmt.Errorf("config name changed after handle-bound protection convergence")
	}
	return before.protectionDigest != after.protectionDigest, nil
}
