// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const managedTargetRuntimeStageAttempts = 128

// managedTargetRuntimeBeforePublish is a Windows-only test seam. The staged
// inode and its exact descriptor are already fixed when this hook is invoked.
var managedTargetRuntimeBeforePublish func(string) error

func writeManagedTargetRuntimeFilePlatform(path string, data []byte, replace bool) error {
	if len(data) > atomicTransformMaxConfigBytes {
		return fmt.Errorf(
			"managed target runtime file exceeds %d-byte limit",
			atomicTransformMaxConfigBytes,
		)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("managed target runtime path is not absolute")
	}
	name := filepath.Base(path)
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return fmt.Errorf("validate managed target runtime file name: %w", err)
	}
	target, err := windowsManagedTargetRuntimeSID()
	if err != nil {
		return err
	}
	descriptor, err := windowsManagedTargetRuntimeSecurityDescriptor(target)
	if err != nil {
		return fmt.Errorf("build managed target runtime descriptor: %w", err)
	}

	parent, err := bindAtomicTransformDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("bind managed target runtime directory: %w", err)
	}
	defer parent.Close()
	if err := parent.validate(); err != nil {
		return fmt.Errorf("validate managed target runtime directory: %w", err)
	}
	expectedData := data
	if expectedData == nil {
		// nil and an empty slice are the same file payload, but nil is reserved
		// below for the pre-write empty-stage check.
		expectedData = []byte{}
	}
	if replace && windowsManagedTargetRuntimeFileMatches(parent, name, target, expectedData) {
		return nil
	}

	stage, stageName, err := createWindowsManagedTargetRuntimeStage(
		parent.file,
		descriptor,
	)
	if err != nil {
		return err
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = deleteAtomicTransformHandle(windows.Handle(stage.Fd()))
		}
		_ = stage.Close()
	}()
	if err := validateWindowsManagedTargetRuntimeHandle(stage, target, nil); err != nil {
		return fmt.Errorf("validate empty managed target runtime stage: %w", err)
	}
	written, err := io.Copy(stage, bytes.NewReader(expectedData))
	if err != nil {
		return fmt.Errorf("write managed target runtime stage: %w", err)
	}
	if written != int64(len(expectedData)) {
		return fmt.Errorf(
			"write managed target runtime stage: wrote %d bytes, want %d",
			written,
			len(expectedData),
		)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync managed target runtime stage: %w", err)
	}
	if err := validateWindowsManagedTargetRuntimeHandle(stage, target, expectedData); err != nil {
		return fmt.Errorf("validate populated managed target runtime stage: %w", err)
	}
	stageIdentity, err := atomicTransformOpenFileIdentity(stage)
	if err != nil {
		return fmt.Errorf("capture managed target runtime stage identity: %w", err)
	}
	if managedTargetRuntimeBeforePublish != nil {
		if err := managedTargetRuntimeBeforePublish(path); err != nil {
			return err
		}
	}
	if err := parent.validate(); err != nil {
		return fmt.Errorf("revalidate managed target runtime directory: %w", err)
	}
	if err := renameAtomicTransformBoundFilePlatform(parent.file, stage, name, replace); err != nil {
		if !replace && errors.Is(err, errAtomicTransformConflict) {
			return fmt.Errorf("managed target runtime destination exists: %w", os.ErrExist)
		}
		return fmt.Errorf("publish managed target runtime stage %s: %w", stageName, err)
	}
	if err := validateWindowsManagedTargetRuntimeHandle(stage, target, expectedData); err != nil {
		return fmt.Errorf("validate published managed target runtime handle: %w", err)
	}
	publishedIdentity, err := atomicTransformOpenFileIdentity(stage)
	if err != nil {
		return fmt.Errorf("capture published managed target runtime identity: %w", err)
	}
	if publishedIdentity != stageIdentity {
		return fmt.Errorf("managed target runtime identity changed during publication")
	}
	named, err := openWindowsManagedTargetRuntimeFile(parent.file, name, true)
	if err != nil {
		return fmt.Errorf("open published managed target runtime name: %w", err)
	}
	namedIdentity, identityErr := atomicTransformOpenFileIdentity(named)
	validateErr := validateWindowsManagedTargetRuntimeHandle(named, target, expectedData)
	closeErr := named.Close()
	if identityErr != nil {
		return fmt.Errorf("capture named managed target runtime identity: %w", identityErr)
	}
	if namedIdentity != stageIdentity {
		return fmt.Errorf("managed target runtime name does not identify published stage")
	}
	if validateErr != nil {
		return fmt.Errorf("validate named managed target runtime file: %w", validateErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close named managed target runtime file: %w", closeErr)
	}
	if err := parent.validate(); err != nil {
		return fmt.Errorf("validate managed target runtime directory after publication: %w", err)
	}
	keepStage = true
	return nil
}

func windowsManagedTargetRuntimeSID() (*windows.SID, error) {
	target, err := windowsEffectiveUserSID()
	if err != nil || target == nil {
		return nil, fmt.Errorf("resolve authenticated effective target SID: %w", err)
	}
	if target.IsWellKnown(windows.WinLocalSystemSid) ||
		target.IsWellKnown(windows.WinLocalServiceSid) ||
		target.IsWellKnown(windows.WinNetworkServiceSid) ||
		target.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil, fmt.Errorf("effective Windows identity is not an interactive target user")
	}
	return target, nil
}

func windowsManagedTargetRuntimeSecurityDescriptor(
	target *windows.SID,
) (*windows.SECURITY_DESCRIPTOR, error) {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	entry := func(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	targetMask := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.GENERIC_WRITE |
			windows.GENERIC_EXECUTE |
			windows.DELETE,
	)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(ownerRights, windows.READ_CONTROL),
		entry(target, targetMask),
		entry(system, windows.GENERIC_ALL),
		entry(administrators, windows.GENERIC_ALL),
	}, nil)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := descriptor.SetOwner(target, false); err != nil {
		return nil, err
	}
	if err := descriptor.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	if err := descriptor.SetControl(
		windows.SE_DACL_PROTECTED,
		windows.SE_DACL_PROTECTED,
	); err != nil {
		return nil, err
	}
	return descriptor.ToSelfRelative()
}

func createWindowsManagedTargetRuntimeStage(
	parent *os.File,
	descriptor *windows.SECURITY_DESCRIPTOR,
) (*os.File, string, error) {
	for attempt := 0; attempt < managedTargetRuntimeStageAttempts; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate managed target runtime stage name: %w", err)
		}
		name := ".managed-runtime-stage-" + hex.EncodeToString(random[:])
		attributes, err := atomicTransformBoundObjectAttributes(parent, name, descriptor)
		if err != nil {
			return nil, "", err
		}
		var handle windows.Handle
		var status windows.IO_STATUS_BLOCK
		err = windows.NtCreateFile(
			&handle,
			windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|
				windows.READ_CONTROL|windows.SYNCHRONIZE,
			attributes,
			&status,
			nil,
			windows.FILE_ATTRIBUTE_NORMAL,
			windows.FILE_SHARE_READ,
			windows.FILE_CREATE,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
				windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
		)
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create managed target runtime stage: %w", err)
		}
		if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, "", fmt.Errorf("validate managed target runtime stage type: %w", err)
		}
		file := os.NewFile(uintptr(handle), name)
		if file == nil {
			_ = windows.CloseHandle(handle)
			return nil, "", fmt.Errorf("wrap managed target runtime stage handle")
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create managed target runtime stage: exhausted collision retries")
}

func openWindowsManagedTargetRuntimeFile(
	parent *os.File,
	name string,
	allowExistingStageAccess bool,
) (*os.File, error) {
	attributes, err := atomicTransformBoundObjectAttributes(parent, name, nil)
	if err != nil {
		return nil, err
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if allowExistingStageAccess {
		share |= windows.FILE_SHARE_DELETE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		share,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		return nil, os.ErrNotExist
	}
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
		return nil, fmt.Errorf("wrap managed target runtime file handle")
	}
	return file, nil
}

func windowsManagedTargetRuntimeFileMatches(
	parent *atomicTransformBoundDirectory,
	name string,
	target *windows.SID,
	data []byte,
) bool {
	file, err := openWindowsManagedTargetRuntimeFile(parent.file, name, false)
	if err != nil {
		return false
	}
	defer file.Close()
	return validateWindowsManagedTargetRuntimeHandle(file, target, data) == nil &&
		parent.validate() == nil
}

func validateWindowsManagedTargetRuntimeHandle(
	file *os.File,
	target *windows.SID,
	expectedData []byte,
) error {
	if file == nil || target == nil {
		return fmt.Errorf("managed target runtime handle or target SID is missing")
	}
	handle := windows.Handle(file.Fd())
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return fmt.Errorf("managed target runtime file type: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect managed target runtime identity: %w", err)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf(
			"managed target runtime file has %d hard links, want exactly 1",
			info.NumberOfLinks,
		)
	}
	if err := validateWindowsManagedTargetRuntimeProtection(handle, target); err != nil {
		return err
	}
	if expectedData == nil {
		if info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
			return fmt.Errorf("managed target runtime stage is not empty")
		}
		return validateWindowsManagedTargetRuntimeProtection(handle, target)
	}
	wantSize := int64(len(expectedData))
	if gotSize := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow); gotSize != wantSize {
		return fmt.Errorf(
			"managed target runtime size is %d bytes, want %d",
			gotSize,
			wantSize,
		)
	}
	current, err := io.ReadAll(io.NewSectionReader(file, 0, wantSize+1))
	if err != nil {
		return fmt.Errorf("read managed target runtime bytes: %w", err)
	}
	if !bytes.Equal(current, expectedData) {
		return fmt.Errorf("managed target runtime bytes do not match publication")
	}
	var after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &after); err != nil {
		return fmt.Errorf("reinspect managed target runtime identity: %w", err)
	}
	if after.NumberOfLinks != 1 || after.FileSizeHigh != info.FileSizeHigh ||
		after.FileSizeLow != info.FileSizeLow ||
		after.VolumeSerialNumber != info.VolumeSerialNumber ||
		after.FileIndexHigh != info.FileIndexHigh || after.FileIndexLow != info.FileIndexLow {
		return fmt.Errorf("managed target runtime identity changed while validating bytes")
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return fmt.Errorf("revalidate managed target runtime file type: %w", err)
	}
	return validateWindowsManagedTargetRuntimeProtection(handle, target)
}

func validateWindowsManagedTargetRuntimeProtection(
	handle windows.Handle,
	target *windows.SID,
) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect managed target runtime protection: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(target) {
		return fmt.Errorf("managed target runtime owner does not match effective target user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("managed target runtime DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("managed target runtime file has a null or unreadable DACL")
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	const fileAllAccess windows.ACCESS_MASK = 0x001f01ff
	expected := []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{sid: ownerRights, mask: windows.READ_CONTROL},
		{sid: target, mask: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE},
		{sid: system, mask: fileAllAccess},
		{sid: administrators, mask: fileAllAccess},
	}
	if int(dacl.AceCount) != len(expected) {
		return fmt.Errorf(
			"managed target runtime DACL has %d ACEs, want %d",
			dacl.AceCount,
			len(expected),
		)
	}
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("inspect managed target runtime ACE %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 {
			return fmt.Errorf(
				"managed target runtime DACL contains a noncanonical ACE at index %d",
				index,
			)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		match := -1
		for candidate, want := range expected {
			if !seen[candidate] && sid.Equals(want.sid) && ace.Mask == want.mask {
				match = candidate
				break
			}
		}
		if match < 0 {
			return fmt.Errorf(
				"managed target runtime DACL contains an unexpected or duplicate ACE",
			)
		}
		seen[match] = true
	}
	return nil
}
