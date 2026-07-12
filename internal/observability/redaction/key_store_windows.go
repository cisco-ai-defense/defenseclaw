// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package redaction

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadOrCreateCorrelationKeyPlatform(dataDir string, entropy keyEntropyReader, hooks keyStoreHooks) (CorrelationKey, error) {
	if dataDir == "" {
		return CorrelationKey{}, keyStoreError(KeyStoreErrorInvalidDataDir)
	}
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		return CorrelationKey{}, keyStoreError(KeyStoreErrorInvalidDataDir)
	}
	directories, err := openWindowsCorrelationKeyDirectoryChain(absolute)
	if err != nil {
		return CorrelationKey{}, err
	}
	defer closeWindowsCorrelationKeyDirectories(directories)

	for attempt := 0; attempt < keyInstallAttempts; attempt++ {
		key, found, loadErr := loadExistingWindowsCorrelationKey(absolute, hooks)
		if loadErr != nil {
			return CorrelationKey{}, loadErr
		}
		if found {
			return key, nil
		}

		var material [hashV1KeySize]byte
		if _, err := io.ReadFull(entropy, material[:]); err != nil {
			return CorrelationKey{}, keyStoreError(KeyStoreErrorEntropy)
		}
		candidate := newCorrelationKey(material)
		installed, installErr := installWindowsCorrelationKey(absolute, candidate, entropy, hooks)
		if installErr != nil {
			return CorrelationKey{}, installErr
		}
		if installed {
			return candidate, nil
		}
		// Another same-user creator won MoveFileEx's no-replace race. Reload
		// through the same pinned-handle and protected-DACL checks.
	}
	return CorrelationKey{}, keyStoreError(KeyStoreErrorInstall)
}

func openWindowsCorrelationKeyDirectoryChain(path string) ([]windows.Handle, error) {
	chain := make([]string, 0, 8)
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
		chain[left], chain[right] = chain[right], chain[left]
	}
	handles := make([]windows.Handle, 0, len(chain))
	for _, element := range chain {
		handle, err := openWindowsCorrelationKeyDirectory(element)
		if err != nil {
			closeWindowsCorrelationKeyDirectories(handles)
			return nil, err
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func openWindowsCorrelationKeyDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, keyStoreError(KeyStoreErrorInvalidDataDir)
	}
	// Omitting FILE_SHARE_DELETE pins this path component. The caller retains a
	// handle for every ancestor, so later absolute-path operations cannot be
	// redirected by renaming any component after validation.
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, keyStoreError(KeyStoreErrorInvalidDataDir)
		}
		return 0, keyStoreError(KeyStoreErrorUnavailable)
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, keyStoreError(KeyStoreErrorUnavailable)
	}
	if details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return 0, keyStoreError(KeyStoreErrorInvalidDataDir)
	}
	// The key API, like the Unix openat implementation, does not require a
	// particular ACL shape on the caller-supplied data directory. The gateway's
	// audit-store bootstrap validates that boundary separately. Holding this
	// non-delete-shared handle pins the directory while the protected key leaf
	// enforces exact owner and confidentiality rules below.
	return handle, nil
}

func closeWindowsCorrelationKeyDirectories(handles []windows.Handle) {
	for index := len(handles) - 1; index >= 0; index-- {
		_ = windows.CloseHandle(handles[index])
	}
}

func loadExistingWindowsCorrelationKey(dataDir string, hooks keyStoreHooks) (CorrelationKey, bool, error) {
	path := filepath.Join(dataDir, correlationKeyFilename)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return CorrelationKey{}, false, nil
		case errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
			return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
		default:
			return CorrelationKey{}, false, classifyWindowsCorrelationOpenError(path, err)
		}
	}
	file := os.NewFile(uintptr(handle), correlationKeyFilename)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	defer func() { _ = file.Close() }()

	if err := validateWindowsCorrelationKeyHandle(handle); err != nil {
		return CorrelationKey{}, false, err
	}
	if err := runAfterExistingValidation(hooks); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	var material [hashV1KeySize]byte
	if _, err := io.ReadFull(file, material[:]); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorInvalidLength)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorInvalidLength)
	}
	if err := validateWindowsCorrelationKeyHandle(handle); err != nil {
		return CorrelationKey{}, false, err
	}
	return newCorrelationKey(material), true, nil
}

func classifyWindowsCorrelationOpenError(path string, openErr error) error {
	attributes, attributeErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if attributeErr == nil && attributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	if errors.Is(openErr, windows.ERROR_CANT_ACCESS_FILE) {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	return keyStoreError(KeyStoreErrorUnavailable)
}

func validateWindowsCorrelationKeyHandle(handle windows.Handle) error {
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	if details.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		details.NumberOfLinks != 1 {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	size := int64(details.FileSizeHigh)<<32 | int64(details.FileSizeLow)
	if size != hashV1KeySize {
		return keyStoreError(KeyStoreErrorInvalidLength)
	}
	return validateWindowsCorrelationSecurity(handle)
}

func validateWindowsCorrelationSecurity(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	if !owner.Equals(current.User.Sid) {
		return keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	return validateWindowsCorrelationACL(dacl, current.User.Sid)
}

func validateWindowsCorrelationACL(dacl *windows.ACL, currentUser *windows.SID) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return keyStoreError(KeyStoreErrorUnavailable)
		}
		if ace == nil || ace.Mask == 0 || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType,
			accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return keyStoreError(KeyStoreErrorUnsafePermissions)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windowsCorrelationTrustedPrincipal(sid, currentUser) {
			continue
		}
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	return nil
}

func windowsCorrelationTrustedPrincipal(sid, currentUser *windows.SID) bool {
	return sid != nil && (sid.Equals(currentUser) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func installWindowsCorrelationKey(dataDir string, candidate CorrelationKey, entropy keyEntropyReader, hooks keyStoreHooks) (bool, error) {
	var suffix [keyTempRandomBytes]byte
	if _, err := io.ReadFull(entropy, suffix[:]); err != nil {
		return false, keyStoreError(KeyStoreErrorEntropy)
	}
	tempPath := filepath.Join(dataDir, correlationKeyTempPrefix+hex.EncodeToString(suffix[:]))
	targetPath := filepath.Join(dataDir, correlationKeyFilename)
	file, err := createWindowsCorrelationTemp(tempPath)
	if err != nil {
		return false, err
	}
	tempPresent := true
	cleanup := func() {
		if !tempPresent {
			return
		}
		_ = os.Remove(tempPath)
		tempPresent = false
	}
	defer cleanup()
	closed := false
	closeTemp := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer func() { _ = closeTemp() }()

	material, ok := candidate.Material()
	if !ok {
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	if err := writeAll(file, material[:]); err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := file.Sync(); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	if err := closeTemp(); err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := runAfterTempSync(hooks); err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	to, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return false, nil
		}
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	tempPresent = false
	if err := runAfterLink(hooks); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	return true, nil
}

func createWindowsCorrelationTemp(path string) (*os.File, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + current.User.Sid.String() + "D:P(A;;FA;;;" + current.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)",
	)
	if err != nil {
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := validateWindowsCorrelationSecurity(handle); err != nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	return file, nil
}
