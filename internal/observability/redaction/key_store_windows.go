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
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

const (
	windowsCorrelationFileAllAccess   windows.ACCESS_MASK = 0x001f01ff
	windowsCorrelationFileGenericRead windows.ACCESS_MASK = 0x00120089
)

var windowsCorrelationServiceAccountSID = managed.WindowsServiceAccountSID

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
		installed, installErr := installWindowsCorrelationKey(
			absolute,
			directories[len(directories)-1],
			candidate,
			entropy,
			hooks,
		)
		if installErr != nil {
			return CorrelationKey{}, installErr
		}
		if installed {
			return candidate, nil
		}
		// Another same-service creator won the handle-bound no-replace race. Reload
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
	for index, element := range chain {
		handle, err := openWindowsCorrelationKeyDirectory(element, index == len(chain)-1)
		if err != nil {
			closeWindowsCorrelationKeyDirectories(handles)
			return nil, err
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func openWindowsCorrelationKeyDirectory(path string, publicationRoot bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, keyStoreError(KeyStoreErrorInvalidDataDir)
	}
	// Omitting FILE_SHARE_DELETE pins this path component. The caller retains a
	// handle for every ancestor, so later absolute-path operations cannot be
	// redirected by renaming any component after validation.
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	if publicationRoot {
		// FILE_RENAME_INFO resolves the fixed destination name relative to this
		// pinned final directory handle. Request enumeration only on that leaf,
		// never on ancestors that are held solely to prevent path replacement.
		access |= windows.FILE_LIST_DIRECTORY
	}
	handle, err := openWindowsCorrelationHandle(func() (windows.Handle, error) {
		return windows.CreateFile(
			name,
			access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}, false)
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

func openWindowsCorrelationHandle(
	open func() (windows.Handle, error),
	retryAccessDenied bool,
) (windows.Handle, error) {
	var lastErr error
	for attempt := 0; attempt < keyInstallAttempts; attempt++ {
		handle, err := open()
		if err == nil {
			return handle, nil
		}
		lastErr = err
		if !windowsCorrelationOpenRetryable(err, retryAccessDenied) {
			return 0, err
		}
		if attempt+1 < keyInstallAttempts {
			time.Sleep(time.Millisecond)
		}
	}
	return 0, lastErr
}

func windowsCorrelationHandleBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_DELETE_PENDING)

}

func windowsCorrelationOpenRetryable(err error, retryAccessDenied bool) bool {
	return windowsCorrelationHandleBusy(err) || (retryAccessDenied && errors.Is(err, windows.ERROR_ACCESS_DENIED))
}

func loadExistingWindowsCorrelationKey(dataDir string, hooks keyStoreHooks) (CorrelationKey, bool, error) {
	path := filepath.Join(dataDir, correlationKeyFilename)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	handle, err := openWindowsCorrelationHandle(func() (windows.Handle, error) {
		return windows.CreateFile(
			name,
			windowsCorrelationExistingKeyAccess(false),
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}, true)
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

	if err := validateWindowsCorrelationKeyPhysicalHandle(handle); err != nil {
		return CorrelationKey{}, false, err
	}
	needsHardening, err := windowsCorrelationSecurityNeedsHardening(handle)
	if err != nil {
		return CorrelationKey{}, false, err
	}
	if needsHardening {
		if err := hardenExistingWindowsCorrelationKey(path, handle); err != nil {
			return CorrelationKey{}, false, err
		}
	}
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

func windowsCorrelationExistingKeyAccess(harden bool) uint32 {
	access := uint32(windows.GENERIC_READ | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	if harden {
		// Existing canonical keys never require ACL-changing access. WRITE_DAC
		// and WRITE_OWNER are reserved for a separately opened, short-lived
		// migration handle that installs the exact DACL and primary group.
		access = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER
	}
	return access
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
	if err := validateWindowsCorrelationKeyPhysicalHandle(handle); err != nil {
		return err
	}
	needsHardening, err := windowsCorrelationSecurityNeedsHardening(handle)
	if err != nil {
		return err
	}
	if needsHardening {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	return nil
}

func validateWindowsCorrelationKeyPhysicalHandle(handle windows.Handle) error {
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
	return nil
}

func windowsCorrelationSecurityNeedsHardening(handle windows.Handle) (bool, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return false, keyStoreError(KeyStoreErrorUnavailable)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false, keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	expectedOwner, err := windowsCorrelationExpectedOwnerSID()
	if err != nil {
		return false, err
	}
	if !owner.Equals(expectedOwner) {
		return false, keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return false, keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	groupCanonical := group.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	control, _, err := descriptor.Control()
	if err != nil {
		return false, keyStoreError(KeyStoreErrorUnavailable)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false, keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	canonical, err := windowsCorrelationACLMatches(
		dacl,
		windowsCorrelationCanonicalACL(expectedOwner),
	)
	if err != nil {
		return false, err
	}
	if canonical && groupCanonical {
		return control&windows.SE_DACL_PROTECTED == 0, nil
	}
	legacy, err := windowsCorrelationACLMatches(
		dacl,
		windowsCorrelationLegacyACL(expectedOwner),
	)
	if err != nil {
		return false, err
	}
	if legacy || canonical {
		return true, nil
	}
	// A first OPEN_EXISTING after the no-replace rename can expose the same
	// trusted ACEs as unprotected/inherited. Only that unprotected case is
	// eligible for normalization, and only when every ACE remains confined to
	// the expected owner, SYSTEM, Administrators, or OWNER RIGHTS.
	if control&windows.SE_DACL_PROTECTED == 0 {
		trusted, err := windowsCorrelationMigrationACLTrusted(dacl, expectedOwner)
		if err != nil {
			return false, err
		}
		if trusted {
			return true, nil
		}
	}
	return false, keyStoreError(KeyStoreErrorUnsafePermissions)
}

type windowsCorrelationACEExpectation struct {
	sid  *windows.SID
	mask windows.ACCESS_MASK
}

func windowsCorrelationCanonicalACL(owner *windows.SID) []windowsCorrelationACEExpectation {
	ownerRights, _ := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	localSystem, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	return []windowsCorrelationACEExpectation{
		{sid: ownerRights, mask: windows.READ_CONTROL},
		{sid: localSystem, mask: windowsCorrelationFileAllAccess},
		{sid: administrators, mask: windowsCorrelationFileAllAccess},
		{sid: owner, mask: windowsCorrelationFileGenericRead},
	}
}

func windowsCorrelationLegacyACL(owner *windows.SID) []windowsCorrelationACEExpectation {
	localSystem, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	return []windowsCorrelationACEExpectation{
		{sid: owner, mask: windowsCorrelationFileAllAccess},
		{sid: localSystem, mask: windowsCorrelationFileAllAccess},
		{sid: administrators, mask: windowsCorrelationFileAllAccess},
	}
}

func windowsCorrelationACLMatches(
	dacl *windows.ACL,
	expected []windowsCorrelationACEExpectation,
) (bool, error) {
	if dacl == nil || int(dacl.AceCount) != len(expected) {
		return false, nil
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, keyStoreError(KeyStoreErrorUnavailable)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 || ace.Mask == 0 {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		want := expected[index]
		if want.sid == nil || ace.Mask != want.mask || !sid.Equals(want.sid) {
			return false, nil
		}
	}
	return true, nil
}

func windowsCorrelationMigrationACLTrusted(dacl *windows.ACL, owner *windows.SID) (bool, error) {
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, keyStoreError(KeyStoreErrorUnavailable)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(owner) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			continue
		}
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) && ace.Mask == windows.READ_CONTROL {
			continue
		}
		return false, nil
	}
	return true, nil
}

func windowsCorrelationExpectedOwnerSID() (*windows.SID, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return nil, keyStoreError(KeyStoreErrorUnavailable)
	}
	account := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	if account == "" {
		if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
			return nil, keyStoreError(KeyStoreErrorUnavailable)
		}
		return current.User.Sid, nil
	}
	expected, err := windowsCorrelationServiceAccountSID(account)
	if err != nil || expected == nil || !current.User.Sid.Equals(expected) {
		return nil, keyStoreError(KeyStoreErrorUnavailable)
	}
	return expected, nil
}

func hardenExistingWindowsCorrelationKey(path string, pinned windows.Handle) error {
	pinnedInfo, err := windowsCorrelationHandleInformation(pinned)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	hardening, err := openWindowsCorrelationHandle(func() (windows.Handle, error) {
		return windows.CreateFile(
			name,
			windowsCorrelationExistingKeyAccess(true),
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}, true)
	if err != nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	defer func() { _ = windows.CloseHandle(hardening) }()

	hardeningInfo, err := windowsCorrelationHandleInformation(hardening)
	if err != nil {
		return err
	}
	if !windowsCorrelationSameFile(pinnedInfo, hardeningInfo) {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	if err := validateWindowsCorrelationKeyPhysicalHandle(hardening); err != nil {
		return err
	}
	needsHardening, err := windowsCorrelationSecurityNeedsHardening(hardening)
	if err != nil {
		return err
	}
	if needsHardening {
		if err := protectWindowsCorrelationSecurity(hardening); err != nil {
			return err
		}
	}
	if err := validateWindowsCorrelationKeyHandle(hardening); err != nil {
		return err
	}
	finalPinnedInfo, err := windowsCorrelationHandleInformation(pinned)
	if err != nil {
		return err
	}
	finalHardeningInfo, err := windowsCorrelationHandleInformation(hardening)
	if err != nil {
		return err
	}
	if !windowsCorrelationSameFile(pinnedInfo, finalPinnedInfo) ||
		!windowsCorrelationSameFile(pinnedInfo, finalHardeningInfo) {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	return validateWindowsCorrelationKeyHandle(pinned)
}

func windowsCorrelationHandleInformation(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return details, keyStoreError(KeyStoreErrorUnavailable)
	}
	return details, nil
}

func windowsCorrelationSameFile(left, right windows.ByHandleFileInformation) bool {
	return left.VolumeSerialNumber == right.VolumeSerialNumber &&
		left.FileIndexHigh == right.FileIndexHigh &&
		left.FileIndexLow == right.FileIndexLow
}

func installWindowsCorrelationKey(
	dataDir string,
	directory windows.Handle,
	candidate CorrelationKey,
	entropy keyEntropyReader,
	hooks keyStoreHooks,
) (installed bool, resultErr error) {
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
	preserveFile := false
	closed := false
	closeTemp := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer func() {
		if !preserveFile && !closed {
			// DELETE was granted to this exact handle before hardening. Marking
			// that authenticated inode for deletion avoids a path reopen after
			// the final DACL removes the service's delete permission.
			if err := markWindowsCorrelationKeyForDeletion(windows.Handle(file.Fd())); err != nil && resultErr == nil {
				resultErr = keyStoreError(KeyStoreErrorTemporaryFile)
			}
		}
		if err := closeTemp(); err != nil && resultErr == nil {
			resultErr = keyStoreError(KeyStoreErrorTemporaryFile)
		}
	}()

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
	stagingHandle := windows.Handle(file.Fd())
	if err := validateWindowsCorrelationStagingSecurity(stagingHandle); err != nil {
		return false, err
	}
	stagingInfo, err := windowsCorrelationHandleInformation(stagingHandle)
	if err != nil {
		return false, err
	}
	if err := validateWindowsCorrelationKeyPhysicalHandle(stagingHandle); err != nil {
		return false, err
	}
	// Install and verify the final descriptor before the destination name is
	// published. DELETE was granted when this handle was created, so tightening
	// the DACL does not revoke its already-authorized handle-bound rename.
	if err := protectWindowsCorrelationSecurity(stagingHandle); err != nil {
		return false, err
	}
	if err := validateWindowsCorrelationKeyHandle(stagingHandle); err != nil {
		return false, err
	}
	// A process termination in this short pre-rename window can leave a
	// canonical, read-only temp inode. It cannot become or replace the final key;
	// bounded cleanup of such crash residue requires the privileged installer,
	// because granting the service permanent delete access would weaken the
	// final key contract.
	if err := runAfterTempSync(hooks); err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}

	for attempt := 0; attempt < keyInstallAttempts; attempt++ {
		err := renameWindowsCorrelationKeyHandle(stagingHandle, directory)
		if err == nil {
			if err := validatePublishedWindowsCorrelationKeyHandle(stagingHandle, stagingInfo); err != nil {
				return false, err
			}
			// From this point onward the published inode has the exact final
			// descriptor, physical shape, and pre-publication identity. Preserve
			// it across later sync/test-hook failures so startup can reload it.
			preserveFile = true
			// Flush after both the handle-bound rename and final descriptor update.
			// The handle still denies read/write sharing, so no other creator can
			// load the destination until the exact final state is durable.
			if err := file.Sync(); err != nil {
				return false, keyStoreError(KeyStoreErrorSync)
			}
			if err := runAfterLink(hooks); err != nil {
				return false, keyStoreError(KeyStoreErrorSync)
			}
			if err := closeTemp(); err != nil {
				return false, keyStoreError(KeyStoreErrorTemporaryFile)
			}
			if err := verifyInstalledWindowsCorrelationKey(targetPath, candidate); err != nil {
				return false, err
			}
			return true, nil
		}
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return false, nil
		}
		if !windowsCorrelationOpenRetryable(err, true) {
			return false, keyStoreError(KeyStoreErrorInstall)
		}
		if _, attributeErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(targetPath)); attributeErr == nil {
			// A creator won but its destination is still transiently locked.
			// The outer loop reloads it through the full handle and DACL checks.
			return false, nil
		}
		if attempt+1 < keyInstallAttempts {
			time.Sleep(time.Millisecond)
		}
	}
	return false, keyStoreError(KeyStoreErrorInstall)
}

type windowsCorrelationFileRenameInfo struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// renameWindowsCorrelationKeyHandle publishes the already-authenticated
// staging inode relative to the pinned data-directory handle. ReplaceIfExists
// remains false: a collision is a concurrent winner, never authorization to
// replace an existing key.
func renameWindowsCorrelationKeyHandle(
	handle windows.Handle,
	directory windows.Handle,
) error {
	name, err := windows.UTF16FromString(correlationKeyFilename)
	if err != nil || len(name) < 2 {
		return windows.ERROR_INVALID_NAME
	}
	name = name[:len(name)-1]
	var layout windowsCorrelationFileRenameInfo
	nameBytes := len(name) * 2
	bufferSize := int(unsafe.Offsetof(layout.FileName)) + nameBytes
	buffer := make([]byte, bufferSize)
	information := (*windowsCorrelationFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	information.RootDirectory = directory
	information.FileNameLength = uint32(nameBytes)
	copy(
		(*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&information.FileName[0]))[:len(name):len(name)],
		name,
	)
	err = windows.SetFileInformationByHandle(
		handle,
		windows.FileRenameInfo,
		&buffer[0],
		uint32(len(buffer)),
	)
	runtime.KeepAlive(buffer)
	return err
}

// validatePublishedWindowsCorrelationKeyHandle proves that the no-replace
// rename retained the exact pre-hardened staging inode and final descriptor.
// It never repairs a published object; any mismatch remains fail-closed and is
// deleted through the still-authenticated staging handle by the caller.
func validatePublishedWindowsCorrelationKeyHandle(
	handle windows.Handle,
	stagingInfo windows.ByHandleFileInformation,
) error {
	if err := validateWindowsCorrelationKeyPhysicalHandle(handle); err != nil {
		return err
	}
	publishedInfo, err := windowsCorrelationHandleInformation(handle)
	if err != nil {
		return err
	}
	if !windowsCorrelationSameFile(stagingInfo, publishedInfo) {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	if err := validateWindowsCorrelationKeyHandle(handle); err != nil {
		return err
	}
	finalInfo, err := windowsCorrelationHandleInformation(handle)
	if err != nil {
		return err
	}
	if !windowsCorrelationSameFile(stagingInfo, finalInfo) {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	return nil
}

func markWindowsCorrelationKeyForDeletion(handle windows.Handle) error {
	disposition := byte(1)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		&disposition,
		uint32(unsafe.Sizeof(disposition)),
	)
}

func verifyInstalledWindowsCorrelationKey(path string, candidate CorrelationKey) error {
	loaded, found, err := loadExistingWindowsCorrelationKey(filepath.Dir(path), keyStoreHooks{})
	if err != nil {
		return err
	}
	loadedMaterial, loadedOK := loaded.Material()
	candidateMaterial, candidateOK := candidate.Material()
	if !found || !loadedOK || !candidateOK || loaded.ID() != candidate.ID() || loadedMaterial != candidateMaterial {
		return keyStoreError(KeyStoreErrorInstall)
	}
	return nil
}

func createWindowsCorrelationTemp(path string) (*os.File, error) {
	descriptor, err := windowsCorrelationStagingSecurityDescriptor()
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
		windows.GENERIC_WRITE|windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_DELETE,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := validateWindowsCorrelationStagingSecurity(handle); err != nil {
		_ = markWindowsCorrelationKeyForDeletion(handle)
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = markWindowsCorrelationKeyForDeletion(handle)
		_ = windows.CloseHandle(handle)
		return nil, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	return file, nil
}

func windowsCorrelationStagingSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	owner, err := windowsCorrelationExpectedOwnerSID()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString(
		"O:" + owner.String() + "G:BAD:P(A;;FA;;;" + owner.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)",
	)
}

func windowsCorrelationProtectedSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	owner, err := windowsCorrelationExpectedOwnerSID()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString(
		"O:" + owner.String() + "G:BAD:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + owner.String() + ")",
	)
}

func validateWindowsCorrelationStagingSecurity(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return keyStoreError(KeyStoreErrorUnavailable)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	expectedOwner, err := windowsCorrelationExpectedOwnerSID()
	if err != nil {
		return err
	}
	if !owner.Equals(expectedOwner) {
		return keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil || !group.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	matches, err := windowsCorrelationACLMatches(dacl, windowsCorrelationLegacyACL(expectedOwner))
	if err != nil {
		return err
	}
	if !matches {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	return nil
}

func protectWindowsCorrelationSecurity(handle windows.Handle) error {
	descriptor, err := windowsCorrelationProtectedSecurityDescriptor()
	if err != nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		group,
		dacl,
		nil,
	); err != nil {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	runtime.KeepAlive(descriptor)
	return nil
}
