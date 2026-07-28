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

package connector

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// otlpValidateDirectory enforces the native Windows owner, DACL, and
// reparse-point contract for every directory controlling a token path.
func otlpValidateDirectory(path string) error {
	return hookAPIValidateDirectory(path)
}

// otlpOpenNoFollow returns 0 on Windows. O_NOFOLLOW is a Unix flag and is not
// available here. (Windows DOES traverse reparse points/symlinks during
// CreateFile unless FILE_FLAG_OPEN_REPARSE_POINT is set, but creating symlinks
// on Windows requires elevation or Developer Mode, and the token file is
// created with O_EXCL, so the practical exposure is limited.)
func otlpOpenNoFollow() int {
	return 0
}

// otlpValidatePerm enforces the Windows equivalent of a Unix 0600 token file:
// no untrusted principal may receive read-like access through the DACL. The
// write/owner half of the contract is enforced by otlpValidateOwner below.
func otlpValidatePerm(path string, _ os.FileInfo) error {
	dacl, err := otlpWindowsPathSecurity(path)
	if err != nil {
		return err
	}
	return otlpWindowsRejectUntrustedReadACEs(path, dacl)
}

// otlpValidateOwner rejects reparse points, non-regular files, untrusted
// owners, null DACLs, and write-like access granted to untrusted principals.
// It deliberately reuses the hook-token trust model for current-user,
// LocalSystem, Administrators, and TrustedInstaller ownership.
func otlpValidateOwner(path string, _ os.FileInfo) error {
	dacl, err := otlpWindowsPathSecurity(path)
	if err != nil {
		return err
	}
	return hookAPIRejectUntrustedWindowsWriteACEs(path, dacl, false, true)
}

// Removal does not trust or consume token bytes. Once path shape, owner, and
// opened-handle identity are verified, deleting even a broadly exposed DACL is
// the safe recovery action: rejecting cleanup would leave the compromised
// credential authorized by a running gateway.
func otlpValidateRemovalOwner(path string, _ os.FileInfo) error {
	_, err := otlpWindowsPathSecurity(path)
	return err
}

func otlpValidateTokenDirectory(_, dir string) error {
	if _, err := os.Lstat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return hookAPIValidateDirectory(dir)
}

// otlpPathTokenNeedsSecureReplacement reports whether an existing token owned
// by a trusted principal must be rotated because its DACL exposed read or write
// authority. Reusing its old bytes after merely tightening the ACL would keep a
// credential valid after an untrusted principal may already have learned or
// replaced it, so Ensure publishes a fresh securely-created inode instead.
func otlpPathTokenNeedsSecureReplacement(path string) (bool, error) {
	dacl, err := otlpWindowsPathSecurity(path)
	if err != nil {
		return false, err
	}
	if err := hookAPIRejectUntrustedWindowsWriteACEs(path, dacl, false, true); err != nil {
		return true, nil
	}
	if err := otlpWindowsRejectUntrustedReadACEs(path, dacl); err != nil {
		return true, nil
	}
	return false, nil
}

func otlpWindowsPathSecurity(path string) (*windows.ACL, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode Windows OTLP token path %s: %w", path, err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return nil, fmt.Errorf("inspect Windows attributes for %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular file: %s", path)
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, fmt.Errorf("inspect Windows security descriptor for %s: %w", path, err)
	}
	if sd == nil {
		return nil, fmt.Errorf("missing Windows security descriptor: %s", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("inspect Windows owner for %s: %w", path, err)
	}
	if !hookAPIWindowsTrustedPrincipal(owner) {
		return nil, fmt.Errorf("owner %s is not trusted for OTLP token path %s", hookAPIWindowsSIDString(owner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("inspect Windows DACL for %s: %w", path, err)
	}
	if dacl == nil {
		return nil, fmt.Errorf("null Windows DACL is not trusted: %s", path)
	}
	return dacl, nil
}

func otlpWindowsRejectUntrustedReadACEs(path string, dacl *windows.ACL) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	readLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_READ |
			windows.GENERIC_EXECUTE |
			windows.FILE_READ_DATA |
			windows.FILE_READ_EA |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_EXECUTE,
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&readLike == 0 {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("unsupported Windows read-capable allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if hookAPIWindowsOwnerRightsPrincipal(sid) || hookAPIWindowsTrustedPrincipal(sid) {
			continue
		}
		return fmt.Errorf(
			"untrusted Windows principal %s has read-like access mask 0x%x on %s",
			hookAPIWindowsSIDString(sid), uint32(ace.Mask), path,
		)
	}
	return nil
}

func otlpWindowsOwnerOnlySecurityAttributes() (*windows.SecurityAttributes, error) {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("resolve current Windows token owner: %w", err)
	}
	if currentUser == nil || currentUser.User.Sid == nil {
		return nil, fmt.Errorf("resolve current Windows token owner: missing user SID")
	}
	sid := currentUser.User.Sid.String()
	// Protected DACL: the creating user owns the credential, while LocalSystem
	// and Administrators retain the access required by managed service installs.
	sd, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)(A;;GA;;;BA)",
	)
	if err != nil {
		return nil, fmt.Errorf("build owner-only Windows security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

func openSecureOTLPWindowsFile(path string, creationDisposition, shareMode uint32, secureCreate bool) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var security *windows.SecurityAttributes
	if secureCreate {
		security, err = otlpWindowsOwnerOnlySecurityAttributes()
		if err != nil {
			return nil, err
		}
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		shareMode,
		security,
		creationDisposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap Windows file handle for %s", path)
	}
	return file, nil
}

func createSecureOTLPPathTokenTempFile(tokenPath string) (*os.File, string, error) {
	securityDir := filepath.Dir(tokenPath)
	for attempt := 0; attempt < 128; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", err
		}
		tmpPath := filepath.Join(
			securityDir,
			otlpPathTokenTempPrefix(tokenPath)+hex.EncodeToString(random),
		)
		file, err := openSecureOTLPWindowsFile(tmpPath, windows.CREATE_NEW, 0, true)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		info, statErr := file.Stat()
		pathInfo, pathErr := os.Lstat(tmpPath)
		if statErr != nil || pathErr != nil || !info.Mode().IsRegular() ||
			pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return nil, "", fmt.Errorf("secure Windows OTLP token temp file %s changed identity during creation", tmpPath)
		}
		if err := otlpValidateOwner(tmpPath, info); err != nil {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return nil, "", err
		}
		if err := otlpValidatePerm(tmpPath, info); err != nil {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return nil, "", err
		}
		return file, tmpPath, nil
	}
	return nil, "", fmt.Errorf("create unique secure Windows OTLP token temp file")
}
