// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func LoadAuthKey(path, gatewayServiceName string) ([AuthKeyBytes]byte, error) {
	var key [AuthKeyBytes]byte
	if err := validateLocalAbsolutePath(path, "broker authentication key"); err != nil {
		return key, err
	}
	if err := ValidateIdentityBinding(
		brokerServiceForGateway(gatewayServiceName),
		gatewayServiceName,
		localPipePrefix+brokerServiceForGateway(gatewayServiceName),
	); err != nil {
		return key, err
	}

	directories, err := pinDirectoryChain(filepath.Dir(path))
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is unavailable")
	}
	defer closeHandles(directories)

	// Validate the path while every ancestor is held without delete sharing.
	// Read-only access for the exact gateway SID is permitted; write-like access
	// remains limited to SYSTEM/Administrators by the managed trust validator.
	if err := managed.ValidateTrustedFilePath(path, "broker authentication key"); err != nil {
		return key, fmt.Errorf("broker authentication key trust validation failed: %w", err)
	}

	extended, err := winpath.Extended(path)
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is invalid")
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return key, fmt.Errorf("broker authentication key path is invalid")
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return key, fmt.Errorf("broker authentication key is unavailable")
	}
	file := os.NewFile(uintptr(handle), "broker-auth.key")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return key, fmt.Errorf("broker authentication key is unavailable")
	}
	defer func() { _ = file.Close() }()

	gatewaySID, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + gatewayServiceName)
	if err != nil {
		return key, fmt.Errorf("gateway service identity is unavailable")
	}
	if err := validateKeyHandle(handle, gatewaySID); err != nil {
		return key, err
	}
	if _, err := io.ReadFull(file, key[:]); err != nil {
		zeroKey(&key)
		return key, fmt.Errorf("broker authentication key has an invalid length")
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		zeroKey(&key)
		return key, fmt.Errorf("broker authentication key has an invalid length")
	}
	if err := validateKeyHandle(handle, gatewaySID); err != nil {
		zeroKey(&key)
		return key, err
	}
	return key, nil
}

func validateLocalAbsolutePath(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' ||
		(volume[0] < 'A' || volume[0] > 'Z') && (volume[0] < 'a' || volume[0] > 'z') {
		return fmt.Errorf("%s must be on a local drive", label)
	}
	if strings.Contains(path[len(volume):], ":") {
		return fmt.Errorf("%s must not contain alternate-data-stream syntax", label)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return fmt.Errorf("%s is not on a trusted local NTFS volume: %w", label, err)
	}
	return nil
}

func pinDirectoryChain(path string) ([]windows.Handle, error) {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(path, root)
	elements := []string{root}
	current := root
	for _, element := range strings.Split(relative, string(filepath.Separator)) {
		if element == "" {
			continue
		}
		current = filepath.Join(current, element)
		elements = append(elements, current)
	}
	handles := make([]windows.Handle, 0, len(elements))
	for _, element := range elements {
		pointer, err := winpath.UTF16Ptr(element)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handle, err := windows.CreateFile(
			pointer,
			windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		var details windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &details); err != nil ||
			details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			_ = windows.CloseHandle(handle)
			closeHandles(handles)
			return nil, errors.New("unsafe directory in key path")
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func closeHandles(handles []windows.Handle) {
	for index := len(handles) - 1; index >= 0; index-- {
		_ = windows.CloseHandle(handles[index])
	}
}

func validateKeyHandle(handle windows.Handle, gatewaySID *windows.SID) error {
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return fmt.Errorf("broker authentication key metadata is unavailable")
	}
	if details.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|
		windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_SPARSE_FILE) != 0 ||
		details.NumberOfLinks != 1 {
		return fmt.Errorf("broker authentication key has an unsafe file type")
	}
	size := int64(details.FileSizeHigh)<<32 | int64(details.FileSizeLow)
	if size != AuthKeyBytes {
		return fmt.Errorf("broker authentication key has an invalid length")
	}

	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return fmt.Errorf("broker authentication key security is unavailable")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil ||
		!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("broker authentication key owner is not trusted")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("broker authentication key DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("broker authentication key DACL is unavailable")
	}
	if err := validateKeyACL(dacl, gatewaySID); err != nil {
		return err
	}
	return nil
}

func validateKeyACL(dacl *windows.ACL, gatewaySID *windows.SID) error {
	if dacl == nil || dacl.AceCount != 3 {
		return fmt.Errorf("broker authentication key DACL must contain exactly three ACEs")
	}
	seenSystem, seenAdmins, seenGateway := false, false, false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Errorf("broker authentication key DACL is malformed")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			return fmt.Errorf("broker authentication key DACL contains an unsupported ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			if seenSystem {
				return fmt.Errorf("broker authentication key DACL contains a duplicate SYSTEM ACE")
			}
			seenSystem = true
			if !fullControlMask(ace.Mask) {
				return fmt.Errorf("broker authentication key SYSTEM access is incomplete")
			}
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			if seenAdmins {
				return fmt.Errorf("broker authentication key DACL contains a duplicate Administrators ACE")
			}
			seenAdmins = true
			if !fullControlMask(ace.Mask) {
				return fmt.Errorf("broker authentication key Administrators access is incomplete")
			}
		case gatewaySID != nil && sid.Equals(gatewaySID):
			if seenGateway {
				return fmt.Errorf("broker authentication key DACL contains a duplicate gateway ACE")
			}
			seenGateway = true
			const fileGenericRead windows.ACCESS_MASK = 0x00120089
			if ace.Mask&(windows.GENERIC_WRITE|windows.GENERIC_ALL|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|
				windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES) != 0 ||
				ace.Mask&windows.GENERIC_READ == 0 && ace.Mask&fileGenericRead != fileGenericRead {
				return fmt.Errorf("broker authentication key gateway access is not read-only")
			}
		default:
			return fmt.Errorf("broker authentication key DACL grants an unexpected principal")
		}
	}
	if !seenSystem || !seenAdmins || !seenGateway {
		return fmt.Errorf("broker authentication key DACL is incomplete")
	}
	return nil
}

func fullControlMask(mask windows.ACCESS_MASK) bool {
	const fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	return mask&windows.GENERIC_ALL != 0 || mask&fileAllAccess == fileAllAccess
}

func zeroKey(key *[AuthKeyBytes]byte) {
	if key == nil {
		return
	}
	for index := range key {
		key[index] = 0
	}
}

func brokerServiceForGateway(gatewayServiceName string) string {
	if gatewayServiceName == defaultGatewayService {
		return defaultBrokerService
	}
	match := certificationGatewayPattern.FindStringSubmatch(gatewayServiceName)
	if len(match) == 2 {
		return defaultBrokerService + "_" + match[1]
	}
	return ""
}
