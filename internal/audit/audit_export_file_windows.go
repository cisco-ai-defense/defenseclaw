//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// CreateExportFileExclusive gives a Windows audit export the audit store's
// protected file DACL at creation, before any other process can open it.
// An administrator may export a managed store without running as its gateway.
func CreateExportFileExclusive(path string) (*os.File, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	owner, err := auditExportWindowsTokenOwner()
	if err != nil {
		return nil, err
	}
	dacl, err := auditDBWindowsProtectedDACLForOwnerWithGatewayProof(false, owner, false)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return nil, err
	}
	if err := sd.SetOwner(owner, false); err != nil {
		return nil, err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	protected, err := sd.ToSelfRelative()
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: protected,
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_WRITE|windows.READ_CONTROL,
		0, &attributes, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return nil, errors.New("audit: create export file handle")
	}
	sd, err = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = validateAuditDBWindowsSecurityDescriptor(path, sd, false, true)
	}
	if err == nil {
		var control windows.SECURITY_DESCRIPTOR_CONTROL
		control, _, err = sd.Control()
		if err == nil && control&windows.SE_DACL_PROTECTED == 0 {
			err = errors.New("audit: export DACL is not protected")
		}
	}
	if err == nil {
		gatewaySID, sidErr := auditDBWindowsPinnedGatewayServiceSID()
		if sidErr != nil {
			err = sidErr
		} else if gatewaySID != nil {
			var canonical bool
			canonical, err = auditDBWindowsManagedRuntimeFileCanonical(sd, gatewaySID)
			if err == nil && !canonical {
				err = errors.New("audit: managed export DACL is not canonical")
			}
		}
	}
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("audit: verify private export file: %w", err)
	}
	return file, nil
}

func auditExportWindowsTokenOwner() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size); err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("audit: size Windows export owner: %w", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		return nil, fmt.Errorf("audit: resolve Windows export owner: %w", err)
	}
	owner := *(**windows.SID)(unsafe.Pointer(&buffer[0]))
	if owner == nil {
		return nil, errors.New("audit: Windows export owner is missing")
	}
	return windows.StringToSid(owner.String())
}
