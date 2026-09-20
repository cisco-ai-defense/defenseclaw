// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// LockVerifiedHook opens the exact installed full hook without write/delete
// sharing and validates identity, ownership, private DACL, and digest through
// that held handle. The caller keeps the handle open through CreateProcess so
// verified bytes cannot be replaced in the validation-to-launch window.
func LockVerifiedHook(state State) (*os.File, error) {
	if !state.DelegationCapable() {
		return nil, errors.New("hook runtime state does not authorize full-hook delegation")
	}
	if err := winpath.RejectReparseChain(state.HookPath); err != nil {
		return nil, fmt.Errorf("validate installed full-hook path: %w", err)
	}
	path, err := winpath.UTF16Ptr(state.HookPath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("lock installed full hook: %w", err)
	}
	file := os.NewFile(uintptr(handle), state.HookPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open installed full-hook handle")
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(fmt.Errorf("inspect installed full-hook handle: %w", err))
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fail(errors.New("installed full-hook handle is not a regular non-reparse file"))
	}
	finalPath, err := finalPathForHandle(handle)
	if err != nil {
		return fail(fmt.Errorf("resolve installed full-hook handle: %w", err))
	}
	if !samePath(finalPath, state.HookPath) {
		return fail(fmt.Errorf("installed full-hook final path changed: got %s", finalPath))
	}
	safe, err := privateHandleDACLIsSafe(handle)
	if err != nil {
		return fail(fmt.Errorf("validate installed full-hook handle security: %w", err))
	}
	if !safe {
		return fail(errors.New("installed full-hook handle is not current-user owned with a private DACL"))
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fail(fmt.Errorf("hash installed full-hook handle: %w", err))
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), state.HookSHA256) {
		return fail(errors.New("installed full-hook digest does not match hook runtime state"))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("rewind installed full-hook handle: %w", err))
	}
	return file, nil
}

func finalPathForHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err == nil && length < uint32(len(buffer)) {
			resolved := windows.UTF16ToString(buffer[:length])
			switch {
			case strings.HasPrefix(resolved, `\\?\UNC\`):
				resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
			case strings.HasPrefix(resolved, `\\?\`):
				resolved = strings.TrimPrefix(resolved, `\\?\`)
			}
			return resolved, nil
		}
		if err != nil {
			return "", err
		}
		if length == 0 {
			return "", errors.New("installed full-hook final path is empty")
		}
		buffer = make([]uint16, length+1)
	}
}

func privateHandleDACLIsSafe(handle windows.Handle) (bool, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	return privateDACLForCurrentUserIsSafe(owner, dacl)
}

func privateDACLForCurrentUserIsSafe(owner *windows.SID, dacl *windows.ACL) (bool, error) {
	if dacl == nil {
		return false, nil
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return false, nil
	}

	foundOwner := false
	foundSystem := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, err
		}
		if ace == nil || !simpleDiscretionaryACE(ace.Header.AceType) {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := sid.Equals(user.User.Sid) || sid.Equals(system) ||
			sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			if trusted && ace.Mask != 0 {
				return false, nil
			}
			continue
		}
		if ace.Mask == 0 {
			continue
		}
		if !trusted {
			return false, nil
		}
		if sid.Equals(system) {
			foundSystem = true
		} else {
			foundOwner = true
		}
	}
	return foundOwner && foundSystem, nil
}

func simpleDiscretionaryACE(aceType byte) bool {
	return aceType == windows.ACCESS_ALLOWED_ACE_TYPE ||
		aceType == windows.ACCESS_DENIED_ACE_TYPE
}
