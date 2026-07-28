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
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var atomicTransformCompareStringOrdinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")

func atomicTransformPathsEqualPlatform(a, b string) bool {
	a16, err := windows.UTF16FromString(filepath.Clean(a))
	if err != nil {
		return false
	}
	b16, err := windows.UTF16FromString(filepath.Clean(b))
	if err != nil {
		return false
	}
	result, _, _ := atomicTransformCompareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&a16[0])),
		uintptr(len(a16)-1),
		uintptr(unsafe.Pointer(&b16[0])),
		uintptr(len(b16)-1),
		1,
	)
	const cstrEqual = 2
	return result == cstrEqual
}

func atomicTransformLocationsEquivalentPlatform(a, b string) bool {
	if atomicTransformPathsEqualPlatform(a, b) {
		return true
	}
	aInfo, aErr := os.Stat(a)
	bInfo, bErr := os.Stat(b)
	if aErr == nil && bErr == nil && os.SameFile(aInfo, bInfo) {
		return true
	}
	aParent, aParentErr := os.Stat(filepath.Dir(a))
	bParent, bParentErr := os.Stat(filepath.Dir(b))
	return aParentErr == nil && bParentErr == nil &&
		os.SameFile(aParent, bParent) &&
		atomicTransformPathsEqualPlatform(filepath.Base(a), filepath.Base(b))
}

// filepath.EvalSymlinks does not resolve directory junctions on every
// supported Windows/Go combination. Resolve the opened directory handle so a
// logical junction can never become the recovery or artifact namespace.
func atomicTransformResolveDirectoryPathPlatform(path string) (string, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	return atomicTransformFinalPathByHandle(handle)
}

func atomicTransformFinalPathByHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, pathErr := windows.GetFinalPathNameByHandle(
			handle, &buffer[0], uint32(len(buffer)), 0,
		)
		if pathErr == nil && length < uint32(len(buffer)) {
			resolved := windows.UTF16ToString(buffer[:length])
			switch {
			case strings.HasPrefix(resolved, `\\?\UNC\`):
				resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
			case strings.HasPrefix(resolved, `\\?\`):
				resolved = strings.TrimPrefix(resolved, `\\?\`)
			}
			return filepath.Clean(resolved), nil
		}
		if length >= uint32(len(buffer)) || errors.Is(pathErr, windows.ERROR_INSUFFICIENT_BUFFER) {
			next := int(length) + 1
			if next <= len(buffer) {
				next = len(buffer) * 2
			}
			buffer = make([]uint16, next)
			continue
		}
		if pathErr != nil {
			return "", pathErr
		}
		buffer = make([]uint16, len(buffer)*2)
	}
}

func atomicTransformCanonicalizeExistingLeafPlatform(path string) (string, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	return atomicTransformFinalPathByHandle(handle)
}

// V2 binds and guards ordinary directory handles after this validation. By
// rejecting any pre-existing reparse component, the guarded physical ancestry
// is also the logical ancestry; a junction cannot be retargeted in the final
// resolve-to-Rt window without first deleting a no-share-delete guard.
func atomicTransformValidateNoReparsePathPlatform(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		pointer, pointerErr := winpath.UTF16Ptr(current)
		if pointerErr != nil {
			return pointerErr
		}
		attributes, attributeErr := windows.GetFileAttributes(pointer)
		if attributeErr == nil {
			if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return fmt.Errorf("Windows compare-and-swap locator contains unsupported reparse component: %s", current)
			}
		} else if !errors.Is(attributeErr, windows.ERROR_FILE_NOT_FOUND) &&
			!errors.Is(attributeErr, windows.ERROR_PATH_NOT_FOUND) {
			return attributeErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func atomicTransformValidateStableVolumeLocatorPlatform(
	locator string, boundParent *atomicTransformBoundDirectory,
) error {
	absolute, err := filepath.Abs(locator)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	if len(volume) == 2 && volume[1] == ':' {
		device, pointerErr := windows.UTF16PtrFromString(volume)
		if pointerErr != nil {
			return pointerErr
		}
		buffer := make([]uint16, 32768)
		length, queryErr := windows.QueryDosDevice(device, &buffer[0], uint32(len(buffer)))
		if queryErr != nil {
			return fmt.Errorf("query Windows DOS-device mapping for %s: %w", volume, queryErr)
		}
		target := windows.UTF16ToString(buffer[:length])
		if strings.HasPrefix(strings.ToLower(target), `\??\`) {
			return fmt.Errorf("retargetable Windows DOS-device/SUBST locator is unsupported: %s", volume)
		}
	}
	logicalVolume, err := atomicTransformWindowsVolumeGUIDForPath(absolute)
	if err != nil {
		return fmt.Errorf("resolve Windows locator through Mount Manager: %w", err)
	}
	boundVolume, err := atomicTransformWindowsVolumeGUIDForHandle(windows.Handle(boundParent.file.Fd()))
	if err != nil {
		return fmt.Errorf("resolve bound target parent volume identity: %w", err)
	}
	if !strings.EqualFold(logicalVolume, boundVolume) {
		return fmt.Errorf(
			"Windows locator volume does not match its bound physical target volume: %s != %s",
			logicalVolume, boundVolume,
		)
	}
	return nil
}

func atomicTransformWindowsVolumeGUIDForPath(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	mount := make([]uint16, 32768)
	if err := windows.GetVolumePathName(pointer, &mount[0], uint32(len(mount))); err != nil {
		return "", err
	}
	mountPointer := &mount[0]
	volume := make([]uint16, 128)
	if err := windows.GetVolumeNameForVolumeMountPoint(
		mountPointer, &volume[0], uint32(len(volume)),
	); err != nil {
		return "", err
	}
	return strings.TrimRight(windows.UTF16ToString(volume), `\`), nil
}

func atomicTransformWindowsVolumeGUIDForHandle(handle windows.Handle) (string, error) {
	const volumeNameGUID = 0x1
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(
			handle, &buffer[0], uint32(len(buffer)), volumeNameGUID,
		)
		if err == nil && length < uint32(len(buffer)) {
			path := windows.UTF16ToString(buffer[:length])
			end := strings.Index(path, `}\`)
			if !strings.HasPrefix(strings.ToLower(path), `\\?\volume{`) || end < 0 {
				return "", fmt.Errorf("unexpected volume-GUID final path %q", path)
			}
			return path[:end+1], nil
		}
		if length >= uint32(len(buffer)) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			buffer = make([]uint16, int(length)+1)
			continue
		}
		return "", err
	}
}

func atomicTransformValidateDirectoryCaseSemantics(dir string) error {
	path, err := winpath.UTF16Ptr(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		path,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("open compare-and-swap directory for case-semantics query: %w", err)
	}
	defer windows.CloseHandle(handle)
	var flags uint32
	err = windows.GetFileInformationByHandleEx(
		handle,
		windows.FileCaseSensitiveInfo,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query compare-and-swap directory case semantics: %w", err)
	}
	if flags&windows.FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
		return fmt.Errorf("case-sensitive Windows directory is unsupported for compare-and-swap recovery: %s", dir)
	}
	return nil
}
