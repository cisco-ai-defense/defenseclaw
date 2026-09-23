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
	return atomicTransformValidateStableVolumeLocatorWindows(
		locator, boundParent, windows.QueryDosDevice,
	)
}

func atomicTransformValidateStableVolumeLocatorWindows(
	locator string,
	boundParent *atomicTransformBoundDirectory,
	queryDosDevice func(*uint16, *uint16, uint32) (uint32, error),
) error {
	absolute, err := filepath.Abs(locator)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	drive, isDOSDrive := atomicTransformWindowsDOSDrive(volume)
	if isDOSDrive {
		if queryDosDevice == nil {
			return fmt.Errorf("query Windows DOS-device mapping for %s: unavailable", drive)
		}
		device, pointerErr := windows.UTF16PtrFromString(drive)
		if pointerErr != nil {
			return pointerErr
		}
		buffer := make([]uint16, 32768)
		length, queryErr := queryDosDevice(device, &buffer[0], uint32(len(buffer)))
		// A restricted standard-user token can be denied access to the DOS-device
		// object namespace. Only that denial may fall through to the independent,
		// positive Mount Manager and bound-handle proof below.
		if queryErr != nil && !errors.Is(queryErr, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("query Windows DOS-device mapping for %s: %w", drive, queryErr)
		}
		if queryErr == nil {
			if length == 0 || length > uint32(len(buffer)) {
				return fmt.Errorf("query Windows DOS-device mapping for %s returned an invalid result", drive)
			}
			target := windows.UTF16ToString(buffer[:length])
			if strings.HasPrefix(strings.ToLower(target), `\??\`) {
				return fmt.Errorf("retargetable Windows DOS-device/SUBST locator is unsupported: %s", drive)
			}
		}
	}
	logicalVolume, logicalMount, err := atomicTransformWindowsVolumeGUIDForPath(absolute)
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
	if isDOSDrive {
		// Prefix plus registered-membership proof rejects both forms exposed by a
		// retargetable alias: an unregistered X:\ mount and a followed C:\ mount
		// whose spelling is no longer a prefix of the caller's X:\ locator.
		if !atomicTransformWindowsMountContainsLocator(logicalMount, absolute) {
			return fmt.Errorf(
				"Windows Mount Manager path is not a stable prefix of its locator: %s is not within %s",
				absolute, logicalMount,
			)
		}
		registeredPaths, pathsErr := atomicTransformWindowsVolumePaths(boundVolume)
		if pathsErr != nil {
			return fmt.Errorf("enumerate bound Windows volume paths through Mount Manager: %w", pathsErr)
		}
		if !atomicTransformWindowsMountIsRegistered(logicalMount, registeredPaths) {
			return fmt.Errorf(
				"Windows Mount Manager path is not registered for its bound physical volume: %s",
				logicalMount,
			)
		}
	}
	return nil
}

func atomicTransformWindowsDOSDrive(volume string) (string, bool) {
	if len(volume) == 6 && strings.EqualFold(volume[:4], `\\?\`) {
		volume = volume[4:]
	}
	if len(volume) != 2 || volume[1] != ':' ||
		!((volume[0] >= 'a' && volume[0] <= 'z') || (volume[0] >= 'A' && volume[0] <= 'Z')) {
		return "", false
	}
	return strings.ToUpper(volume), true
}

func atomicTransformWindowsVolumeGUIDForPath(path string) (string, string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", "", err
	}
	mount := make([]uint16, 32768)
	if err := windows.GetVolumePathName(pointer, &mount[0], uint32(len(mount))); err != nil {
		return "", "", err
	}
	mountPath := windows.UTF16ToString(mount)
	if mountPath == "" {
		return "", "", fmt.Errorf("Mount Manager returned an empty volume path")
	}
	mountPointer := &mount[0]
	volume := make([]uint16, 128)
	if err := windows.GetVolumeNameForVolumeMountPoint(
		mountPointer, &volume[0], uint32(len(volume)),
	); err != nil {
		return "", "", err
	}
	volumeGUID := strings.TrimRight(windows.UTF16ToString(volume), `\`)
	if volumeGUID == "" {
		return "", "", fmt.Errorf("Mount Manager returned an empty volume identity")
	}
	return volumeGUID, mountPath, nil
}

func atomicTransformWindowsMountContainsLocator(mount, locator string) bool {
	mount = atomicTransformNormalizeWindowsDrivePath(mount)
	locator = atomicTransformNormalizeWindowsDrivePath(locator)
	relative, err := filepath.Rel(mount, locator)
	if err != nil || filepath.IsAbs(relative) || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, `..\`)
}

func atomicTransformNormalizeWindowsDrivePath(path string) string {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if len(volume) == 6 && strings.EqualFold(volume[:4], `\\?\`) {
		return filepath.Clean(volume[4:] + strings.TrimPrefix(path, volume))
	}
	return path
}

func atomicTransformWindowsMountIsRegistered(mount string, registered []string) bool {
	mount = atomicTransformNormalizeWindowsDrivePath(mount)
	for _, candidate := range registered {
		if atomicTransformPathsEqualPlatform(
			mount, atomicTransformNormalizeWindowsDrivePath(candidate),
		) {
			return true
		}
	}
	return false
}

func atomicTransformWindowsVolumePaths(volumeGUID string) ([]string, error) {
	volumeGUID = strings.TrimRight(volumeGUID, `\`) + `\`
	pointer, err := windows.UTF16PtrFromString(volumeGUID)
	if err != nil {
		return nil, err
	}
	const maxVolumePathUnits = 32768
	bufferLength := uint32(512)
	for {
		buffer := make([]uint16, bufferLength)
		var required uint32
		err = windows.GetVolumePathNamesForVolumeName(
			pointer, &buffer[0], bufferLength, &required,
		)
		if err == nil {
			if required < 2 || required > bufferLength {
				return nil, fmt.Errorf("Mount Manager returned invalid volume-path length %d", required)
			}
			return atomicTransformParseWindowsMultiString(buffer[:required])
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		if required <= bufferLength || required > maxVolumePathUnits {
			return nil, fmt.Errorf(
				"Mount Manager volume-path list requires invalid length %d", required,
			)
		}
		bufferLength = required
	}
}

func atomicTransformParseWindowsMultiString(buffer []uint16) ([]string, error) {
	if len(buffer) < 2 || buffer[len(buffer)-1] != 0 || buffer[len(buffer)-2] != 0 {
		return nil, fmt.Errorf("Mount Manager returned a malformed volume-path list")
	}
	paths := make([]string, 0, 2)
	start := 0
	for index := 0; index < len(buffer)-1; index++ {
		if buffer[index] != 0 {
			continue
		}
		if index == start {
			return nil, fmt.Errorf("Mount Manager returned an empty volume path")
		}
		path := windows.UTF16ToString(buffer[start:index])
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("Mount Manager returned a non-absolute volume path %q", path)
		}
		paths = append(paths, path)
		start = index + 1
	}
	if start != len(buffer)-1 || len(paths) == 0 {
		return nil, fmt.Errorf("Mount Manager returned a malformed volume-path list")
	}
	return paths, nil
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
