// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxMountedVolumeUTF16 = 32 * 1024

// finalPathVolumeNameNT is VOLUME_NAME_NT of GetFinalPathNameByHandle: the
// path starts with the kernel device name (\Device\HarddiskVolumeN).
const finalPathVolumeNameNT = 0x2

// MountedVolumeIdentity is the mount-manager identity of a trusted local
// drive. DeviceTarget is the kernel device object backing both the effective
// and global DOS drive names and the volume GUID name.
type MountedVolumeIdentity struct {
	DriveRoot    string
	VolumeName   string
	DeviceTarget string
	FileSystem   string
}

// ValidateFixedNTFSMountedPath rejects UNC/device/ADS paths, mapped,
// substituted, and per-logon DefineDosDevice aliases, removable filesystems,
// and non-NTFS volumes. A valid path must use a drive letter that the Windows
// mount manager lists for the volume, and its effective and global DOS-device
// identities must exactly match that volume. Callers must separately reject
// reparse points in the path chain, including volume-folder mount points.
//
// Standard users can create local DOS aliases for unused drive letters. Such
// aliases can report DRIVE_FIXED and NTFS, so those properties alone are not a
// security boundary.
func ValidateFixedNTFSMountedPath(path string) (MountedVolumeIdentity, error) {
	var identity MountedVolumeIdentity
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return identity, fmt.Errorf("Windows path is empty or contains NUL")
	}
	path = filepath.Clean(filepath.FromSlash(path))
	volume := filepath.VolumeName(path)
	if !isLocalDriveLetterSyntax(path) {
		return identity, fmt.Errorf("path must use a local drive letter without UNC, device, or alternate-stream syntax: %s", path)
	}

	root := strings.ToUpper(volume[:1]) + `:\`
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return identity, fmt.Errorf("encode drive root %s: %w", root, err)
	}
	if driveType := windows.GetDriveType(rootPtr); driveType != windows.DRIVE_FIXED {
		return identity, fmt.Errorf("drive %s is not a fixed local volume (type %d)", root, driveType)
	}

	volumeBuffer := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeNameForVolumeMountPoint(
		rootPtr,
		&volumeBuffer[0],
		uint32(len(volumeBuffer)),
	); err != nil {
		return identity, fmt.Errorf("resolve mount-manager volume for %s: %w", root, err)
	}
	volumeName := windows.UTF16ToString(volumeBuffer)
	if !validVolumeGUIDName(volumeName) {
		return identity, fmt.Errorf("mount manager returned malformed volume name %q for %s", volumeName, root)
	}

	mountPaths, err := volumeMountPaths(volumeName)
	if err != nil {
		return identity, fmt.Errorf("enumerate mount-manager paths for %s: %w", volumeName, err)
	}
	if !containsFold(mountPaths, root) {
		return identity, fmt.Errorf("drive %s is not an exact mount-manager path for %s", root, volumeName)
	}

	driveTarget, err := effectiveDOSDeviceTarget(strings.TrimSuffix(root, `\`))
	if err != nil {
		return identity, fmt.Errorf("resolve effective DOS device for %s: %w", root, err)
	}
	globalTarget, err := globalDOSDeviceTarget(strings.TrimSuffix(root, `\`))
	if err != nil {
		return identity, fmt.Errorf("resolve global DOS device for %s: %w", root, err)
	}
	volumeDevice := strings.TrimSuffix(strings.TrimPrefix(volumeName, `\\?\`), `\`)
	volumeTarget, err := singleDOSDeviceTarget(volumeDevice)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		volumeTarget, err = globalDOSDeviceTarget(volumeDevice)
	}
	if err != nil {
		return identity, fmt.Errorf("resolve DOS device for %s: %w", volumeName, err)
	}
	if !strings.EqualFold(driveTarget, globalTarget) ||
		!strings.EqualFold(driveTarget, volumeTarget) {
		return identity, fmt.Errorf(
			"drive %s DOS-device identity does not match its mount-manager volume",
			root,
		)
	}

	handle, err := openMountedVolumeRoot(root)
	if err != nil {
		return identity, fmt.Errorf("open mounted volume %s: %w", root, err)
	}
	defer windows.CloseHandle(handle)
	fileSystemBuffer := make([]uint16, 64)
	if err := windows.GetVolumeInformationByHandle(
		handle,
		nil,
		0,
		nil,
		nil,
		nil,
		&fileSystemBuffer[0],
		uint32(len(fileSystemBuffer)),
	); err != nil {
		return identity, fmt.Errorf("inspect filesystem for %s: %w", root, err)
	}
	fileSystem := windows.UTF16ToString(fileSystemBuffer)
	if !strings.EqualFold(fileSystem, "NTFS") {
		return identity, fmt.Errorf("drive %s filesystem %q is not NTFS", root, fileSystem)
	}

	return MountedVolumeIdentity{
		DriveRoot:    root,
		VolumeName:   volumeName,
		DeviceTarget: driveTarget,
		FileSystem:   fileSystem,
	}, nil
}

// isLocalDriveLetterSyntax reports whether path is in the exact local
// drive-letter form (e.g. `C:\...`). Rejects UNC, `\\?\` and `\\.\` device
// namespaces, alternate-data-stream syntax (a colon past position 1), and
// non-ASCII drive letters. Callers that also require Clean-idempotence or
// forward-slash rejection perform those checks at the call site.
func isLocalDriveLetterSyntax(path string) bool {
	volume := filepath.VolumeName(path)
	return filepath.IsAbs(path) &&
		len(path) >= 3 && path[2] == '\\' &&
		len(volume) == 2 && volume[1] == ':' &&
		isASCIIDriveLetter(volume[0]) &&
		!strings.HasPrefix(path, `\\`) &&
		!strings.HasPrefix(path, `\\?\`) &&
		!strings.HasPrefix(path, `\\.\`) &&
		!strings.Contains(path[2:], ":")
}

func validVolumeGUIDName(value string) bool {
	const prefix = `\\?\Volume{`
	if !strings.HasPrefix(strings.ToUpper(value), strings.ToUpper(prefix)) ||
		!strings.HasSuffix(value, `}\`) {
		return false
	}
	guid := value[len(prefix) : len(value)-2]
	if len(guid) != 36 {
		return false
	}
	for index := 0; index < len(guid); index++ {
		switch index {
		case 8, 13, 18, 23:
			if guid[index] != '-' {
				return false
			}
		default:
			char := guid[index]
			if !((char >= '0' && char <= '9') ||
				(char >= 'a' && char <= 'f') ||
				(char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	return true
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func volumeMountPaths(volumeName string) ([]string, error) {
	volumePtr, err := windows.UTF16PtrFromString(volumeName)
	if err != nil {
		return nil, err
	}
	size := uint32(256)
	for {
		if size > maxMountedVolumeUTF16 {
			return nil, fmt.Errorf("mount path list exceeds %d UTF-16 code units", maxMountedVolumeUTF16)
		}
		buffer := make([]uint16, size)
		var required uint32
		err = windows.GetVolumePathNamesForVolumeName(
			volumePtr,
			&buffer[0],
			uint32(len(buffer)),
			&required,
		)
		if err == nil {
			if required == 0 || required > uint32(len(buffer)) {
				return nil, fmt.Errorf("mount manager returned invalid path length %d", required)
			}
			return parseMultiSZ(buffer[:required]), nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		if required <= size {
			size *= 2
		} else {
			size = required
		}
	}
}

func singleDOSDeviceTarget(deviceName string) (string, error) {
	if deviceName == "" || strings.IndexByte(deviceName, 0) >= 0 {
		return "", fmt.Errorf("DOS device name is empty or contains NUL")
	}
	namePtr, err := windows.UTF16PtrFromString(deviceName)
	if err != nil {
		return "", err
	}
	size := uint32(256)
	for {
		if size > maxMountedVolumeUTF16 {
			return "", fmt.Errorf("DOS-device target list exceeds %d UTF-16 code units", maxMountedVolumeUTF16)
		}
		buffer := make([]uint16, size)
		n, queryErr := windows.QueryDosDevice(namePtr, &buffer[0], uint32(len(buffer)))
		if queryErr == nil {
			if n == 0 || n > uint32(len(buffer)) {
				return "", fmt.Errorf("DOS-device query returned invalid length %d", n)
			}
			targets := parseMultiSZ(buffer[:n])
			if len(targets) != 1 || targets[0] == "" ||
				!strings.HasPrefix(strings.ToUpper(targets[0]), `\DEVICE\`) {
				return "", fmt.Errorf("expected one kernel device target, got %q", targets)
			}
			return targets[0], nil
		}
		if !errors.Is(queryErr, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", queryErr
		}
		size *= 2
	}
}

func parseMultiSZ(buffer []uint16) []string {
	var values []string
	for start := 0; start < len(buffer); {
		end := start
		for end < len(buffer) && buffer[end] != 0 {
			end++
		}
		if end == start {
			break
		}
		values = append(values, windows.UTF16ToString(buffer[start:end]))
		start = end + 1
	}
	return values
}

// effectiveDOSDeviceTarget returns the kernel device of drive ("C:") as this
// process resolves it: QueryDosDevice, or, when the token cannot read its
// logon session DOS-device directory, the device an open of the drive root
// reaches (effectiveDriveTargetByHandle).
func effectiveDOSDeviceTarget(drive string) (string, error) {
	target, err := singleDOSDeviceTarget(drive)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return target, err
	}
	return effectiveDriveTargetByHandle(drive + `\`)
}

// effectiveDriveTargetByHandle returns the kernel device that an open of
// root reaches through this process DOS-device map, for a token that may not
// query its logon session DOS-device directory. That is the case for a token
// whose Administrators SID is deny-only in a logon session an administrator
// token created (runas /trustlevel:0x20000 of the built-in Administrator, a
// Safer or other filtered token): the directory grants Administrators, so
// QueryDosDevice of the drive fails with access denied, while an open still
// resolves the name, with traverse checking bypassed (cowork-1-0-8 GAP-0052).
// The open resolves a per-logon alias exactly as QueryDosDevice would, so a
// drive alias still shows as a device other than the global one and is
// refused by the comparison in ValidateFixedNTFSMountedPath. Only a token
// that can write that directory can add an alias to it, and that token is
// an administrator.
func effectiveDriveTargetByHandle(root string) (string, error) {
	handle, err := openMountedVolumeRoot(root)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	size := uint32(windows.MAX_PATH + 1)
	for {
		if size > maxMountedVolumeUTF16 {
			return "", fmt.Errorf("final path exceeds %d UTF-16 code units", maxMountedVolumeUTF16)
		}
		buffer := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, finalPathVolumeNameNT)
		if err != nil {
			return "", err
		}
		if n >= size {
			size = n + 1
			continue
		}
		// The volume root: \Device\HarddiskVolumeN\ (one trailing separator).
		target := strings.TrimSuffix(windows.UTF16ToString(buffer[:n]), `\`)
		if !strings.HasPrefix(strings.ToUpper(target), `\DEVICE\`) || strings.Contains(target[len(`\Device\`):], `\`) {
			return "", fmt.Errorf("unexpected final path %q for %s", target, root)
		}
		return target, nil
	}
}

// globalDOSDeviceTarget returns the target of the global DOS device name
// (\GLOBAL??\<name>). QueryDosDevice reaches it through the Global link of
// the logon session DOS-device directory, which a token with Administrators
// deny-only cannot read in a session an administrator token created
// (GAP-0052); the object manager directory \GLOBAL?? itself is readable by
// every account, so the link is then opened there directly.
func globalDOSDeviceTarget(name string) (string, error) {
	target, err := singleDOSDeviceTarget(`Global\` + name)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return target, err
	}
	return globalSymbolicLinkTarget(name)
}

var (
	procNtOpenSymbolicLinkObject  = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenSymbolicLinkObject")
	procNtQuerySymbolicLinkObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySymbolicLinkObject")
)

const symbolicLinkQuery = 0x0001 // SYMBOLIC_LINK_QUERY

func globalSymbolicLinkTarget(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `\/`) || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("invalid DOS device name %q", name)
	}
	objectName, err := windows.NewNTUnicodeString(`\GLOBAL??\` + name)
	if err != nil {
		return "", err
	}
	attributes := windows.OBJECT_ATTRIBUTES{ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var link windows.Handle
	if status, _, _ := procNtOpenSymbolicLinkObject.Call(
		uintptr(unsafe.Pointer(&link)), symbolicLinkQuery, uintptr(unsafe.Pointer(&attributes)),
	); windows.NTStatus(status) != windows.STATUS_SUCCESS {
		return "", fmt.Errorf("open \\GLOBAL??\\%s: %w", name, windows.NTStatus(status))
	}
	defer windows.CloseHandle(link)
	buffer := make([]uint16, windows.MAX_PATH+1)
	target := windows.NTUnicodeString{MaximumLength: uint16(len(buffer) * 2), Buffer: &buffer[0]}
	var returned uint32
	if status, _, _ := procNtQuerySymbolicLinkObject.Call(
		uintptr(link), uintptr(unsafe.Pointer(&target)), uintptr(unsafe.Pointer(&returned)),
	); windows.NTStatus(status) != windows.STATUS_SUCCESS {
		return "", fmt.Errorf("query \\GLOBAL??\\%s: %w", name, windows.NTStatus(status))
	}
	value := target.String()
	if value == "" || !strings.HasPrefix(strings.ToUpper(value), `\DEVICE\`) || strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("expected one kernel device target for %s, got %q", name, value)
	}
	return value, nil
}

func openMountedVolumeRoot(root string) (windows.Handle, error) {
	extended, err := Extended(root)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}
