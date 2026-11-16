// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentprocess

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxLaunchEnvironmentBytes = 1 << 20

// LaunchEnvironmentForPID reads only the launch selectors needed by managed
// coverage and by the foreground gateway home proof (DEFENSECLAW_HOME). It
// requires a privileged process handle and never returns the complete
// environment, which can contain credentials. A failed or partial read
// leaves coverage unverified.
func LaunchEnvironmentForPID(pid int) (map[string]string, error) {
	handle, err := openProcessForRead(pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	parameters, width, length, err := processParameters(handle)
	if err != nil {
		return nil, err
	}
	// RTL_USER_PROCESS_PARAMETERS.Environment is a native layout field.
	// Windows may change it; any unreadable or implausible pointer stays
	// unverified.
	environmentOffset := uintptr(0x80)
	if width == 4 {
		environmentOffset = 0x48
	}
	if length < uint32(environmentOffset)+uint32(width) {
		return nil, errors.New("process parameters layout is unverified")
	}
	environment, err := readLaunchPointer(handle, parameters+environmentOffset, width)
	if err != nil || environment == 0 {
		return nil, fmt.Errorf("read process environment pointer: %w", errOrUnavailable(err))
	}
	raw, err := readLaunchEnvironmentBlock(handle, environment)
	if err != nil {
		return nil, err
	}
	return parseLaunchEnvironmentBlock(raw)
}

// openProcessForRead opens a process for reading its memory. The caller
// closes the handle.
func openProcessForRead(pid int) (windows.Handle, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return 0, errors.New("invalid process ID")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("open process: %w", err)
	}
	return handle, nil
}

// processParameters returns the address of the RTL_USER_PROCESS_PARAMETERS of
// the process an open handle names, the pointer width of the process and the
// Length the structure states for itself. It leaves the handle to its owner,
// which closes it on every return, a failed read included.
func processParameters(handle windows.Handle) (parameters uintptr, width int, length uint32, err error) {
	// ProcessWow64Information returns the 32-bit PEB address for a WOW64
	// process. Otherwise ProcessBasicInformation returns the native PEB.
	width = int(unsafe.Sizeof(uintptr(0)))
	var wowPEB uintptr
	if width == 8 {
		if err = windows.NtQueryInformationProcess(handle, windows.ProcessWow64Information,
			unsafe.Pointer(&wowPEB), uint32(width), nil); err != nil {
			return 0, 0, 0, fmt.Errorf("query WOW64 PEB: %w", err)
		}
	}
	var peb uintptr
	if wowPEB != 0 {
		peb, width = wowPEB, 4
	} else {
		// Use the aligned native layout; NtQueryInformationProcess can
		// reject a raw byte buffer with STATUS_DATATYPE_MISALIGNMENT.
		var info windows.PROCESS_BASIC_INFORMATION
		if err = windows.NtQueryInformationProcess(handle, windows.ProcessBasicInformation,
			unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return 0, 0, 0, fmt.Errorf("query native PEB: %w", err)
		}
		peb = uintptr(unsafe.Pointer(info.PebBaseAddress))
	}
	if peb == 0 {
		return 0, 0, 0, errors.New("process PEB is unavailable")
	}
	// PEB.ProcessParameters is a native layout field Windows documents.
	parametersOffset := uintptr(0x20)
	if width == 4 {
		parametersOffset = 0x10
	}
	parameters, err = readLaunchPointer(handle, peb+parametersOffset, width)
	if err != nil || parameters == 0 {
		return 0, 0, 0, fmt.Errorf("read process parameters: %w", errOrUnavailable(err))
	}
	var header [8]byte
	var n uintptr
	if err = windows.ReadProcessMemory(handle, parameters, &header[0], uintptr(len(header)), &n); err != nil || n != uintptr(len(header)) {
		return 0, 0, 0, fmt.Errorf("read process parameters header: %w", errOrUnavailable(err))
	}
	maximum := binary.LittleEndian.Uint32(header[:4])
	length = binary.LittleEndian.Uint32(header[4:])
	if maximum < length || maximum > maxLaunchEnvironmentBytes {
		return 0, 0, 0, errors.New("process parameters layout is unverified")
	}
	return parameters, width, length, nil
}

// workingDirectory reads the current directory of a process of the same user
// from its process parameters: RTL_USER_PROCESS_PARAMETERS.CurrentDirectory,
// a UNICODE_STRING. A failed or implausible read returns "": the caller
// keeps its other sources.
func workingDirectory(pid int) string {
	handle, err := openProcessForRead(pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)
	parameters, width, length, err := processParameters(handle)
	if err != nil {
		return ""
	}
	// CurrentDirectory.DosPath: Length (uint16) and MaximumLength (uint16),
	// then the buffer pointer after the padding the pointer width needs.
	currentOffset, bufferOffset := uintptr(0x38), uintptr(8)
	if width == 4 {
		currentOffset, bufferOffset = 0x24, 4
	}
	if length < uint32(currentOffset+bufferOffset)+uint32(width) {
		return ""
	}
	var text [4]byte
	var n uintptr
	if err := windows.ReadProcessMemory(handle, parameters+currentOffset, &text[0], uintptr(len(text)), &n); err != nil || n != uintptr(len(text)) {
		return ""
	}
	size, capacity := binary.LittleEndian.Uint16(text[:2]), binary.LittleEndian.Uint16(text[2:])
	if size == 0 || size%2 != 0 || size > capacity {
		return ""
	}
	buffer, err := readLaunchPointer(handle, parameters+currentOffset+bufferOffset, width)
	if err != nil || buffer == 0 {
		return ""
	}
	raw := make([]byte, size)
	if err := windows.ReadProcessMemory(handle, buffer, &raw[0], uintptr(size), &n); err != nil || n != uintptr(size) {
		return ""
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	dir := string(utf16.Decode(units))
	if len(dir) > 3 {
		// The system keeps a trailing separator; only a drive root needs it.
		dir = strings.TrimRight(dir, `\/`)
	}
	return dir
}

func errOrUnavailable(err error) error {
	if err != nil {
		return err
	}
	return errors.New("unavailable")
}

func launchPointer(raw []byte, width int) uintptr {
	if width == 4 {
		return uintptr(binary.LittleEndian.Uint32(raw))
	}
	return uintptr(binary.LittleEndian.Uint64(raw))
}

func readLaunchPointer(handle windows.Handle, address uintptr, width int) (uintptr, error) {
	var raw [8]byte
	var n uintptr
	if err := windows.ReadProcessMemory(handle, address, &raw[0], uintptr(width), &n); err != nil {
		return 0, err
	}
	if n != uintptr(width) {
		return 0, errors.New("short process memory read")
	}
	return launchPointer(raw[:], width), nil
}

func readLaunchEnvironmentBlock(handle windows.Handle, address uintptr) ([]byte, error) {
	var raw []byte
	for len(raw) < maxLaunchEnvironmentBytes {
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, address, &region, unsafe.Sizeof(region)); err != nil {
			return nil, fmt.Errorf("query process environment memory: %w", err)
		}
		end := region.BaseAddress + region.RegionSize
		if region.State != windows.MEM_COMMIT || region.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) != 0 ||
			end <= address || end < region.BaseAddress {
			return nil, errors.New("process environment memory is unavailable")
		}
		size := min(uintptr(4096), end-address, uintptr(maxLaunchEnvironmentBytes-len(raw)))
		// Environment entries are UTF-16, so never split a code unit.
		size &^= 1
		if size == 0 {
			return nil, errors.New("process environment memory is incomplete")
		}
		chunk := make([]byte, size)
		var n uintptr
		if err := windows.ReadProcessMemory(handle, address, &chunk[0], size, &n); err != nil {
			return nil, fmt.Errorf("read process environment block: %w", err)
		}
		if n != size {
			return nil, errors.New("short process environment read")
		}
		previousLength := len(raw)
		raw = append(raw, chunk...)
		first := max(2, previousLength-2)
		for i := first; i+1 < len(raw); i += 2 {
			if binary.LittleEndian.Uint16(raw[i-2:i]) == 0 && binary.LittleEndian.Uint16(raw[i:i+2]) == 0 {
				return raw[:i+2], nil
			}
		}
		address += size
	}
	return nil, errors.New("process environment exceeds inspection limit")
}

func parseLaunchEnvironmentBlock(raw []byte) (map[string]string, error) {
	if len(raw)%2 != 0 || len(raw) < 4 {
		return nil, errors.New("malformed process environment")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	if units[len(units)-1] != 0 || units[len(units)-2] != 0 {
		return nil, errors.New("unterminated process environment")
	}
	out := map[string]string{}
	for start, i := 0, 0; i < len(units); i++ {
		if units[i] != 0 {
			continue
		}
		if i == start {
			if i != len(units)-1 {
				return nil, errors.New("malformed process environment entry")
			}
			break
		}
		entry := string(utf16.Decode(units[start:i]))
		key, value, ok := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if ok && launchEnvironmentKey(key) {
			if previous, duplicate := out[key]; duplicate && previous != value {
				return nil, errors.New("conflicting process environment entries")
			}
			out[key] = value
		}
		start = i + 1
	}
	return out, nil
}

func launchEnvironmentKey(key string) bool {
	switch key {
	case "DEFENSECLAW_HOME", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "XDG_CONFIG_HOME",
		"OPENCODE_PURE", "OPENCODE_TEST_MANAGED_CONFIG_DIR",
		"KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR",
		"HERMES_HOME", "HERMES_MANAGED_DIR", "HERMES_SAFE_MODE":
		return true
	}
	return false
}
