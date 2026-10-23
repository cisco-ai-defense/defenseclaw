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
// coverage. It requires a privileged process handle and never returns the
// complete environment, which can contain credentials. A failed or partial
// read leaves coverage unverified.
func LaunchEnvironmentForPID(pid int) (map[string]string, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return nil, errors.New("invalid process ID")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("open process: %w", err)
	}
	defer windows.CloseHandle(handle)

	// ProcessWow64Information returns the 32-bit PEB address for a WOW64
	// process. Otherwise ProcessBasicInformation returns the native PEB.
	width := int(unsafe.Sizeof(uintptr(0)))
	var wowPEB uintptr
	if width == 8 {
		if err := windows.NtQueryInformationProcess(handle, windows.ProcessWow64Information,
			unsafe.Pointer(&wowPEB), uint32(width), nil); err != nil {
			return nil, fmt.Errorf("query WOW64 PEB: %w", err)
		}
	}
	var peb uintptr
	if wowPEB != 0 {
		peb, width = wowPEB, 4
	} else {
		// Use the aligned native layout; NtQueryInformationProcess can
		// reject a raw byte buffer with STATUS_DATATYPE_MISALIGNMENT.
		var info windows.PROCESS_BASIC_INFORMATION
		if err := windows.NtQueryInformationProcess(handle, windows.ProcessBasicInformation,
			unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return nil, fmt.Errorf("query native PEB: %w", err)
		}
		peb = uintptr(unsafe.Pointer(info.PebBaseAddress))
	}
	if peb == 0 {
		return nil, errors.New("process PEB is unavailable")
	}
	// PEB.ProcessParameters and RTL_USER_PROCESS_PARAMETERS.Environment
	// are native layout fields. Windows documents the PEB pointer and the
	// process-parameters link, but may change the Environment field layout;
	// any unreadable or implausible pointer stays unverified.
	parametersOffset, environmentOffset := uintptr(0x20), uintptr(0x80)
	if width == 4 {
		parametersOffset, environmentOffset = 0x10, 0x48
	}
	parameters, err := readLaunchPointer(handle, peb+parametersOffset, width)
	if err != nil || parameters == 0 {
		return nil, fmt.Errorf("read process parameters: %w", errOrUnavailable(err))
	}
	var header [8]byte
	var n uintptr
	if err := windows.ReadProcessMemory(handle, parameters, &header[0], uintptr(len(header)), &n); err != nil || n != uintptr(len(header)) {
		return nil, fmt.Errorf("read process parameters header: %w", errOrUnavailable(err))
	}
	maximum, length := binary.LittleEndian.Uint32(header[:4]), binary.LittleEndian.Uint32(header[4:])
	if length < uint32(environmentOffset)+uint32(width) || maximum < length || maximum > maxLaunchEnvironmentBytes {
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
	case "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "XDG_CONFIG_HOME",
		"OPENCODE_PURE", "OPENCODE_TEST_MANAGED_CONFIG_DIR",
		"KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR",
		"HERMES_HOME", "HERMES_MANAGED_DIR", "HERMES_SAFE_MODE":
		return true
	}
	return false
}
