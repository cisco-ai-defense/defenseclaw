// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listenerProcessLabel names the program of the process holding the API port
// and, when this account may open it, its account. A standard account cannot
// open another account's process, but the process snapshot still lists its
// image name (GAP-1345).
func listenerProcessLabel(pid int) string {
	image, account := describeWindowsEnterpriseProcess(pid)
	name := filepath.Base(image)
	if image == "" {
		name = snapshotProcessImage(pid)
	}
	switch {
	case name == "":
		return ""
	case account != "":
		return name + ", " + account
	case strings.EqualFold(name, "defenseclaw-gateway.exe"):
		return name + ", probably another account's DefenseClaw gateway"
	}
	return name
}

func snapshotProcessImage(pid int) string {
	if pid <= 0 {
		return ""
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(pid) {
			return windows.UTF16ToString(entry.ExeFile[:])
		}
	}
	return ""
}
