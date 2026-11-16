// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Restart Manager names the processes that hold a file open. It is used only
// to word an error (Setup's native state reads after their retry window, a
// fresh managed file whose old object another program holds open), so every
// failure here means "no name" rather than a different error.
var (
	modRstrtmgr             = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession      = modRstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources = modRstrtmgr.NewProc("RmRegisterResources")
	procRmGetList           = modRstrtmgr.NewProc("RmGetList")
	procRmEndSession        = modRstrtmgr.NewProc("RmEndSession")
)

const (
	rmSessionKeyChars = 32 // CCH_RM_SESSION_KEY
	rmMaxAppNameChars = 255
	rmMaxSvcNameChars = 63
	rmMaxHolders      = 8
)

// rmProcessInfo is RM_PROCESS_INFO.
type rmProcessInfo struct {
	ProcessID        uint32
	ProcessStartTime windows.Filetime
	AppName          [rmMaxAppNameChars + 1]uint16
	ServiceShortName [rmMaxSvcNameChars + 1]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

// FileHolders names, as "<app> (PID <n>)", the processes Restart Manager
// reports holding path open; nil when it cannot tell.
func FileHolders(path string) []string {
	if procRmStartSession.Find() != nil || procRmRegisterResources.Find() != nil ||
		procRmGetList.Find() != nil || procRmEndSession.Find() != nil {
		return nil
	}
	resource, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	var session uint32
	var key [rmSessionKeyChars + 1]uint16
	if r, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0])),
	); r != 0 {
		return nil
	}
	defer procRmEndSession.Call(uintptr(session))

	resources := [1]*uint16{resource}
	if r, _, _ := procRmRegisterResources.Call(
		uintptr(session), 1, uintptr(unsafe.Pointer(&resources[0])), 0, 0, 0, 0,
	); r != 0 {
		return nil
	}
	var infos [rmMaxHolders]rmProcessInfo
	var needed, reasons uint32
	count := uint32(len(infos))
	r, _, _ := procRmGetList.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&infos[0])),
		uintptr(unsafe.Pointer(&reasons)),
	)
	if r == uintptr(windows.ERROR_MORE_DATA) {
		return []string{fmt.Sprintf("%d processes", needed)}
	}
	if r != 0 || count > uint32(len(infos)) {
		return nil
	}
	holders := make([]string, 0, count)
	for _, info := range infos[:count] {
		name := windows.UTF16ToString(info.AppName[:])
		if name == "" {
			name = "process"
		}
		holders = append(holders, fmt.Sprintf("%s (PID %d)", name, info.ProcessID))
	}
	return holders
}
