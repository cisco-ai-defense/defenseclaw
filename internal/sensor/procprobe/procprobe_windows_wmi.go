// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procprobe

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

type processOwner struct{ name, sid string }

// lookupWMIProcessOwners asks the local Win32_Process provider for only the
// PIDs whose process tokens were inaccessible. GetOwnerSid is a WMI method
// available without an elevated caller; WTS process enumeration requires
// Administrators membership for another user's processes.
func lookupWMIProcessOwners(wanted map[uint32]int) map[uint32]processOwner {
	owners := make(map[uint32]processOwner)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || oleErr.Code() != 1 { // S_FALSE: already initialized on this thread
			return owners
		}
	}
	defer ole.CoUninitialize()
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return owners
	}
	defer unknown.Release()
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return owners
	}
	defer locator.Release()
	serviceRaw, err := oleutil.CallMethod(locator, "ConnectServer", ".", `Root\CIMV2`)
	if err != nil {
		return owners
	}
	defer serviceRaw.Clear()
	service := serviceRaw.ToIDispatch()
	if service == nil {
		return owners
	}
	securityRaw, err := oleutil.GetProperty(service, "Security_")
	if err != nil {
		return owners
	}
	security := securityRaw.ToIDispatch()
	if security == nil {
		_ = securityRaw.Clear()
		return owners
	}
	set, err := oleutil.PutProperty(security, "ImpersonationLevel", 3)
	if set != nil {
		_ = set.Clear()
	}
	_ = securityRaw.Clear()
	if err != nil {
		return owners
	}
	for pid := range wanted {
		if owner, ok := wmiProcessOwner(service, pid); ok {
			owners[pid] = owner
		}
	}
	return owners
}

func wmiProcessOwner(service *ole.IDispatch, pid uint32) (processOwner, bool) {
	processRaw, err := oleutil.CallMethod(service, "Get", fmt.Sprintf(`Win32_Process.Handle="%d"`, pid))
	if err != nil {
		return processOwner{}, false
	}
	defer processRaw.Clear()
	process := processRaw.ToIDispatch()
	if process == nil {
		return processOwner{}, false
	}
	resultRaw, err := oleutil.CallMethod(process, "ExecMethod_", "GetOwnerSid")
	if err != nil {
		return processOwner{}, false
	}
	defer resultRaw.Clear()
	result := resultRaw.ToIDispatch()
	if result == nil {
		return processOwner{}, false
	}
	status, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		return processOwner{}, false
	}
	code := status.Value()
	_ = status.Clear()
	if code != int32(0) && code != uint32(0) {
		return processOwner{}, false
	}
	value, err := oleutil.GetProperty(result, "Sid")
	if err != nil {
		return processOwner{}, false
	}
	sidText := value.ToString()
	_ = value.Clear()
	sid, err := windows.StringToSid(sidText)
	if err != nil {
		return processOwner{}, false
	}
	name, sidText := windowsOwner(sid)
	return processOwner{name: name, sid: sidText}, sidText != ""
}
