// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procprobe

import (
	"fmt"
	"runtime"
	"strconv"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

type processOwner struct {
	name, sid string
	// created is the creation time of the process WMI answered about, read
	// before and after GetOwnerSid. The owner is dropped when the two
	// readings differ: the pid changed hands while the method ran.
	created time.Time
}

// wmiCreationTolerance absorbs the microsecond rounding of CIM datetimes
// against the kernel creation time of the snapshot row.
const wmiCreationTolerance = time.Millisecond

// adoptWMIOwners asks lookup for the owners of the rows whose tokens could
// not be read and copies each one into its row only when WMI answered about
// that process instance: same creation time as the row. The pid of a process
// that exited after the Toolhelp snapshot can already name a process of
// another account when WMI is asked, and that SID must never land on the
// earlier row.
func adoptWMIOwners(
	rows []Process, missing map[uint32]int, lookup func(map[uint32]int) map[uint32]processOwner,
) {
	for pid, owner := range lookup(missing) {
		index, ok := missing[pid]
		if !ok {
			continue
		}
		row := &rows[index]
		delta := row.StartedAt.Sub(owner.created)
		if row.StartedAt.IsZero() || owner.created.IsZero() ||
			delta > wmiCreationTolerance || delta < -wmiCreationTolerance {
			continue
		}
		row.User, row.UserSID = owner.name, owner.sid
	}
}

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

// wmiProcessCreated reads Win32_Process.CreationDate for pid, zero when WMI
// has no such process or no date.
func wmiProcessCreated(service *ole.IDispatch, pid uint32) time.Time {
	processRaw, err := oleutil.CallMethod(service, "Get", fmt.Sprintf(`Win32_Process.Handle="%d"`, pid))
	if err != nil {
		return time.Time{}
	}
	defer processRaw.Clear()
	process := processRaw.ToIDispatch()
	if process == nil {
		return time.Time{}
	}
	return wmiCreationDate(process)
}

func wmiCreationDate(process *ole.IDispatch) time.Time {
	value, err := oleutil.GetProperty(process, "CreationDate")
	if err != nil {
		return time.Time{}
	}
	defer value.Clear()
	return parseCIMDateTime(value.ToString())
}

// parseCIMDateTime parses a CIM datetime, yyyymmddHHMMSS.mmmmmm in local time
// followed by the signed UTC offset in minutes.
func parseCIMDateTime(text string) time.Time {
	if len(text) != 25 {
		return time.Time{}
	}
	local, err := time.ParseInLocation("20060102150405.000000", text[:21], time.UTC)
	if err != nil {
		return time.Time{}
	}
	offset, err := strconv.Atoi(text[21:])
	if err != nil {
		return time.Time{}
	}
	return local.Add(-time.Duration(offset) * time.Minute)
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
	created := wmiCreationDate(process)
	if created.IsZero() {
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
	// GetOwnerSid opens the process by pid when it runs, so read the
	// creation time again: a pid that changed hands meanwhile answered for
	// another process.
	if after := wmiProcessCreated(service, pid); !after.Equal(created) {
		return processOwner{}, false
	}
	name, sidText := windowsOwner(sid)
	return processOwner{name: name, sid: sidText, created: created}, sidText != ""
}
