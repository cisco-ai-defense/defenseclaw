// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// sameHomeGatewayProcessPlatform diagnoses this account's foreground gateway
// that has no PID record (GAP-0694). Windows names no listener UID, so the
// owner is the process token's user, compared with this process's. The image
// must be this gateway's executable file, and the home is proved by the
// private runtime record (gateway-api.json) a gateway writes in its own data
// directory after it starts: it must name this PID and be newer than the
// process. The handle stays open across the reads, so the PID cannot be
// reused meanwhile. The result never authorizes a token or process control.
func sameHomeGatewayProcessPlatform(pid int, home, executable string) bool {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	if !windowsProcessRunning(process) || !windowsProcessOfThisAccount(process) {
		return false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if windows.QueryFullProcessImageName(process, 0, &buffer[0], &size) != nil ||
		!sameForegroundFile(windows.UTF16ToString(buffer[:size]), executable) {
		return false
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil {
		return false
	}
	record, err := os.Lstat(filepath.Join(filepath.Clean(home), "gateway-api.json"))
	if err != nil || record.ModTime().UnixNano() < created.Nanoseconds() {
		return false
	}
	return gatewayRuntimeRecordNamesPID(home, pid) && windowsProcessRunning(process)
}

// windowsProcessRunning waits on the handle instead of reading the exit
// code, which a process that exited with 259 (STILL_ACTIVE) would fake.
func windowsProcessRunning(process windows.Handle) bool {
	event, err := windows.WaitForSingleObject(process, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}

func windowsProcessOfThisAccount(process windows.Handle) bool {
	own, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	peer, err := token.GetTokenUser()
	return err == nil && sameWindowsAccount(own.User.Sid, peer.User.Sid)
}

// sameWindowsAccount accepts only an interactive account: LocalSystem and
// the service accounts run managed services, never a per-user foreground
// gateway, as defenseclaw status (GAP-0604) also requires.
func sameWindowsAccount(own, peer *windows.SID) bool {
	if own == nil || peer == nil || !own.IsValid() || !peer.IsValid() {
		return false
	}
	for _, service := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid, windows.WinLocalServiceSid, windows.WinNetworkServiceSid,
	} {
		if own.IsWellKnown(service) {
			return false
		}
	}
	return own.Equals(peer)
}
