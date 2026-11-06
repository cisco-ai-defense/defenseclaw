// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// sameHomeGatewayProcessPlatform diagnoses this account's foreground gateway
// that has no PID record (GAP-0694). Windows names no listener UID, so the
// owner is the process token's user, compared with this process's. The image
// must be this gateway's executable file. The home is read from the launch
// environment of that very process (DEFENSECLAW_HOME, else USERPROFILE's
// .defenseclaw), the Windows twin of /proc/<pid>/environ and KERN_PROCARGS2:
// a record file in some home cannot stand in for it, however it was written.
// The handle stays open across the reads, so the PID cannot be reused
// meanwhile. The result never authorizes a token or process control.
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
	environment, err := agentprocess.LaunchEnvironmentForPID(pid)
	if err != nil {
		return false
	}
	processHome, ok := foregroundLaunchHomeFrom(foregroundLaunchEntries(environment), "USERPROFILE")
	return ok && sameForegroundFile(processHome, home) && windowsProcessRunning(process)
}

// foregroundLaunchEntries renders the selected launch variables as
// NAME=value entries for foregroundLaunchHomeFrom.
func foregroundLaunchEntries(environment map[string]string) []string {
	entries := make([]string, 0, 2)
	for _, name := range []string{"DEFENSECLAW_HOME", "USERPROFILE"} {
		if value, ok := environment[name]; ok {
			entries = append(entries, name+"="+value)
		}
	}
	return entries
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
