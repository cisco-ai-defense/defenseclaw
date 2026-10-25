// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package procidentity names a process by what the operating system keeps
// from the moment it was created, so a reused pid is told from the process
// that had it without reading any clock. It is the install lock's owner
// record (proc-start): install.sh and install.ps1 write their own beside the
// lock's pid, and every per-user hook, both per-user plugins and
// `defenseclaw doctor` compare it, as text, with what the system names now.
//
//   - Linux: "<boot_id> <starttime>", the boot id and field 22 of
//     /proc/<pid>/stat (clock ticks since boot).
//   - macOS: the creation second (kern.proc.pid p_starttime) as
//     `LC_ALL=C TZ=UTC ps -o lstart=` prints it, one space between fields
//     ("Sun Oct 25 07:40:20 2026").
//   - Windows: the creation FILETIME of GetProcessTimes, in decimal, as
//     PowerShell's (Get-Process -Id <pid>).StartTime.ToFileTimeUtc() prints it.
//
// A wall-clock step moves none of them.
package procidentity

import "time"

// Of names process pid; false when the system does not say (no such
// process, access denied, a system without a reader).
func Of(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	return of(pid)
}

// lstartLayout is ps's lstart in the C locale (strftime %c), with the
// padding of the day collapsed to one space.
const lstartLayout = "Mon Jan 2 15:04:05 2006"

// lstart is the macOS record of a process created at second sec (UTC).
func lstart(sec int64) string {
	return time.Unix(sec, 0).UTC().Format(lstartLayout)
}
