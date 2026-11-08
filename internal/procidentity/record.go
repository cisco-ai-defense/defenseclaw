// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

// Recorded names process pid the way the gateway names itself in the
// start_identity of its gateway.pid record. The gateway (internal/daemon)
// writes it and every reader of that record compares against it, so this is
// the one place that decides the text:
//
//   - Linux: field 22 of /proc/<pid>/stat, the bare clock ticks since boot.
//   - macOS: the kern.proc start time as "<seconds>.<microseconds>".
//
// It is not Of: Of is the install lock's owner record and carries the boot id
// (Linux) or the creation second in ps lstart form (macOS). A reader that
// compares a gateway.pid record with Of never matches. False on a system with
// no reader here (Windows: the gateway reads its own creation time).
func Recorded(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	return recorded(pid)
}

// IsRecorded reports whether process pid is the process a gateway.pid
// start_identity names: the system names it the same way now, so a reused pid
// is no match. An empty record names nothing.
func IsRecorded(pid int, startIdentity string) bool {
	if startIdentity == "" {
		return false
	}
	live, ok := Recorded(pid)
	return ok && live == startIdentity
}
