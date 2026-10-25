// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

// Ended reports a process that has exited but still holds its pid: a zombie
// its parent has not reaped (Linux, macOS), or a process object a handle
// keeps open (Windows). It keeps its identity (Of) and still answers a
// signal, but it runs nothing, so an install lock that names it has no
// owner. False when the system does not say.
func Ended(pid int) bool {
	if pid <= 0 {
		return false
	}
	return ended(pid)
}
