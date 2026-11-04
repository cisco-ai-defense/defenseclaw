//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "golang.org/x/sys/unix"

// clearManagedFileRestrictiveAttributes clears the user immutable and
// append-only flags on a managed file, through a descriptor opened without
// following links, so the next managed write is not refused. EnsureCanonical
// already clears them as part of a repair; this covers a caller that only
// wants the flags gone.
func clearManagedFileRestrictiveAttributes(path string) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return
	}
	if st.Flags&darwinUserBlockingFlags == 0 {
		return
	}
	if err := unix.Fchflags(fd, int(st.Flags&^darwinUserBlockingFlags)); err == nil {
		EmitResilienceEvent(MarkerRepair, map[string]string{
			"path":   path,
			"reason": "write-blocking flags " + darwinFlagNames(st.Flags&darwinUserBlockingFlags) + " cleared",
		})
	}
}
