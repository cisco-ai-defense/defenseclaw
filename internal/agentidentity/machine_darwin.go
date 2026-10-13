// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package agentidentity

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readPlatformMachineID reads the hardware UUID (IOPlatformUUID, the
// "Hardware UUID" in System Information) with gethostuuid(2), so no ioreg
// process is needed. The timeout only matters early in boot, before IOKit
// has published the UUID. Never use the kern.uuid sysctl: it is the UUID of
// the kernel build, the same on every Mac on one macOS build and new after
// every update.
func readPlatformMachineID() (string, error) {
	var id [16]byte
	wait := unix.Timespec{Sec: 5}
	if _, _, errno := unix.Syscall(unix.SYS_GETHOSTUUID,
		uintptr(unsafe.Pointer(&id[0])), uintptr(unsafe.Pointer(&wait)), 0); errno != 0 {
		return "", fmt.Errorf("agentidentity: gethostuuid: %w", errno)
	}
	if id == [16]byte{} {
		return "", errors.New("agentidentity: gethostuuid returned no hardware UUID")
	}
	return fmt.Sprintf("%X-%X-%X-%X-%X", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}
