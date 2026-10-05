// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package agentidentity

import "golang.org/x/sys/unix"

// readPlatformMachineID reads the hardware UUID. kern.uuid is the kernel's
// copy of IOPlatformUUID, so no ioreg process is needed.
func readPlatformMachineID() (string, error) {
	return unix.Sysctl("kern.uuid")
}
