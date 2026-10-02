// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// gatewayMinFreeDiskBytes is the free space a gateway start needs on the disk
// that holds its data folder (pid and state files, the audit database and its
// WAL, gateway.log).
const gatewayMinFreeDiskBytes uint64 = 32 << 20

// dataDirFreeBytes reports the free space for dir; tests replace it.
var dataDirFreeBytes = platformFreeDiskBytes

// gatewayLowDiskProblem describes a disk too full for the gateway, or "" when
// there is enough space or the free space cannot be read.
func gatewayLowDiskProblem(dataDir string) string {
	free, err := dataDirFreeBytes(dataDir)
	if err != nil || free >= gatewayMinFreeDiskBytes {
		return ""
	}
	return fmt.Sprintf("the disk holding %s is full (%d MB free; the gateway needs at least %d MB)",
		dataDir, free>>20, gatewayMinFreeDiskBytes>>20)
}

// gatewayDiskFullError refuses start and restart before they stop or launch
// anything when the data disk is full. A restart used to stop the healthy
// gateway and then fail to write its pid file, which left every agent session
// without a gateway (GAP-1813).
func gatewayDiskFullError(verb, dataDir string) error {
	problem := gatewayLowDiskProblem(dataDir)
	if problem == "" {
		return nil
	}
	untouched := ""
	if verb == "restart" {
		untouched = " Nothing was stopped."
	}
	if running, pid := daemon.New(dataDir).IsRunning(); running {
		untouched += fmt.Sprintf(" The gateway (PID %d) is still running.", pid)
	}
	return fmt.Errorf("cannot %s the gateway: %s.%s Free some space on that disk, then run: defenseclaw-gateway %s",
		verb, problem, untouched, verb)
}

// gatewayStartFailureDiskNote names a full disk after a failed start, whose
// own error (a pid write, the audit store open, an agent's state database)
// does not always say so (GAP-1813).
func gatewayStartFailureDiskNote(dataDir string) string {
	if problem := gatewayLowDiskProblem(dataDir); problem != "" {
		return "; " + problem + ": free some space, then run: defenseclaw-gateway start"
	}
	return ""
}
