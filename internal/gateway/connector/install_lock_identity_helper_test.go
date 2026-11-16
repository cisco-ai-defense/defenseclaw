// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// installLockIdentityOf is the proc-start record install.sh and install.ps1
// write for process pid (procidentity.Of: the Linux boot id and kernel
// start, the macOS creation second, the Windows creation FILETIME), and the
// record of another process that had the same pid (its last digit changed:
// a reused pid). It skips where the system names no process identity.
func installLockIdentityOf(t *testing.T, pid int) (identity, reused string) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("no process identity reader on " + runtime.GOOS)
	}
	identity, ok := procidentity.Of(pid)
	if !ok || identity == "" {
		t.Fatalf("no process identity for pid %d", pid)
	}
	last := identity[len(identity)-1]
	return identity, identity[:len(identity)-1] + string(rune('0'+(last-'0'+1)%10))
}
