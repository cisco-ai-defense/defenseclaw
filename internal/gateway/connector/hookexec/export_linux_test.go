// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"testing"
)

// UseManagedLinuxGatewayUnitForTest makes systemd report pid as the main
// process of the packaged gateway unit. The socket and service account
// checks still read the real /proc.
func UseManagedLinuxGatewayUnitForTest(t testing.TB, pid int) {
	t.Helper()
	previous := managedLinuxServiceShow
	managedLinuxServiceShow = func(context.Context) ([]byte, error) {
		return []byte(managedGatewayShow(pid, managedLinuxGatewayExecutable)), nil
	}
	t.Cleanup(func() { managedLinuxServiceShow = previous })
}
