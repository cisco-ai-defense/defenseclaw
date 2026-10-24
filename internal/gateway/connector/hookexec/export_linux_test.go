// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"strconv"
	"testing"
)

// UseManagedLinuxGatewayUnitForTest makes systemd report pid as the main
// process of the packaged gateway unit, running as uid. The socket check
// still reads the real /proc/net.
func UseManagedLinuxGatewayUnitForTest(t testing.TB, pid, uid int) {
	t.Helper()
	previous := managedLinuxServiceShow
	managedLinuxServiceShow = func(context.Context) ([]byte, error) {
		return []byte(managedGatewayShowAs(pid, managedLinuxGatewayExecutable, strconv.Itoa(uid), strconv.Itoa(uid))), nil
	}
	t.Cleanup(func() { managedLinuxServiceShow = previous })
}
