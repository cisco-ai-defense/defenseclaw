// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import "net"

// listenersHeldOnlyBy is listenersHeldOnlyByThen without the holder mark, on
// the fake socket tables of the tests.
func listenersHeldOnlyBy(procNet, procRoot string, pid int, server *net.TCPAddr) bool {
	return listenersHeldOnlyByThen(procNet, procRoot, pid, server, nil)
}
