// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import "syscall"

func processAlive(pid int) bool    { return syscall.Kill(pid, 0) == nil }
func signalRecreateSocket(pid int) { _ = syscall.Kill(pid, syscall.SIGUSR1) }
