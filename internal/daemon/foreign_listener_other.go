// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

// ForeignListenerPID is the Windows listener-ownership check. Linux and macOS
// hooks and CLI calls name another account's listener from the kernel's
// socket tables instead (GAP-1260), so it always returns 0 here.
func ForeignListenerPID(string, int, string) int { return 0 }
