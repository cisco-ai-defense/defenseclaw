// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

// Only the Windows managed gateway is a service whose state the hook reads
// while a call waits (watchManagedGatewayService); the Linux standalone unit
// has its own watch (standaloneGatewayServiceProbe).
var platformManagedGatewayServiceRunning func(string) (bool, bool)
