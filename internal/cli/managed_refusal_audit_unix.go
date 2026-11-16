// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func managedRefusalSocket() string {
	descriptor, err := managed.LoadRuntimeDescriptor(managedHostDescriptorPath())
	if err != nil || descriptor.HookSocket == "" {
		return ""
	}
	return descriptor.HookSocket
}

// reportManagedCommandRefusal is best effort: the gateway owns the audit store
// and attributes this request using the hook socket's kernel peer credentials.
// Only fixed command names reach the record; CLI arguments can contain secrets.
// Enforcement never depends on the report: the caller refuses either way.
var reportManagedCommandRefusal = func(command, reason string) {
	socket := managedRefusalSocket()
	if socket == "" {
		return
	}
	_, _ = managed.ReportCommandRefusal(context.Background(), socket, command, reason)
}
