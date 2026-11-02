// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Windows-only parts of the managed drift model: the runtime-file retry, the
// repair log and the private per-user descriptor.

var defaultManagedTransientRetry = managedTransientRetry{
	Attempts: 8,
	Initial:  25 * time.Millisecond,
	Max:      800 * time.Millisecond,
}

// emitManagedRepairResilience logs a completed repair. The re-stamp itself is
// always a MarkerRepair line, so every repair is visible under one marker; an
// untrusted writer on policy or code is additionally reported as a boundary
// finding first, as managedDriftMarker decides.
func emitManagedRepairResilience(drift managedDrift, policyOrCode bool, path, reason string, extra map[string]string) {
	if marker := managedDriftMarker(drift, true, policyOrCode); marker != managed.MarkerRepair {
		emitManagedResilience(marker, path, reason, extra)
	}
	emitManagedResilience(managed.MarkerRepair, path, reason, extra)
}

// managedPrivateCanonicalModel is the private per-user descriptor used for
// configuration transaction state: owned by the user, protected, full control
// for LocalSystem and the user only.
func managedPrivateCanonicalModel(user string) managedDescriptor {
	return managedDescriptor{
		Owner:     user,
		Protected: true,
		ACEs: []managedACE{
			{SID: managedSIDLocalSystem, Mask: managedFileAllAccess},
			{SID: user, Mask: managedFileAllAccess},
		},
	}
}
