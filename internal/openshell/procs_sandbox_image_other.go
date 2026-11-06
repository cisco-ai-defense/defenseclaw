//go:build !darwin && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import "context"

// Other platforms cannot establish the running image for a sandbox port.
func (r *doctorRun) ownSandboxDaemonImage(context.Context, int) bool {
	return false
}
