// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "github.com/defenseclaw/defenseclaw/internal/managed"

// managedRuntimeOpenTransient accepts a sharing or lock violation only:
// access denied and not found are answers, not contention.
func managedRuntimeOpenTransient(err error) bool {
	return managed.IsTransientWindowsError(err)
}
