//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "github.com/defenseclaw/defenseclaw/internal/managed"

// secureClientManagedRuntime limits service resilience rules to the managed
// Secure Client process. A per-user gateway has no managed deployment pin.
func secureClientManagedRuntime() bool {
	return managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) && !managed.StandaloneTrustScope()
}
