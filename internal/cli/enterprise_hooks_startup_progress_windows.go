//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Windows guardian writes the startup record that the Setup coverage
// wait reads (GAP-0401), so a slow first reconcile extends the wait: on the
// standalone profile, and on Secure Client outside strict mode. A strict
// Secure Client host keeps the fixed wait.
func init() {
	enterpriseHookStartup.enabled = func() bool {
		return enterprisehooks.WindowsStandaloneProcess() || !managed.TrustStrictAncestors()
	}
}
