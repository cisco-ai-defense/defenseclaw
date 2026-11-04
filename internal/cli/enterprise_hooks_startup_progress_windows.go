//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// Every Windows guardian writes the startup record that the Setup coverage
// wait reads (GAP-0401), so a slow first reconcile extends the wait on
// Secure Client as it does on the standalone profile.
func init() {
	enterpriseHookStartup.enabled = func() bool { return true }
}
