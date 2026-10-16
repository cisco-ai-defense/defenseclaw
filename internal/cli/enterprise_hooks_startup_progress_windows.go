//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

// Only the standalone Windows guardian writes the startup record that the
// Setup coverage wait reads (GAP-0401); Secure Client is unchanged.
func init() {
	enterpriseHookStartup.enabled = enterprisehooks.WindowsStandaloneProcess
}
