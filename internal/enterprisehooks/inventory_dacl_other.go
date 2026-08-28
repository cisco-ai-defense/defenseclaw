// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

// GrantGatewayInventoryReadForManifest is a Windows-only no-op on other
// platforms. macOS uses per-user launchd agents that inherit user permissions
// naturally; Linux systemd-user runs likewise. Only the Windows service model
// requires the gateway service SID to be added to the user profile DACLs.
func GrantGatewayInventoryReadForManifest(_ Manifest, _ string, _ EnumerationLogger) error {
	return nil
}
