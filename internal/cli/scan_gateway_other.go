// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// managedScanGatewayEndpoint: only a managed Windows computer binds the scan
// commands to the managed gateway; elsewhere they use the loaded config.
func managedScanGatewayEndpoint() (string, string, bool, error) {
	return "", "", false, nil
}
