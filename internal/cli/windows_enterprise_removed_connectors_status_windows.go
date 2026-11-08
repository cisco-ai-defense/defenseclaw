//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/managed"

// windowsEnterpriseRemovedConnectorsForStatus reads the removed-connectors
// record the hook guardian keeps beside its authorization ledger; tests
// replace it.
var windowsEnterpriseRemovedConnectorsForStatus = func() ([]managed.RemovedConnector, error) {
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		return nil, err
	}
	return loadEnterpriseHookRemovedConnectors(layout.DataDir)
}
