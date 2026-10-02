//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

// setStandaloneProfileForTest switches this process between the standalone
// and Secure Client profiles for one test.
func setStandaloneProfileForTest(t *testing.T, standalone bool) {
	t.Helper()
	previous := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
}
