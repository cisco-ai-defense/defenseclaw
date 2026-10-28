//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// setStandaloneProfileForTest switches this process between the standalone
// and Secure Client profiles for one test. The Secure Client profile is an
// authenticated Secure Client install (connector.SecureClientDeploymentVerified,
// which only binaries that link internal/cli's host classifier set), so its
// delivery defaults apply; a test of an unverified install sets it false
// itself.
func setStandaloneProfileForTest(t *testing.T, standalone bool) {
	t.Helper()
	previous, verified := windowsEnterpriseStandaloneProcess, connector.SecureClientDeploymentVerified
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	connector.SecureClientDeploymentVerified = func() bool { return !standalone }
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previous
		connector.SecureClientDeploymentVerified = verified
	})
}
