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

// useWindowsSecureClientForTest runs a test as a verified Secure Client host
// (#1163): the process carries no standalone profile pin and the trusted
// Secure Client install marker is present. The shipped binaries set
// connector.SecureClientDeploymentVerified from the host; this package's test
// binary links no host check, so without this a Secure Client test saw an
// unverified host and its standalone defaults (GAP-0921).
func useWindowsSecureClientForTest(t *testing.T) {
	t.Helper()
	setStandaloneProfileForTest(t, false)
	useSecureClientHookDelivery(t)
}
