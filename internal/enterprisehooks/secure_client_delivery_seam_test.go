// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// useSecureClientHookDelivery lets a test of the Secure Client delivery
// contract (#1163) run on Linux CI with a simulated trusted install marker.
// Linux has no Secure Client profile in production (GAP-0002).
func useSecureClientHookDelivery(t *testing.T) {
	t.Helper()
	previous := secureClientHookDeliveryHost
	verified := connector.SecureClientDeploymentVerified
	secureClientHookDeliveryHost = true
	connector.SecureClientDeploymentVerified = func() bool { return true }
	t.Cleanup(func() {
		secureClientHookDeliveryHost = previous
		connector.SecureClientDeploymentVerified = verified
	})
}

// GAP-0002: a Linux process that never set the standalone process mode does
// not get the Secure Client fail-open delivery: unset stays closed.
func TestSecureClientHookDeliveryNeedsAHostWithSecureClient(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux has no Secure Client profile")
	}
	if secureClientHookDelivery() {
		t.Fatal("a Linux process selected Secure Client hook delivery")
	}
	if got := canonicalHookFailMode(""); got != "closed" {
		t.Fatalf("unset fail mode on Linux = %q, want closed", got)
	}
	useSecureClientHookDelivery(t)
	if got := canonicalHookFailMode(""); got != "open" {
		t.Fatalf("the Secure Client contract (#1163) renders unset as %q, want open", got)
	}
}

func TestSecureClientEnvironmentNeedsTrustedInstallMarker(t *testing.T) {
	useSecureClientHookDelivery(t)
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "secure_client")
	previous := connector.SecureClientDeploymentVerified
	t.Cleanup(func() { connector.SecureClientDeploymentVerified = previous })
	connector.SecureClientDeploymentVerified = func() bool { return false }
	if secureClientHookDelivery() || canonicalHookFailMode("") != "closed" {
		t.Fatal("process environment enabled Secure Client delivery without its trusted install marker")
	}
	connector.SecureClientDeploymentVerified = func() bool { return true }
	if !secureClientHookDelivery() || canonicalHookFailMode("") != "open" {
		t.Fatal("a verified Secure Client install did not keep its configured delivery")
	}
}
