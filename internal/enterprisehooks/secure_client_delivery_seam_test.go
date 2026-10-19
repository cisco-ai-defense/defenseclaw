// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"runtime"
	"testing"
)

// useSecureClientHookDelivery lets a test of the Secure Client delivery
// contract (#1163) run on Linux CI. Linux has no Secure Client profile, so
// secureClientHookDelivery is false there whatever the process flags say
// (GAP-0002); the standalone process mode still decides on every OS.
func useSecureClientHookDelivery(t *testing.T) {
	t.Helper()
	previous := secureClientHookDeliveryHost
	secureClientHookDeliveryHost = true
	t.Cleanup(func() { secureClientHookDeliveryHost = previous })
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
