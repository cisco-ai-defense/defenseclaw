//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

func TestGatewayServiceAccountOffWindowsIsThePin(t *testing.T) {
	t.Setenv(WindowsServiceAccountEnv, `NT SERVICE\OtherGateway`)
	if got := GatewayServiceAccount(); got != `NT SERVICE\OtherGateway` {
		t.Fatalf("GatewayServiceAccount() = %q, want the pin", got)
	}
	t.Setenv(WindowsServiceAccountEnv, "")
	if got := GatewayServiceAccount(); got != "" {
		t.Fatalf("GatewayServiceAccount() = %q, want empty without the pin", got)
	}
}
