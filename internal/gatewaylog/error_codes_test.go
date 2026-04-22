// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import "testing"

func TestAllErrorCodesUnique(t *testing.T) {
	seen := make(map[ErrorCode]bool)
	for _, c := range AllErrorCodes() {
		if seen[c] {
			t.Errorf("duplicate error code %q in AllErrorCodes()", c)
		}
		seen[c] = true
	}
}

func TestAllErrorCodesNonEmpty(t *testing.T) {
	for _, c := range AllErrorCodes() {
		if c == "" {
			t.Errorf("empty error code value in AllErrorCodes()")
		}
	}
}

func TestAllSubsystemsUnique(t *testing.T) {
	seen := make(map[Subsystem]bool)
	for _, s := range AllSubsystems() {
		if seen[s] {
			t.Errorf("duplicate subsystem %q in AllSubsystems()", s)
		}
		seen[s] = true
	}
}

func TestErrorCodeSpecificConstants(t *testing.T) {
	// Sanity-check a few high-visibility codes so a typo in the
	// literal doesn't silently fly through.
	cases := []struct {
		got  ErrorCode
		want string
	}{
		{ErrCodeSinkDeliveryFailed, "SINK_DELIVERY_FAILED"},
		{ErrCodeAuthInvalidToken, "AUTH_INVALID_TOKEN"},
		{ErrCodePanicRecovered, "PANIC_RECOVERED"},
		{ErrCodeLLMBridgeError, "LLM_BRIDGE_ERROR"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Errorf("ErrorCode constant: got %q, want %q", tc.got, tc.want)
		}
	}
}
