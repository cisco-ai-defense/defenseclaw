// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// TestMapConfigurationState pins the four-case table from
// docs/specs/004-windows-ui-ipc/requirements.md REQ-13:
//
//     waiting_for_config  → CONFIGURATION_STATE_WAITING_FOR_CONFIG
//     waiting_for_targets → CONFIGURATION_STATE_WAITING_FOR_TARGETS
//     ready               → CONFIGURATION_STATE_READY
//     absent / unknown    → CONFIGURATION_STATE_UNSPECIFIED
//
// The last row covers two things: a nil *ConfigurationHealth
// pointer (non-managed deployments never allocate it), and a
// state string that spec 003 introduces in a future extension
// which this spec 004 build doesn't yet recognise. Both must
// collapse to UNSPECIFIED so a stale build never surfaces a
// false "ready" for a state it doesn't understand.
func TestMapConfigurationState(t *testing.T) {
	tests := []struct {
		name string
		in   *gateway.ConfigurationHealth
		want pb.ConfigurationState
	}{
		{
			name: "nil pointer (non-managed deployment)",
			in:   nil,
			want: pb.ConfigurationState_CONFIGURATION_STATE_UNSPECIFIED,
		},
		{
			name: "waiting_for_config",
			in:   &gateway.ConfigurationHealth{State: gateway.ConfigStateWaitingForConfig},
			want: pb.ConfigurationState_CONFIGURATION_STATE_WAITING_FOR_CONFIG,
		},
		{
			name: "waiting_for_targets",
			in:   &gateway.ConfigurationHealth{State: gateway.ConfigStateWaitingForTargets},
			want: pb.ConfigurationState_CONFIGURATION_STATE_WAITING_FOR_TARGETS,
		},
		{
			name: "ready",
			in:   &gateway.ConfigurationHealth{State: gateway.ConfigStateReady},
			want: pb.ConfigurationState_CONFIGURATION_STATE_READY,
		},
		{
			name: "unknown state literal — safe default",
			in:   &gateway.ConfigurationHealth{State: gateway.ConfigurationState("some_future_state")},
			want: pb.ConfigurationState_CONFIGURATION_STATE_UNSPECIFIED,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapConfigurationState(tc.in); got != tc.want {
				t.Fatalf("mapConfigurationState(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCodesignStateLabel pins the four-row table in
// codesignStateLabel: Windows always reports deferred_windows;
// linux/darwin report "enabled" when ANY require flag or
// allowlist is set, and "disabled" otherwise. See
// docs/specs/004-windows-ui-ipc/requirements.md REQ-09.
func TestCodesignStateLabel(t *testing.T) {
	tests := []struct {
		name                        string
		goos                        string
		requireUnixPeer             bool
		requireSigningMetadata      bool
		allowlistTotal              int
		want                        string
	}{
		{"windows managed_enterprise, all defaults", "windows", true, true, 3, codesignStateDeferredWindows},
		{"windows dev, everything off", "windows", false, false, 0, codesignStateDeferredWindows},
		{"darwin managed_enterprise", "darwin", true, true, 3, codesignStateEnabled},
		{"darwin partial: only allowlist populated", "darwin", false, false, 1, codesignStateEnabled},
		{"darwin dev, everything off", "darwin", false, false, 0, codesignStateDisabled},
		{"linux dev, everything off", "linux", false, false, 0, codesignStateDisabled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := codesignStateLabel(tc.goos, tc.requireUnixPeer, tc.requireSigningMetadata, tc.allowlistTotal)
			if got != tc.want {
				t.Fatalf("goos=%q reqUnix=%v reqSig=%v allow=%d ⇒ %q, want %q",
					tc.goos, tc.requireUnixPeer, tc.requireSigningMetadata, tc.allowlistTotal,
					got, tc.want)
			}
		})
	}
}
