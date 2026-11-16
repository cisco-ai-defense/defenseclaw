// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1075, GAP-0993: on Windows the gateway service's start type is the
// lifecycle marker. The lifecycle disables every service before it stops
// it, starts the gateway on demand and makes it automatic only after the
// readiness proof, so a call that met a gateway still starting, or started
// but not yet listening, under demand start was allowed by an
// administrator's open. Only automatic is outside a transition.
func TestManagedGatewayStartTypeIsTheLifecycleMarker(t *testing.T) {
	for _, test := range []struct {
		name       string
		startType  uint32
		known      bool
		transition bool
	}{
		{"automatic (control)", windows.SERVICE_AUTO_START, true, false},
		{"disabled (quiesce)", windows.SERVICE_DISABLED, true, true},
		{"demand start (activation before readiness)", windows.SERVICE_DEMAND_START, true, true},
		{"start type unreadable", 0, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := startTypeInTransition(test.startType, test.known); got != test.transition {
				t.Fatalf("startTypeInTransition(%d, %v) = %v, want %v", test.startType, test.known, got, test.transition)
			}
		})
	}
	// No service to restart: the transport refuses the call itself.
	for _, name := range []string{"", "DefenseClawNoSuchGateway7f3a"} {
		if managedGatewayServiceInTransition(name) {
			t.Fatalf("service %q reads as a transition", name)
		}
	}
}
