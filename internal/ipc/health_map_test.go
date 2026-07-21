// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

func TestMapHealth(t *testing.T) {
	sub := func(s gateway.SubsystemState) gateway.SubsystemHealth {
		return gateway.SubsystemHealth{State: s}
	}

	cases := []struct {
		name string
		in   gateway.HealthSnapshot
		want pb.ServiceAvailability
	}{
		{
			name: "managed error dominates everything else",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateRunning),
				API:     sub(gateway.StateRunning),
				Managed: &gateway.SubsystemHealth{State: gateway.StateError},
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR,
		},
		{
			name: "gateway error → ERROR",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateError),
				API:     sub(gateway.StateRunning),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR,
		},
		{
			name: "api error → ERROR",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateRunning),
				API:     sub(gateway.StateError),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR,
		},
		{
			name: "managed starting → STARTING",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateRunning),
				API:     sub(gateway.StateRunning),
				Managed: &gateway.SubsystemHealth{State: gateway.StateStarting},
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_STARTING,
		},
		{
			name: "gateway starting → STARTING",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateStarting),
				API:     sub(gateway.StateRunning),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_STARTING,
		},
		{
			name: "api stopped → UNAVAILABLE",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateRunning),
				API:     sub(gateway.StateStopped),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE,
		},
		{
			name: "gateway reconnecting → DEGRADED",
			in: gateway.HealthSnapshot{
				Gateway: sub(gateway.StateReconnecting),
				API:     sub(gateway.StateRunning),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED,
		},
		{
			name: "everything running → READY",
			in: gateway.HealthSnapshot{
				Gateway:   sub(gateway.StateRunning),
				API:       sub(gateway.StateRunning),
				Watcher:   sub(gateway.StateDisabled),
				Guardrail: sub(gateway.StateDisabled),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY,
		},
		{
			name: "opt-in subsystems disabled do not downgrade",
			in: gateway.HealthSnapshot{
				Gateway:               sub(gateway.StateRunning),
				API:                   sub(gateway.StateRunning),
				Watcher:               sub(gateway.StateDisabled),
				Guardrail:             sub(gateway.StateDisabled),
				Telemetry:             sub(gateway.StateDisabled),
				AIDiscovery:           sub(gateway.StateDisabled),
				ApplicationProtection: sub(gateway.StateDisabled),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY,
		},
		{
			name: "opt-in subsystem in error does NOT downgrade top-level",
			in: gateway.HealthSnapshot{
				Gateway:   sub(gateway.StateRunning),
				API:       sub(gateway.StateRunning),
				Guardrail: sub(gateway.StateError),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapHealth(tc.in)
			if got != tc.want {
				t.Errorf("mapHealth: got %v, want %v", got, tc.want)
			}
		})
	}
}
