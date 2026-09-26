// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
				Gateway:     sub(gateway.StateRunning),
				API:         sub(gateway.StateRunning),
				Watcher:     sub(gateway.StateError),
				AIDiscovery: sub(gateway.StateError),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY,
		},
		{
			name: "guardrail error → DEGRADED",
			in: gateway.HealthSnapshot{
				Gateway:   sub(gateway.StateRunning),
				API:       sub(gateway.StateRunning),
				Guardrail: sub(gateway.StateError),
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED,
		},
		{
			name: "managed inspection unavailable → DEGRADED",
			in: gateway.HealthSnapshot{
				Gateway:           sub(gateway.StateRunning),
				API:               sub(gateway.StateRunning),
				Guardrail:         sub(gateway.StateRunning),
				ManagedInspection: &gateway.ManagedInspectionHealth{Available: false, UnavailableAction: "allow"},
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED,
		},
		{
			name: "managed inspection available → READY",
			in: gateway.HealthSnapshot{
				Gateway:           sub(gateway.StateRunning),
				API:               sub(gateway.StateRunning),
				Guardrail:         sub(gateway.StateRunning),
				ManagedInspection: &gateway.ManagedInspectionHealth{Available: true, UnavailableAction: "allow"},
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY,
		},
		{
			name: "core error still dominates an unavailable inspection",
			in: gateway.HealthSnapshot{
				Gateway:           sub(gateway.StateRunning),
				API:               sub(gateway.StateError),
				Guardrail:         sub(gateway.StateError),
				ManagedInspection: &gateway.ManagedInspectionHealth{Available: false},
			},
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR,
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

func TestMapHealthWithReason(t *testing.T) {
	sub := func(s gateway.SubsystemState) gateway.SubsystemHealth {
		return gateway.SubsystemHealth{State: s}
	}
	running := func() gateway.HealthSnapshot {
		return gateway.HealthSnapshot{Gateway: sub(gateway.StateRunning), API: sub(gateway.StateRunning)}
	}
	cases := []struct {
		name   string
		mutate func(*gateway.HealthSnapshot)
		want   pb.ServiceAvailability
		reason string
	}{
		{name: "ready", mutate: func(*gateway.HealthSnapshot) {}, want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY},
		{name: "managed ipc error", mutate: func(s *gateway.HealthSnapshot) { s.Managed = &gateway.SubsystemHealth{State: gateway.StateError} },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, reason: availabilityReasonManagedIPCError},
		{name: "gateway error", mutate: func(s *gateway.HealthSnapshot) { s.Gateway = sub(gateway.StateError) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, reason: availabilityReasonGatewayError},
		{name: "api error", mutate: func(s *gateway.HealthSnapshot) { s.API = sub(gateway.StateError) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, reason: availabilityReasonAPIError},
		{name: "starting", mutate: func(s *gateway.HealthSnapshot) { s.API = sub(gateway.StateStarting) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_STARTING, reason: availabilityReasonStarting},
		{name: "gateway stopped", mutate: func(s *gateway.HealthSnapshot) { s.Gateway = sub(gateway.StateStopped) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE, reason: availabilityReasonGatewayStopped},
		{name: "api stopped", mutate: func(s *gateway.HealthSnapshot) { s.API = sub(gateway.StateStopped) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE, reason: availabilityReasonAPIStopped},
		{name: "gateway reconnecting", mutate: func(s *gateway.HealthSnapshot) { s.Gateway = sub(gateway.StateReconnecting) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, reason: availabilityReasonGatewayReconnecting},
		{name: "guardrail error", mutate: func(s *gateway.HealthSnapshot) { s.Guardrail = sub(gateway.StateError) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, reason: availabilityReasonGuardrailError},
		{name: "inspection unavailable, allowing", mutate: func(s *gateway.HealthSnapshot) {
			s.ManagedInspection = &gateway.ManagedInspectionHealth{UnavailableAction: config.AIDUnavailableActionAllow}
		}, want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, reason: availabilityReasonInspectionUnavailableAllowing},
		{name: "inspection unavailable, blocking", mutate: func(s *gateway.HealthSnapshot) {
			s.ManagedInspection = &gateway.ManagedInspectionHealth{UnavailableAction: config.AIDUnavailableActionBlock}
		}, want: pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, reason: availabilityReasonInspectionUnavailableBlocking},
		{name: "guardrail disabled with no inspection report", mutate: func(s *gateway.HealthSnapshot) { s.Guardrail = sub(gateway.StateDisabled) },
			want: pb.ServiceAvailability_SERVICE_AVAILABILITY_READY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := running()
			tc.mutate(&snap)
			got, reason := mapHealthWithReason(snap)
			if got != tc.want || reason != tc.reason {
				t.Fatalf("mapHealthWithReason = %v/%q, want %v/%q", got, reason, tc.want, tc.reason)
			}
		})
	}
}
