// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// Availability reason codes carried in HealthSnapshot.availability_reason.
// The set is part of the AVC contract (see secureclient.proto); add codes,
// never repurpose them.
const (
	availabilityReasonManagedIPCError               = "managed_ipc_error"
	availabilityReasonGatewayError                  = "gateway_error"
	availabilityReasonAPIError                      = "api_error"
	availabilityReasonStarting                      = "starting"
	availabilityReasonGatewayStopped                = "gateway_stopped"
	availabilityReasonAPIStopped                    = "api_stopped"
	availabilityReasonGatewayReconnecting           = "gateway_reconnecting"
	availabilityReasonGuardrailError                = "guardrail_error"
	availabilityReasonInspectionUnavailableAllowing = "inspection_unavailable_allowing"
	availabilityReasonInspectionUnavailableBlocking = "inspection_unavailable_blocking"
)

// mapHealth reduces the rich internal HealthSnapshot to the flat
// ServiceAvailability enum the AVC contract exposes. See
// mapHealthWithReason for the priority order.
func mapHealth(s gateway.HealthSnapshot) pb.ServiceAvailability {
	availability, _ := mapHealthWithReason(s)
	return availability
}

// mapHealthWithReason returns the availability and the reason code that
// explains it. The priority order is deterministic so behavior is easy to
// reason about:
//
//  1. Managed self-report Error → ERROR (the IPC server itself is
//     the source of truth for its own health).
//  2. Any core subsystem (Gateway, API) in Error → ERROR.
//  3. Managed self-report Starting, or any core Starting → STARTING.
//  4. Any core Stopped → UNAVAILABLE.
//  5. Gateway Reconnecting → DEGRADED (protection is impaired but the
//     sidecar itself is up; UI should show a soft warning).
//  6. Guardrail Error → DEGRADED: the sidecar is up but tool-call
//     protection is not running.
//  7. Managed inspection unavailable → DEGRADED: Cisco AI Defense, the
//     only decision-maker in managed_enterprise, cannot be reached, so
//     tool calls are either allowed uninspected or blocked, per
//     cisco_ai_defense.unavailable_action as enforced by the connectors'
//     mode (the gateway reports allow while no connector is in action
//     mode). Skipped while the guardrail is
//     Disabled: nothing is being inspected, so there is nothing to allow
//     or block.
//  8. Otherwise → READY.
//
// The other opt-in subsystems (Watcher, Telemetry, AIDiscovery,
// ApplicationProtection, Sinks, Sandbox) do NOT downgrade the top-level
// availability, and a Disabled guardrail does not either — each can be
// Disabled in a healthy install. DISABLED_BY_POLICY is reserved for future
// policy-driven shutdowns and is not emitted from v1.
func mapHealthWithReason(s gateway.HealthSnapshot) (pb.ServiceAvailability, string) {
	if s.Managed != nil && s.Managed.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, availabilityReasonManagedIPCError
	}
	if s.Gateway.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, availabilityReasonGatewayError
	}
	if s.API.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR, availabilityReasonAPIError
	}
	if (s.Managed != nil && s.Managed.State == gateway.StateStarting) ||
		s.Gateway.State == gateway.StateStarting ||
		s.API.State == gateway.StateStarting {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_STARTING, availabilityReasonStarting
	}
	if s.Gateway.State == gateway.StateStopped {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE, availabilityReasonGatewayStopped
	}
	if s.API.State == gateway.StateStopped {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE, availabilityReasonAPIStopped
	}
	if s.Gateway.State == gateway.StateReconnecting {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, availabilityReasonGatewayReconnecting
	}
	if s.Guardrail.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, availabilityReasonGuardrailError
	}
	if inspection := s.ManagedInspection; inspection != nil && !inspection.Available &&
		s.Guardrail.State != gateway.StateDisabled {
		if inspection.UnavailableAction == config.AIDUnavailableActionBlock {
			return pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, availabilityReasonInspectionUnavailableBlocking
		}
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED, availabilityReasonInspectionUnavailableAllowing
	}
	return pb.ServiceAvailability_SERVICE_AVAILABILITY_READY, ""
}
