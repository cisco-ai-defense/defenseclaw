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
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// mapHealth reduces the rich internal HealthSnapshot to the flat
// ServiceAvailability enum the AVC contract exposes. The priority
// order is deterministic so behavior is easy to reason about:
//
//  1. Managed self-report Error → ERROR (the IPC server itself is
//     the source of truth for its own health).
//  2. Any core subsystem (Gateway, API) in Error → ERROR.
//  3. Managed self-report Starting, or any core Starting → STARTING.
//  4. Any core Stopped → UNAVAILABLE.
//  5. Gateway Reconnecting → DEGRADED (protection is impaired but the
//     sidecar itself is up; UI should show a soft warning).
//  6. Otherwise → READY.
//
// Opt-in subsystems (Watcher, Guardrail, Telemetry, AIDiscovery,
// ApplicationProtection, Sinks, Sandbox) do NOT downgrade the top-
// level availability — they can be Disabled in a healthy install.
// DISABLED_BY_POLICY is reserved for future policy-driven shutdowns
// and is not emitted from v1.
func mapHealth(s gateway.HealthSnapshot) pb.ServiceAvailability {
	if s.Managed != nil && s.Managed.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR
	}
	if s.Gateway.State == gateway.StateError || s.API.State == gateway.StateError {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_ERROR
	}
	if (s.Managed != nil && s.Managed.State == gateway.StateStarting) ||
		s.Gateway.State == gateway.StateStarting ||
		s.API.State == gateway.StateStarting {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_STARTING
	}
	if s.Gateway.State == gateway.StateStopped || s.API.State == gateway.StateStopped {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_UNAVAILABLE
	}
	if s.Gateway.State == gateway.StateReconnecting {
		return pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED
	}
	return pb.ServiceAvailability_SERVICE_AVAILABILITY_READY
}
