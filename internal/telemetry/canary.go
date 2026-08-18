// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

// Canary markers are shared by the v8 sampler, destination isolation, and
// generated two-span diagnostic. They are transport internals, not a legacy
// span-construction API.
const (
	telemetryCanaryAttribute            = "defenseclaw.telemetry.canary"
	telemetryCanaryDestinationAttribute = "defenseclaw.telemetry.canary.destination"
)
