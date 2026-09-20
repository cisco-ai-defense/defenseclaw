// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

// The runtime capability tuple is the telemetry vocabulary compiled into this
// binary. Configuration still derives its effective tuple from the embedded
// registry and semantic-convention lock, then verifies that source tuple against
// these capabilities. A different tuple therefore requires a new profile ID and
// runtime support rather than silently changing an existing profile's meaning.
const (
	RuntimeSemanticProfileID                 = "defenseclaw-genai-rich-v1"
	RuntimeTraceSchemaVersion                = "defenseclaw-trace-v1"
	RuntimeGenAISemconvProfile               = "otel-genai-b028dceecdad117461a785c3af35315e7184e813"
	RuntimeOpenInferenceProfile              = "openinference-semantic-conventions-v0.1.30"
	RuntimeOpenInferenceCompatibilityProfile = "openinference-v1"
	RuntimeGalileoCompatibilityProfile       = "galileo-rich-v2"
	RuntimeLocalObservabilityDestination     = "local-observability"
	RuntimeLocalObservabilityProfile         = "local-observability-v1"
)
