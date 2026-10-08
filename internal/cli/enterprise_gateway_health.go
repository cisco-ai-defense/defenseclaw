// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// appendStandaloneGatewayWarnings uses the same gateway /health facts as the
// Unix lifecycle. It is called only by Windows standalone status and verify.
func appendStandaloneGatewayWarnings(result *enterprisestatus.Result, body []byte) {
	var health struct {
		ProfileAssignmentWarnings []string `json:"profile_assignment_warnings"`
		Telemetry                 struct {
			Details struct {
				OptionalState  string `json:"optional_destination_state"`
				FailureSummary string `json:"optional_destination_failure_summary"`
			} `json:"details"`
		} `json:"telemetry"`
	}
	if json.Unmarshal(body, &health) != nil {
		return
	}
	for _, warning := range health.ProfileAssignmentWarnings {
		if strings.TrimSpace(warning) != "" {
			result.AddWarning("profile_assignment_unmatched", warning)
		}
	}
	if health.Telemetry.Details.OptionalState == "degraded" {
		summary := strings.TrimSpace(health.Telemetry.Details.FailureSummary)
		if summary == "" {
			summary = "see gateway /health telemetry.details.destinations"
		}
		result.AddWarning("optional_destination_failing", "optional telemetry destination failing: "+summary+
			"; inspect `defenseclaw-gateway status` or gateway /health telemetry details")
	}
}
