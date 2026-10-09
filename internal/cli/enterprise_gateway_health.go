// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// appendStandaloneGatewayWarnings uses the same gateway /health facts as the
// Unix lifecycle. It is called only by Windows standalone status and verify.
func appendStandaloneGatewayWarnings(result *enterprisestatus.Result, body []byte) {
	var health struct {
		ProfileAssignmentWarnings []string `json:"profile_assignment_warnings"`
		ProfileWarnings           []string `json:"profile_warnings"`
		Telemetry                 struct {
			Details struct {
				OptionalState  string `json:"optional_destination_state"`
				FailureSummary string `json:"optional_destination_failure_summary"`
			} `json:"details"`
		} `json:"telemetry"`
		Guardrail *struct {
			Details enterprisestatus.JudgeHealth `json:"details"`
		} `json:"guardrail"`
	}
	if json.Unmarshal(body, &health) != nil {
		return
	}
	for _, warning := range health.ProfileAssignmentWarnings {
		if strings.TrimSpace(warning) != "" {
			result.AddWarning("profile_assignment_unmatched", warning)
		}
	}
	for _, warning := range health.ProfileWarnings {
		if strings.TrimSpace(warning) != "" && !slices.Contains(health.ProfileAssignmentWarnings, warning) {
			result.AddWarning("guardrail_profile", warning)
		}
	}
	// A rejected judge key made every judge call fail while status and
	// verify said the scanners and judge were ready (GAP-1026).
	if g := health.Guardrail; g != nil {
		if message, failing := g.Details.Warning(); failing {
			result.AddWarning(enterprisestatus.CodeJudgeFailing, message)
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
