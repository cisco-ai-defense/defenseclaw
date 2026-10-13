// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// appendStandaloneGatewayWarnings uses the same gateway facts as the Unix
// lifecycle. It is called only by Windows standalone status and verify:
// health is the /health document, status the /status one read with the
// gateway credential, or nil when it could not be read. /health gives only
// the number of the profile warnings, because they name the configured
// groups and accounts and /health needs no credential (GAP-1268).
func appendStandaloneGatewayWarnings(result *enterprisestatus.Result, body, status []byte) {
	var health struct {
		ProfileAssignmentWarningCount int `json:"profile_assignment_warning_count"`
		ProfileWarningCount           int `json:"profile_warning_count"`
		Telemetry                     struct {
			Details struct {
				OptionalState  string `json:"optional_destination_state"`
				FailureSummary string `json:"optional_destination_failure_summary"`
			} `json:"details"`
		} `json:"telemetry"`
		Guardrail *struct {
			Details enterprisestatus.JudgeHealth `json:"details"`
		} `json:"guardrail"`
		Watcher struct {
			Details struct {
				ProjectSkillRootsUnverified int `json:"project_skill_roots_unverified"`
			} `json:"details"`
		} `json:"watcher"`
	}
	if json.Unmarshal(body, &health) != nil {
		return
	}
	var profiles struct {
		ProfileAssignmentWarnings []string `json:"profile_assignment_warnings"`
		ProfileWarnings           []string `json:"profile_warnings"`
	}
	if status == nil || json.Unmarshal(status, &profiles) != nil {
		if withheld := max(health.ProfileAssignmentWarningCount, health.ProfileWarningCount); withheld > 0 {
			result.AddWarning("profile_assignment_unmatched", fmt.Sprintf("%d guardrail profile assignment warning(s) are "+
				"unavailable without the gateway credential; run this command from an elevated Administrator prompt to list them", withheld))
		}
	}
	for _, warning := range profiles.ProfileAssignmentWarnings {
		if strings.TrimSpace(warning) != "" {
			result.AddWarning("profile_assignment_unmatched", warning)
		}
	}
	for _, warning := range profiles.ProfileWarnings {
		if strings.TrimSpace(warning) != "" && !slices.Contains(profiles.ProfileAssignmentWarnings, warning) {
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
	// A project skill folder the hook guardian could not verify (a link in
	// its path, a folder outside the user's own profile) is not watched and
	// its skills are refused (GAP-1356). /health gives only the number.
	if n := health.Watcher.Details.ProjectSkillRootsUnverified; n > 0 {
		result.AddWarning("project_skill_root_unverified", fmt.Sprintf("%d project skill folder(s) could not be verified: "+
			"they are not watched and their skills are refused; the gateway log names each folder and the reason", n))
	}
}
