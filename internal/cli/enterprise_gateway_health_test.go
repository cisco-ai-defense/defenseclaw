// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestStandaloneGatewayHealthWarnings(t *testing.T) {
	result := enterprisestatus.New("verify", "standalone", "windows", "test")
	appendStandaloneGatewayWarnings(result, []byte(`{"profile_assignment_warning_count":1,"telemetry":{"details":{"optional_destination_state":"degraded","optional_destination_failure_summary":"otlp: timeout"}}}`),
		[]byte(`{"profile_assignment_warnings":["assignment 1 cannot match"]}`))
	if len(result.Warnings) != 2 || result.Warnings[0].Code != "profile_assignment_unmatched" ||
		result.Warnings[0].Message != "assignment 1 cannot match" || result.Warnings[1].Code != "optional_destination_failing" ||
		!strings.Contains(result.Warnings[1].Message, "otlp: timeout") {
		t.Fatalf("warnings = %+v", result.Warnings)
	}
	// Without the gateway credential only their number shows (GAP-1268).
	result = enterprisestatus.New("status", "standalone", "windows", "test")
	appendStandaloneGatewayWarnings(result, []byte(`{"profile_assignment_warning_count":1,"profile_warning_count":2}`), nil)
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0].Message, "2 guardrail profile assignment warning(s) are unavailable without the gateway credential") {
		t.Fatalf("warnings without the credential = %+v", result.Warnings)
	}
	// A project skill folder that could not be verified is reported
	// (GAP-1356).
	result = enterprisestatus.New("status", "standalone", "windows", "test")
	appendStandaloneGatewayWarnings(result, []byte(`{"watcher":{"details":{"project_skill_roots_unverified":1}}}`), nil)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "project_skill_root_unverified" {
		t.Fatalf("unverified project skill folder warnings = %+v", result.Warnings)
	}
}

// GAP-1026: a judge whose calls all fail is a judge_failing warning on
// Windows too, as on Linux and macOS.
func TestStandaloneGatewayHealthNamesFailingJudge(t *testing.T) {
	result := enterprisestatus.New("status", "standalone", "windows", "test")
	appendStandaloneGatewayWarnings(result, []byte(`{"guardrail":{"details":{"judge_state":"failing","judge_failed_calls":6,`+
		`"judge_last_error":"Bedrock returned 403","judge_last_failure_at":"2026-10-08T17:23:47Z"}}}`), nil)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "judge_failing" ||
		!strings.Contains(result.Warnings[0].Message, "Bedrock returned 403") {
		t.Fatalf("warnings = %+v, want one judge_failing naming the last error", result.Warnings)
	}
}
