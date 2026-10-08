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
	appendStandaloneGatewayWarnings(result, []byte(`{"profile_assignment_warnings":["assignment 1 cannot match"],"telemetry":{"details":{"optional_destination_state":"degraded","optional_destination_failure_summary":"otlp: timeout"}}}`))
	if len(result.Warnings) != 2 || result.Warnings[0].Code != "profile_assignment_unmatched" ||
		result.Warnings[1].Code != "optional_destination_failing" ||
		!strings.Contains(result.Warnings[1].Message, "otlp: timeout") {
		t.Fatalf("warnings = %+v", result.Warnings)
	}
}
