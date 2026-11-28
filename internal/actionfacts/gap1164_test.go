// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// substrate-1:GAP-1164: the MCP callout and bridge judge bounded projections
// of a large call, so each projection's analysis cost is paid again. One
// analysis reads the arguments once: the closed coding-agent schema check
// decodes nothing for a tool that has no such schema, and the Kerberos S4U
// reader takes analyzeReading's own argument reading.
func TestGAP1164AnalysisReadsArgumentsOnce(t *testing.T) {
	raw := json.RawMessage(`{"items":[` + strings.Repeat(`{"note":"hello"},`, 249) + `{"note":"hello"}]}`)
	const tool = "mcp__notes__read_file"
	if issue := ArgsLimitIssue(raw); issue != "" {
		t.Fatalf("fixture must fit the reading's bounds: %s", issue)
	}

	if got := testing.AllocsPerRun(5, func() { _ = usesClosedCodingAgentArgumentSchema(raw, tool) }); got != 0 {
		t.Errorf("closed coding-agent schema check of an MCP tool: %.0f allocs, want 0 (no decode)", got)
	}
	// A coding-agent tool still decodes and still finds its schema.
	if !usesClosedCodingAgentArgumentSchema(json.RawMessage(`{"file_path":"a","offset":1}`), "Read") {
		t.Error("Read with offset is no longer the closed coding-agent schema")
	}

	input := Input{Tool: tool, Args: raw}
	reading := testing.AllocsPerRun(5, func() { _ = extractArgsForTool(raw, tool) })
	analysis := testing.AllocsPerRun(5, func() { _ = Analyze(input) })
	t.Logf("allocs: one argument reading %.0f, one analysis %.0f (%.2fx)", reading, analysis, analysis/reading)
	if analysis > 1.5*reading {
		t.Errorf("one analysis allocates %.0f, %.2fx one argument reading (%.0f): the arguments are read more than once", analysis, analysis/reading, reading)
	}
}
