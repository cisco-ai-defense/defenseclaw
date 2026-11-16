// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"testing"
)

// GAP-2621: the gateway scan reports the LLM skip lines the Python scanner
// prints on stderr, and nothing else from stderr.
func TestMCPAnalyzerWarningsKeepsOnlyLLMSkipLines(t *testing.T) {
	stderr := "INFO starting scan\n" +
		"warning: LLM analyzer skipped: DEFENSECLAW_LLM_KEY is not configured; continuing with local analyzers\n" +
		"warning: unknown analyzer \"x\"\n" +
		"\x1b[33mwarning: LLM skipped (backend unreachable) while scanning \"http://h/mcp\": 401\x1b[0m\n"
	got := mcpAnalyzerWarnings(stderr)
	want := []string{
		"LLM analyzer skipped: DEFENSECLAW_LLM_KEY is not configured; continuing with local analyzers",
		"LLM skipped (backend unreachable) while scanning \"http://h/mcp\": 401",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %q, want %q", got, want)
	}
	if got := mcpAnalyzerWarnings("INFO scan ok\n"); len(got) != 0 {
		t.Fatalf("clean stderr gave warnings %q", got)
	}
}
