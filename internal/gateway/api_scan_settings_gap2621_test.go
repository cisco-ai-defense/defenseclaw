// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2621: an admin gateway MCP scan names the analyzers that ran (never
// "(none)" for auto) and warns when the LLM judge did not run.
func TestWithScannerSettingsMCPNamesTheAnalyzersThatRan(t *testing.T) {
	cases := []struct {
		name      string
		analyzers []string
		model     string
		warnings  []string
		wantRan   string
		wantJudge bool
		wantWarn  []string
	}{
		{name: "auto with judge", model: "bedrock/m", wantRan: "auto (yara, llm)", wantJudge: true},
		{name: "auto judge skipped", model: "bedrock/m", warnings: []string{"LLM analyzer skipped: K is not configured"},
			wantRan: "auto (yara)", wantWarn: []string{"LLM analyzer skipped: K is not configured"}},
		{name: "auto without model", wantRan: "auto (yara)",
			wantWarn: []string{"LLM judge did not run: no LLM model is configured for the MCP scanner"}},
		{name: "explicit yara", analyzers: []string{"yara"}, model: "bedrock/m", wantRan: "yara"},
		{name: "explicit llm skipped", analyzers: []string{"yara,llm"}, model: "bedrock/m",
			warnings: []string{"LLM skipped (backend unreachable)"}, wantRan: "yara", wantWarn: []string{"LLM skipped (backend unreachable)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.LLM.Model = tc.model
			cfg.Scanners.MCPScanner.Analyzers = tc.analyzers
			result := &scanner.ScanResult{Warnings: tc.warnings}
			env := withScannerSettings(cfg, "mcp", result, map[string]interface{}{})
			settings := env["scanner_settings"].(map[string]interface{})
			if settings["analyzers"] != tc.wantRan {
				t.Fatalf("analyzers = %v, want %q", settings["analyzers"], tc.wantRan)
			}
			if _, ok := settings["judge_model"]; ok != tc.wantJudge {
				t.Fatalf("judge_model present = %v, want %v", ok, tc.wantJudge)
			}
			got, _ := env["warnings"].([]string)
			if !reflect.DeepEqual(got, tc.wantWarn) {
				t.Fatalf("warnings = %q, want %q", got, tc.wantWarn)
			}
		})
	}
}
