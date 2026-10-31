// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0172: status, verify and ensure name an admin llm.model the judge
// cannot route; a real id or an unreadable config adds nothing.
func TestWindowsEnterpriseWarnsAnUnroutableLLMModel(t *testing.T) {
	seam := readWindowsStandaloneScannerConfig
	t.Cleanup(func() { readWindowsStandaloneScannerConfig = seam })
	for _, tc := range []struct{ name, body, want string }{
		{"nickname", "llm:\n  model: luna\n  region: us-east-1\n", `llm.model "luna" names no provider`},
		{"bom and not a model", "\ufeffllm:\n  model: not-a-model\n", `llm.model "not-a-model"`},
		{"full id", "llm:\n  model: bedrock/us.openai.gpt-5.6-luna\n", ""},
		{"no llm", "gateway:\n  api_port: 18970\n", ""},
		{"not yaml", "llm: [\n", ""},
	} {
		body := tc.body
		readWindowsStandaloneScannerConfig = func() ([]byte, error) { return []byte(body), nil }
		result := &enterprisestatus.Result{}
		appendWindowsEnterpriseLLMModelWarning(result)
		if tc.want == "" {
			if len(result.Warnings) != 0 {
				t.Fatalf("%s: unexpected warnings %+v", tc.name, result.Warnings)
			}
			continue
		}
		if len(result.Warnings) != 1 || result.Warnings[0].Code != enterprisestatus.CodeLLMModelUnroutable ||
			!strings.Contains(result.Warnings[0].Message, tc.want) || !strings.Contains(result.Warnings[0].Message, "Setup /ensure") {
			t.Fatalf("%s: warnings %+v", tc.name, result.Warnings)
		}
	}
}
