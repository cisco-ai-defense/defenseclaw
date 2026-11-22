// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The answer template at the end of the tool-injection judge prompt shows the
// reply's shape. A value other than "none" in it is copied by smaller models:
// with "Data Exfiltration": "strong_signal" there, Gemma 3 27B rated pytest
// and cat README.md as CRITICAL exfiltration and the hook blocked them.
func TestToolInjectionAnswerTemplateIsNeutral(t *testing.T) {
	prompts := map[string]string{"embedded": EmbeddedToolInjectionPrompt()}
	for _, pack := range []string{"default", "strict", "permissive"} {
		rp, err := LoadRulePack(filepath.Join("..", "..", "policies", "guardrail", pack))
		if err != nil {
			t.Fatalf("%s: %v", pack, err)
		}
		jc := rp.ToolInjectionJudge()
		if jc == nil || jc.SystemPrompt == "" {
			t.Fatalf("%s: no tool-injection prompt", pack)
		}
		prompts[pack] = jc.SystemPrompt
	}
	for name, prompt := range prompts {
		start := strings.LastIndex(prompt, "{")
		end := strings.LastIndex(prompt, "}")
		if start < 0 || end < start {
			t.Fatalf("%s: no answer template", name)
		}
		var template map[string]string
		if err := json.Unmarshal([]byte(prompt[start:end+1]), &template); err != nil {
			t.Fatalf("%s: answer template is not a JSON object of strings: %v", name, err)
		}
		if len(template) != 8 {
			t.Fatalf("%s: template has %d keys, want the 8 categories", name, len(template))
		}
		for category, value := range template {
			if value != "none" {
				t.Errorf("%s: template sets %q to %q; a template value is copied as an answer", name, category, value)
			}
		}
	}
}
