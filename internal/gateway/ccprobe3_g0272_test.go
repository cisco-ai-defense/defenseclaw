// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe3 old-API probe for rel-1-0-10:GAP-0272 (P2 security): the chat
// request a Gemma prompt-lane judge sends (LLMJudge.judgeChatRequest, the
// same signature at the pre-fix sha cd5400ffc5 = 66eeb882b6^ and at rel)
// bounds every free-text field of its response schema, so a repetition loop
// in "reasoning" cannot run to max_tokens and cut the JSON. Control: a
// non-Gemma judge keeps the exact unbounded schema on both sides.
// Scratch, test-only branch s7/ccprobes-3.

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestCCP3G0272_GemmaPromptJudgeSchemaIsBounded(t *testing.T) {
	checked := 0
	for _, kind := range []string{"injection", "exfil", "pii"} {
		plain := string((&LLMJudge{model: "gpt-4o-mini", cfg: &config.JudgeConfig{}}).judgeChatRequest(nil, 256, kind).ResponseFormat)
		if !strings.Contains(plain, `"reasoning"`) && !strings.Contains(plain, `"entities"`) {
			continue
		}
		if strings.Contains(plain, "maxLength") {
			t.Fatalf("control %s: the non-Gemma schema carries bounds: %s", kind, plain)
		}
		checked++
		gemma := string((&LLMJudge{model: "openai/gemma-4-31b", cfg: &config.JudgeConfig{}}).judgeChatRequest(nil, 256, kind).ResponseFormat)
		t.Logf("ROW %s gemma bounded=%v", kind, strings.Contains(gemma, "maxLength"))
		if !strings.Contains(gemma, "maxLength") {
			t.Errorf("%s: the Gemma judge schema has unbounded free text: %s", kind, gemma)
		}
	}
	if checked == 0 {
		t.Fatal("no prompt-lane schema with free text on this tree")
	}
}
