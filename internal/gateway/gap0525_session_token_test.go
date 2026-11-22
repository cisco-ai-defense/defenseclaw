// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// GAP-0525: a Claude Code actor's agent environment holds
// CLAUDE_CODE_MESSAGING_TOKEN, Claude Code's own per-session inbox token.
// When the agent lists its environment, the value is in the model content
// the hook reports, and the gateway recorded that content as is in audit
// rows and OTLP records. The value is masked there, in every spelling an
// environment listing or a model's answer uses; the variable's name and
// everything else stay.
func TestGAP0525AgentSessionTokenIsMaskedInRecordedModelContent(t *testing.T) {
	const v = "3f9c2b7d1e8a4c6f0b5d9e2a7c1f4b8d"
	for name, content := range map[string]string{
		"env listing":        "ANTHROPIC_BEDROCK_BASE_URL=http://defenseclaw-actor/llm/bedrock\nCLAUDE_CODE_MESSAGING_TOKEN=" + v + "\nCLAUDE_CODE_USE_BEDROCK=1",
		"markdown answer":    "- `CLAUDE_CODE_MESSAGING_TOKEN`: `" + v + "`",
		"json":               `{"CLAUDE_CODE_MESSAGING_TOKEN": "` + v + `", "TERM": "dumb"}`,
		"export":             "export CLAUDE_CODE_MESSAGING_TOKEN='" + v + "'",
		"two in one content": "CLAUDE_CODE_MESSAGING_TOKEN=" + v + " and again CLAUDE_CODE_MESSAGING_TOKEN=" + v,
	} {
		in, _, inOK, _, _ := hookModelV8InputMessages(content, int64(len(content)), false)
		out, _, outOK, _, _ := hookModelV8OutputMessages(content, nil)
		if !inOK || !outOK {
			t.Fatalf("%s: content not reported", name)
		}
		for kind, msg := range map[string]any{"input": in, "output": out} {
			b, err := json.Marshal(msg)
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			if strings.Contains(s, v) {
				t.Errorf("%s: the %s messages recorded for audit and OTLP hold the session token value: %s", name, kind, s)
			}
			if !strings.Contains(s, "CLAUDE_CODE_MESSAGING_TOKEN") || !strings.Contains(s, "redacted") {
				t.Errorf("%s: the %s messages lost the variable name or the redaction mark: %s", name, kind, s)
			}
		}
	}
	// Other content is unchanged, including a 32-hex value of another name.
	plain := "CLAUDE_CODE_USE_BEDROCK=1\ntrace " + v
	out, _, _, _, _ := hookModelV8OutputMessages(plain, nil)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "trace "+v) || strings.Contains(string(b), "redacted") {
		t.Errorf("unrelated content changed: %s", b)
	}
}
