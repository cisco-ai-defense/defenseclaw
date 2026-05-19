package gateway

import (
	"context"
	"testing"
)

func TestInspectCompletionScopesToAssistantOutput(t *testing.T) {
	g := NewGuardrailInspector("balanced", nil, nil, "")

	v := g.Inspect(
		context.Background(),
		"completion",
		"OK",
		[]ChatMessage{
			{Role: "system", Content: "SOUL.md AGENTS.md MEMORY.md"},
			{Role: "assistant", Content: "OK"},
		},
		"test-model",
		"action",
	)

	if v == nil {
		t.Fatalf("verdict = nil")
	}
	if v.Action == "block" {
		t.Fatalf("completion verdict action = block, want allow/warn; reason=%s", v.Reason)
	}
}
