package gateway

import (
	"encoding/json"
	"testing"

	"github.com/maximhq/bifrost/core/providers/openai"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// outboundChatBody runs an inbound Chat Completions body through the same
// steps as the structured (non raw-forward) path and returns the JSON
// Bifrost's OpenAI-compatible serializer would put on the wire.
func outboundChatBody(t *testing.T, provider schemas.ModelProvider, body string) map[string]any {
	t.Helper()
	var req ChatRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal inbound: %v", err)
	}
	req.RawBody = []byte(body)
	req.ExtraParams = extractExtraParams(req.RawBody)

	bReq := toBifrostChatRequest(provider, req.Model, &req)
	bCtx := newBifrostRequestContext(t.Context(), &req)
	wire, bErr := providerUtils.CheckContextAndGetRequestBody(bCtx, bReq,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return openai.ToOpenAIChatRequest(bCtx, bReq), nil
		})
	if bErr != nil {
		t.Fatalf("serialize outbound: %+v", bErr)
	}
	var out map[string]any
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal outbound: %v\n%s", err, wire)
	}
	return out
}

const reflectionBeamBody = `{
  "model": "reflection-beam",
  "stream": false,
  "reasoning_effort": "medium",
  "max_tokens": 2048,
  "parallel_tool_calls": false,
  "seed": 7,
  "chat_template_kwargs": {"allow_missing_thinking": true},
  "extra_body": {"google": {"thinking_config": {"include_thoughts": true}}},
  "messages": [
    {"role": "system", "content": "be brief"},
    {"role": "user", "content": "pick a word"},
    {"role": "assistant", "content": "", "reasoning_content": "thinking about lamps",
     "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "content": "lantern"},
    {"role": "assistant", "content": "lantern", "reasoning_content": "the tool said lantern"},
    {"role": "user", "content": "again"}
  ]
}`

func TestStructuredPath_PreservesProviderExtensions(t *testing.T) {
	for _, provider := range []schemas.ModelProvider{schemas.OpenAI, schemas.Azure} {
		t.Run(string(provider), func(t *testing.T) {
			out := outboundChatBody(t, provider, reflectionBeamBody)

			kw, ok := out["chat_template_kwargs"].(map[string]any)
			if !ok || kw["allow_missing_thinking"] != true {
				t.Errorf("chat_template_kwargs dropped: %v", out["chat_template_kwargs"])
			}
			if out["reasoning_effort"] != "medium" {
				t.Errorf("reasoning_effort = %v, want medium", out["reasoning_effort"])
			}
			if out["parallel_tool_calls"] != false {
				t.Errorf("parallel_tool_calls = %v, want false", out["parallel_tool_calls"])
			}
			if out["seed"] != float64(7) {
				t.Errorf("seed = %v, want 7", out["seed"])
			}
			if _, ok := out["extra_body"].(map[string]any); !ok {
				t.Errorf("extra_body dropped (regression)")
			}
		})
	}
}

func TestStructuredPath_PreservesAssistantReasoningContent(t *testing.T) {
	out := outboundChatBody(t, schemas.OpenAI, reflectionBeamBody)
	msgs, _ := out["messages"].([]any)
	if len(msgs) != 6 {
		t.Fatalf("got %d messages, want 6", len(msgs))
	}
	for i, want := range map[int]string{2: "thinking about lamps", 4: "the tool said lantern"} {
		m := msgs[i].(map[string]any)
		if m["reasoning_content"] != want {
			t.Errorf("messages[%d].reasoning_content = %v, want %q", i, m["reasoning_content"], want)
		}
	}
	if tc, _ := msgs[2].(map[string]any)["tool_calls"].([]any); len(tc) != 1 {
		t.Errorf("messages[2].tool_calls lost alongside reasoning_content")
	}
}

// Fields the proxy rewrites or owns must never be re-injected from the
// client's original body by the top-level ExtraParams merge.
func TestExtractExtraParams_NeverForwardsOwnedFields(t *testing.T) {
	extra := extractExtraParams([]byte(reflectionBeamBody))
	for _, k := range []string{"model", "messages", "stream", "stream_options", "max_tokens",
		"tools", "tool_choice", "reasoning_effort", "parallel_tool_calls", "fallbacks"} {
		if _, ok := extra[k]; ok {
			t.Errorf("ExtraParams must not carry %q", k)
		}
	}
}

// Translated providers keep the pre-existing allowlist so OpenAI-only keys
// are not merged into an Anthropic/Bedrock/Gemini request body.
func TestToBifrostChatRequest_TranslatedProvidersKeepAllowlist(t *testing.T) {
	var req ChatRequest
	if err := json.Unmarshal([]byte(reflectionBeamBody), &req); err != nil {
		t.Fatal(err)
	}
	req.ExtraParams = extractExtraParams([]byte(reflectionBeamBody))
	for _, provider := range []schemas.ModelProvider{schemas.Anthropic, schemas.Bedrock, schemas.Gemini} {
		got := toBifrostChatRequest(provider, req.Model, &req).Params.ExtraParams
		if _, ok := got["extra_body"]; !ok {
			t.Errorf("%s: extra_body dropped", provider)
		}
		for _, k := range []string{"chat_template_kwargs", "seed"} {
			if _, ok := got[k]; ok {
				t.Errorf("%s: OpenAI-only key %q forwarded", provider, k)
			}
		}
	}
}
