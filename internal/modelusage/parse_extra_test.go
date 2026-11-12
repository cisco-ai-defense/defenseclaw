package modelusage

import (
	"strings"
	"testing"
)

func TestResponsesCompletedLineLargerThanLineCapStillYieldsUsage(t *testing.T) {
	big := strings.Repeat("x", 3*maxLineBytes)
	line := `data: {"type":"response.completed","response":{"id":"r","model":"gpt-5-2025-08-07","output":[{"type":"message","content":[{"type":"output_text","text":"` + big +
		`"}]}],"usage":{"input_tokens":70,"input_tokens_details":{"cached_tokens":20},"output_tokens":9,"output_tokens_details":{"reasoning_tokens":3}}}}` + "\n\n"
	for _, chunk := range []int{1 << 20, 4096, 1000} {
		p := NewStreamParser(FamilyResponses)
		feed(p, []byte(line), chunk)
		u := p.Usage()
		if u.Input != 70 || u.Output != 9 || u.CacheRead != 20 || u.Reasoning != 3 || p.Dropped() != 1 {
			t.Fatalf("chunk %d: %+v dropped=%d", chunk, u, p.Dropped())
		}
		if len(p.bigTail) > maxTailBytes || len(p.buf) > maxLineBytes {
			t.Fatalf("buffers grew: tail=%d buf=%d", len(p.bigTail), len(p.buf))
		}
	}
}

func TestOversizeLineOfAnotherEventIsIgnored(t *testing.T) {
	p := NewStreamParser(FamilyResponses)
	line := `data: {"type":"response.output_text.delta","delta":"` + strings.Repeat("y", 3*maxLineBytes) + `","usage":{"input_tokens":1,"output_tokens":1}}` + "\n"
	feed(p, []byte(line), 8192)
	if u := p.Usage(); !u.IsEmpty() {
		t.Fatalf("a non-terminal event must not set usage: %+v", u)
	}
}

func TestHugeBodyReadsTailOnly(t *testing.T) {
	body := `{"id":"x","model":"gpt-5","choices":[{"message":{"content":"` + strings.Repeat("z", 2*maxFullDecodeBytes) +
		`"}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`
	u := ParseBody(FamilyChat, []byte(body))
	if u.Input != 11 || u.Output != 7 || u.Source != SourceProvider {
		t.Fatalf("%+v", u)
	}
	// a string in the content that looks like a usage key must not win
	body = `{"choices":[{"message":{"content":"` + strings.Repeat("z", 2*maxFullDecodeBytes) +
		`"}}],"usage":{"prompt_tokens":2,"completion_tokens":3}}`
	if u := ParseBody(FamilyChat, []byte(body)); u.Input != 2 {
		t.Fatalf("%+v", u)
	}
}

func TestPartialMarkers(t *testing.T) {
	cases := []struct {
		f    APIFamily
		body string
		want string
	}{
		{FamilyMessages, `{"usage":{"input_tokens":1,"output_tokens":1,"service_tier":"priority"}}`, "service_tier:priority"},
		{FamilyMessages, `{"usage":{"input_tokens":1,"output_tokens":1,"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":5}}}`, "cache_ttl_1h"},
		{FamilyMessages, `{"usage":{"input_tokens":1,"output_tokens":1,"server_tool_use":{"web_search_requests":2}}}`, "server_tools"},
		{FamilyMessages, `{"usage":{"input_tokens":1,"output_tokens":1,"service_tier":"standard","server_tool_use":{"web_search_requests":0}}}`, ""},
		{FamilyChat, `{"service_tier":"flex","usage":{"prompt_tokens":1,"completion_tokens":1}}`, "service_tier:flex"},
		{FamilyResponses, `{"service_tier":"default","usage":{"input_tokens":1,"output_tokens":1}}`, ""},
		{FamilyGemini, `{"modelVersion":"gemini-2.5-pro","usageMetadata":{"promptTokenCount":250000,"candidatesTokenCount":1}}`, "long_context"},
		{FamilyGemini, `{"modelVersion":"gemini-2.5-flash","usageMetadata":{"promptTokenCount":250000,"candidatesTokenCount":1}}`, ""},
		{FamilyMessages, `{"usage":{"input_tokens":1,"output_tokens":1,"service_tier":"made-up"}}`, ""},
	}
	for i, c := range cases {
		if got := ParseBody(c.f, []byte(c.body)).Partial; got != c.want {
			t.Errorf("case %d: partial %q, want %q", i, got, c.want)
		}
	}
}

func TestGeminiToolUsePromptCountsAsInput(t *testing.T) {
	u := ParseBody(FamilyGemini, []byte(`{"usageMetadata":{"promptTokenCount":100,"toolUsePromptTokenCount":40,"candidatesTokenCount":5}}`))
	if u.Input != 140 || u.Output != 5 {
		t.Fatalf("%+v", u)
	}
}

func TestAnthropicStreamDeltaCanCarryInputFields(t *testing.T) {
	p := NewStreamParser(FamilyMessages)
	feed(p, []byte("data: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"usage\":{\"input_tokens\":3,\"cache_read_input_tokens\":10,\"output_tokens\":1}}}\n"+
		"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":4,\"output_tokens\":20}}\n"), 5)
	u := p.Usage()
	if u.Input != 14 || u.CacheRead != 10 || u.Output != 20 {
		t.Fatalf("last value wins per field: %+v", u)
	}
}
