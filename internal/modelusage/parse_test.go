package modelusage

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type want struct {
	in, out, cr, cc, rs int64
	has                 Has
	model               string
}

func check(t *testing.T, got Usage, w want) {
	t.Helper()
	if got.Has != w.has {
		t.Fatalf("Has = %05b, want %05b (%+v)", got.Has, w.has, got)
	}
	if got.Input != w.in || got.Output != w.out || got.CacheRead != w.cr || got.CacheCreation != w.cc || got.Reasoning != w.rs {
		t.Fatalf("counts = %+v, want %+v", got, w)
	}
	if got.ResponseModel != w.model {
		t.Fatalf("model = %q, want %q", got.ResponseModel, w.model)
	}
	if got.Anomaly != "" {
		t.Fatalf("unexpected anomaly %q", got.Anomaly)
	}
}

func TestParseBodyFamilies(t *testing.T) {
	cases := []struct {
		name string
		f    APIFamily
		file string
		w    want
	}{
		// Anthropic input_tokens is uncached only: 12 + 100 + 2000.
		{"anthropic", FamilyMessages, "anthropic_messages.json", want{2112, 34, 2000, 100, 0, HasInput | HasOutput | HasCacheRead | HasCacheCreation, "claude-haiku-4-5-20251001"}},
		{"chat", FamilyChat, "openai_chat.json", want{120, 80, 64, 0, 30, HasInput | HasOutput | HasCacheRead | HasReasoning, "gpt-5-2025-08-07"}},
		{"responses", FamilyResponses, "openai_responses.json", want{300, 90, 200, 0, 40, HasInput | HasOutput | HasCacheRead | HasReasoning, "gpt-5-2025-08-07"}},
		// Converse inputTokens is uncached: 14 + 1500 + 300.
		{"converse", FamilyConverse, "bedrock_converse.json", want{1814, 22, 1500, 300, 0, HasInput | HasOutput | HasCacheRead | HasCacheCreation, ""}},
		// Gemini output = candidates 60 + thoughts 25; prompt includes cached.
		{"gemini", FamilyGemini, "gemini.json", want{400, 85, 100, 0, 25, HasInput | HasOutput | HasCacheRead | HasReasoning, "gemini-2.5-pro"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := ParseBody(c.f, fixture(t, c.file))
			check(t, u, c.w)
			if u.Source != SourceProvider {
				t.Fatalf("source = %q", u.Source)
			}
		})
	}
}

func TestAbsentUsageStaysAbsent(t *testing.T) {
	u := ParseBody(FamilyMessages, fixture(t, "anthropic_messages_nousage.json"))
	if !u.IsEmpty() || u.Source != "" {
		t.Fatalf("want empty usage, got %+v", u)
	}
	for _, f := range []APIFamily{FamilyChat, FamilyResponses, FamilyConverse, FamilyGemini, FamilyOllama, FamilyOther} {
		for _, body := range []string{"", "[]", "not json", "{}", `{"usage":null}`} {
			if u := ParseBody(f, []byte(body)); !u.IsEmpty() {
				t.Fatalf("%s %q: want empty, got %+v", f, body, u)
			}
		}
	}
}

func TestRealZeroIsPresent(t *testing.T) {
	u := ParseBody(FamilyChat, []byte(`{"usage":{"prompt_tokens":0,"completion_tokens":0}}`))
	if u.Has != HasInput|HasOutput || u.Input != 0 || u.Output != 0 {
		t.Fatalf("zero counts must be present: %+v", u)
	}
}

func TestAnomaliesAreDroppedNotClamped(t *testing.T) {
	u := ParseBody(FamilyChat, []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":99}}}`))
	if u.Has&HasCacheRead != 0 || u.Anomaly != "inconsistent_cache" || u.Input != 10 {
		t.Fatalf("cache larger than input must be dropped: %+v", u)
	}
	u = ParseBody(FamilyChat, []byte(`{"usage":{"prompt_tokens":-5,"completion_tokens":1.0}}`))
	if u.Has != HasOutput || u.Anomaly != "invalid_count" || u.Output != 1 {
		t.Fatalf("negative count must be absent, integral float accepted: %+v", u)
	}
}

func feed(p *StreamParser, b []byte, chunk int) {
	for len(b) > 0 {
		n := chunk
		if n > len(b) {
			n = len(b)
		}
		p.Write(b[:n])
		b = b[n:]
	}
}

func TestStreamFamiliesAnyChunking(t *testing.T) {
	cases := []struct {
		name string
		f    APIFamily
		file string
		w    want
	}{
		{"anthropic", FamilyMessages, "anthropic_stream.sse", want{1025, 15, 1000, 0, 0, HasInput | HasOutput | HasCacheRead | HasCacheCreation, "claude-haiku-4-5-20251001"}},
		{"chat", FamilyChat, "openai_chat_stream.sse", want{50, 9, 0, 0, 0, HasInput | HasOutput | HasCacheRead | HasReasoning, "gpt-5-2025-08-07"}},
		{"responses", FamilyResponses, "openai_responses_stream.sse", want{10, 5, 0, 0, 0, HasInput | HasOutput | HasCacheRead | HasReasoning, "gpt-5-2025-08-07"}},
		{"gemini", FamilyGemini, "gemini_stream.sse", want{10, 5, 0, 0, 2, HasInput | HasOutput | HasReasoning, "gemini-2.5-flash"}},
	}
	for _, c := range cases {
		for _, chunk := range []int{1, 7, 64, 1 << 20} {
			p := NewStreamParser(c.f)
			feed(p, fixture(t, c.file), chunk)
			u := p.Usage()
			check(t, u, c.w)
			if u.Source != SourceStreamFinal {
				t.Fatalf("%s chunk %d: source %q", c.name, chunk, u.Source)
			}
		}
	}
}

func TestChatStreamWithoutUsageIsAbsent(t *testing.T) {
	p := NewStreamParser(FamilyChat)
	p.Write([]byte("data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"x\"}}],\"usage\":null}\n\ndata: [DONE]\n\n"))
	if u := p.Usage(); !u.IsEmpty() {
		t.Fatalf("stream without include_usage must stay absent: %+v", u)
	}
}

func TestOversizeGarbageLineIsCountedAndBounded(t *testing.T) {
	p := NewStreamParser(FamilyChat)
	p.Write([]byte("data: {\"x\":\""))
	big := make([]byte, 3*maxLineBytes)
	for i := range big {
		big[i] = 0x61
	}
	p.Write(big)
	p.Write([]byte("\"}\n"))
	p.Write([]byte("data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n"))
	u := p.Usage()
	if p.Dropped() != 1 || u.Input != 3 || u.Output != 4 {
		t.Fatalf("dropped=%d usage=%+v", p.Dropped(), u)
	}
	if len(p.buf) > maxLineBytes || len(p.bigTail) > maxTailBytes {
		t.Fatalf("buffers grew: %d %d", len(p.buf), len(p.bigTail))
	}
}

func TestGeminiJSONArrayStreamTailFallback(t *testing.T) {
	p := NewStreamParser(FamilyGemini)
	feed(p, []byte("[{\"candidates\":[],\n\"usageMetadata\": {\"promptTokenCount\": 7, \"candidatesTokenCount\": 2, \"totalTokenCount\": 9}\n}\n]"), 5)
	u := p.Usage()
	if u.Input != 7 || u.Output != 2 || u.Source != SourceStreamFinal {
		t.Fatalf("%+v", u)
	}
}

func TestOllamaNDJSON(t *testing.T) {
	p := NewStreamParser(FamilyOllama)
	feed(p, []byte("{\"model\":\"llama3\",\"response\":\"a\",\"done\":false}\n{\"model\":\"llama3\",\"done\":true,\"prompt_eval_count\":26,\"eval_count\":298}\n"), 9)
	u := p.Usage()
	if u.Input != 26 || u.Output != 298 || u.ResponseModel != "llama3" {
		t.Fatalf("%+v", u)
	}
}

func esFrame(event string, payload []byte) []byte {
	hdr := []byte{byte(len(":event-type"))}
	hdr = append(hdr, ":event-type"...)
	hdr = append(hdr, 7)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(event)))
	hdr = append(hdr, event...)
	total := 12 + len(hdr) + len(payload) + 4
	b := binary.BigEndian.AppendUint32(nil, uint32(total))
	b = binary.BigEndian.AppendUint32(b, uint32(len(hdr)))
	b = binary.BigEndian.AppendUint32(b, 0) // prelude CRC not checked
	b = append(b, hdr...)
	b = append(b, payload...)
	return binary.BigEndian.AppendUint32(b, 0)
}

func TestConverseEventStream(t *testing.T) {
	stream := append(esFrame("contentBlockDelta", []byte(`{"delta":{"text":"x"}}`)),
		esFrame("metadata", []byte(`{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13,"cacheReadInputTokens":50},"metrics":{"latencyMs":1}}`))...)
	for _, chunk := range []int{1, 13, 1 << 20} {
		p := NewStreamParser(FamilyConverse)
		feed(p, stream, chunk)
		check(t, p.Usage(), want{59, 4, 50, 0, 0, HasInput | HasOutput | HasCacheRead, ""})
	}
}

func TestInvokeEventStreamAnthropicChunks(t *testing.T) {
	enc := func(s string) []byte {
		return []byte(`{"bytes":"` + base64.StdEncoding.EncodeToString([]byte(s)) + `"}`)
	}
	stream := append(esFrame("chunk", enc(`{"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":5,"output_tokens":1}}}`)),
		esFrame("chunk", enc(`{"type":"message_delta","usage":{"output_tokens":8},"amazon-bedrock-invocationMetrics":{"inputTokenCount":5,"outputTokenCount":8}}`))...)
	p := NewStreamParser(FamilyInvoke)
	feed(p, stream, 11)
	check(t, p.Usage(), want{5, 8, 0, 0, 0, HasInput | HasOutput, "claude-x"})
}

func TestEventStreamGarbageStopsParsing(t *testing.T) {
	p := NewStreamParser(FamilyConverse)
	p.Write([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 0})
	p.Write(esFrame("metadata", []byte(`{"usage":{"inputTokens":1}}`)))
	if u := p.Usage(); !u.IsEmpty() || p.Dropped() != 1 {
		t.Fatalf("garbage prelude must stop the parser: %+v dropped=%d", u, p.Dropped())
	}
}

func TestNilParserIsSafe(t *testing.T) {
	var p *StreamParser
	p.Write([]byte("x"))
	if !p.Usage().IsEmpty() || p.Dropped() != 0 {
		t.Fatal("nil parser must be a no-op")
	}
	if NewStreamParser(FamilyOther) != nil {
		t.Fatal("unknown family has no parser")
	}
}
