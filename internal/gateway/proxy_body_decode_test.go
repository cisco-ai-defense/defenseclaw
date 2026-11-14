// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSSEFramerSpec(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     []string // data of the events that carry data
	}{
		{"lf", "data: a\n\ndata: b\n\n", []string{"a", "b"}},
		{"no space after the colon", "data:a\n\n", []string{"a"}},
		{"crlf", "data: a\r\n\r\ndata: b\r\n\r\n", []string{"a", "b"}},
		{"bare cr", "data: a\r\rdata: b\r\r", []string{"a", "b"}},
		{"mixed line ends", "data: a\r\n\ndata: b\n\r\n", []string{"a", "b"}},
		{"several data lines", "data: a\ndata: b\ndata:c\n\n", []string{"a\nb\nc"}},
		{"comment and other fields", ": hi\nevent: x\nid: 1\nretry: 5\ndata: a\n\n", []string{"a"}},
		{"byte-order mark", "\xEF\xBB\xBFdata: a\n\n", []string{"a"}},
		{"only the first space is dropped", "data:  a\n\n", []string{" a"}},
		{"field without a colon", "data\n\n", []string{""}},
		{"no data", ": ping\n\nevent: x\n\n", nil},
		{"unterminated last event", "data: a\n\ndata: b", []string{"a", "b"}},
	} {
		for _, split := range []bool{false, true} {
			f := &sseFramer{}
			var events []sseEvent
			if split {
				for i := 0; i < len(c.in); i++ {
					events = append(events, f.Write([]byte{c.in[i]}, false)...)
				}
			} else {
				events = f.Write([]byte(c.in), false)
			}
			events = append(events, f.Write(nil, true)...)
			var got []string
			var raw bytes.Buffer
			for _, ev := range events {
				raw.Write(ev.Raw)
				if ev.HasData {
					got = append(got, ev.Data)
				}
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") || len(got) != len(c.want) {
				t.Errorf("%s (split=%v): data %q, want %q", c.name, split, got, c.want)
			}
			if raw.String() != c.in {
				t.Errorf("%s (split=%v): the events do not add up to the stream: %q", c.name, split, raw.String())
			}
		}
	}
	f := &sseFramer{}
	f.Write([]byte("{\"type\":\"x\"}\n\n"), false)
	if f.DataEvents != 0 || f.Unframed != 1 {
		t.Errorf("a JSON line in an event stream is neither data nor unframed: %+v", f)
	}
	big := &sseFramer{}
	big.Write(bytes.Repeat([]byte("a"), sseEventMax+1), false)
	if !big.Broken() {
		t.Error("an event over the cap is not broken")
	}
}

func TestDecodeBodyEncodingsAndCharsets(t *testing.T) {
	const plain = `{"input":"héllo 😀"}`
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	for _, enc := range []string{"gzip", "deflate", "raw-deflate", "br", "zstd", "gzip, br"} {
		wire := strings.ReplaceAll(enc, "raw-deflate", "deflate")
		d, err := decodeBody(hdr("Content-Encoding", wire), encodeReply(t, enc, []byte(plain)))
		if err != nil || string(d.Text) != plain || !d.Decoded || d.Transcoded {
			t.Errorf("%s: %q %v %+v", enc, d.Text, err, d)
		}
		// The stream decoder reads what the buffered one reads.
		r, closeFn, err := newStreamDecoder(hdr("Content-Encoding", wire), bytes.NewReader(encodeReply(t, enc, []byte(plain))))
		if err != nil {
			t.Errorf("%s: stream decoder: %v", enc, err)
			continue
		}
		got, err := io.ReadAll(r)
		closeFn()
		if err != nil || string(got) != plain {
			t.Errorf("%s: stream %q %v", enc, got, err)
		}
	}
	u16 := func(order string, bom bool) []byte {
		var out []byte
		if bom {
			out = append(out, map[string][]byte{"le": {0xFF, 0xFE}, "be": {0xFE, 0xFF}}[order]...)
		}
		for _, r := range plain {
			if r > 0xFFFF {
				hi, lo := (r-0x10000)>>10+0xD800, (r-0x10000)&0x3FF+0xDC00
				for _, u := range []rune{hi, lo} {
					out = appendU16(out, order, uint16(u))
				}
				continue
			}
			out = appendU16(out, order, uint16(r))
		}
		return out
	}
	for name, c := range map[string]struct {
		body []byte
		ct   string
	}{
		"utf-8 mark":        {append([]byte{0xEF, 0xBB, 0xBF}, plain...), "application/json"},
		"utf-16le mark":     {u16("le", true), "application/json"},
		"utf-16be mark":     {u16("be", true), "application/json"},
		"utf-16le charset":  {u16("le", false), "application/json; charset=utf-16le"},
		"utf-16be charset":  {u16("be", false), "application/json; charset=UTF-16BE"},
		"utf-16le no label": {u16("le", false), "application/json"},
		"utf-16be no label": {u16("be", false), "application/json"},
		"utf-8 charset":     {[]byte(plain), "application/json; charset=utf-8"},
		"unlabelled utf-8":  {[]byte(plain), ""},
		"latin-1":           {[]byte("{\"input\":\"h\xe9llo\"}"), "application/json; charset=iso-8859-1"},
	} {
		d, err := decodeBody(hdr("Content-Type", c.ct), c.body)
		want := plain
		if strings.HasPrefix(name, "latin") {
			want = `{"input":"héllo"}`
		}
		if err != nil || string(d.Text) != want {
			t.Errorf("%s: %q %v", name, d.Text, err)
		}
	}
	for name, h := range map[string]http.Header{
		"unknown encoding":    hdr("Content-Encoding", "dc-test-enc"),
		"too many layers":     hdr("Content-Encoding", "gzip, gzip, gzip, gzip, gzip"),
		"unsupported charset": hdr("Content-Type", "application/json; charset=shift_jis"),
	} {
		if _, err := decodeBody(h, []byte(plain)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := decodeBody(hdr("Content-Encoding", "gzip"), []byte("not gzip")); err == nil {
		t.Error("a corrupt gzip body decoded")
	}
	if _, err := decodeBody(hdr("Content-Type", "application/json; charset=utf-16"), []byte{'{', 0, '"'}); err == nil {
		t.Error("an odd-length UTF-16 body decoded")
	}
	if _, _, err := newStreamDecoder(hdr("Content-Encoding", "gzip"), strings.NewReader("not gzip")); err == nil {
		t.Error("a corrupt gzip stream opened")
	}
}

func appendU16(b []byte, order string, u uint16) []byte {
	if order == "le" {
		return append(b, byte(u), byte(u>>8))
	}
	return append(b, byte(u>>8), byte(u))
}

func TestPromptWalkHistoryAndAllowlist(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       []string // segments
		unreadable string
	}{
		{"history is not read again", `{"model":"m","input":[{"role":"user","content":"old"},{"role":"assistant","content":"mid"},{"role":"user","content":"new"}]}`, []string{"new"}, ""},
		{"system and developer turns are always read", `{"input":[{"role":"system","content":"sys"},{"role":"user","content":"old"},{"role":"assistant","content":"mid"},{"role":"developer","content":"dev"},{"role":"user","content":"new"}]}`, []string{"sys", "dev", "new"}, ""},
		{"a prefill is read", `{"messages":[{"role":"user","content":"old"},{"role":"assistant","content":"prefill"}]}`, []string{"prefill"}, ""},
		{"tool results since the last model turn", `{"input":[{"type":"function_call","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"out1"},{"type":"function_call_output","call_id":"d","output":"out2"}]}`, []string{"out1", "out2"}, ""},
		{"ids, enums and media are not text", `{"model":"m","id":"x1","input":[{"id":"i1","type":"message","role":"user","status":"completed","content":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"},{"type":"input_text","text":"hi"}]}],"stream":true,"temperature":0.2}`, []string{"hi"}, ""},
		{"a property named type keeps its description", `{"tools":[{"name":"f","input_schema":{"properties":{"type":{"type":"string","description":"kind"}}}}]}`, []string{"f", "kind"}, ""},
		{"nested repeated key", `{"input":[{"role":"user","content":"a","content":"b"}]}`, []string{"a", "b"}, "the body repeats the key content"},
		{"nested folded key", `{"input":[{"role":"user","Content":"a","content":"b"}]}`, []string{"a", "b"}, "the body spells the key content two ways"},
		{"role spelled another way", `{"input":[{"Role":"assistant","content":"a"}]}`, []string{"a"}, "the body spells the key role another way"},
		{"not valid json", `{"input":`, nil, "the body is not valid JSON"},
	} {
		got := passthroughPromptFor([]byte(c.body), false, 0)
		if strings.Join(got.Segments, "|") != strings.Join(c.want, "|") || len(got.Segments) != len(c.want) || (got.Unreadable != c.unreadable && (!strings.HasPrefix(c.unreadable, "the body is not valid JSON") || !strings.HasPrefix(got.Unreadable, c.unreadable))) {
			t.Errorf("%s: %q / %q, want %q / %q", c.name, got.Segments, got.Unreadable, c.want, c.unreadable)
		}
	}
	var deep strings.Builder
	for i := 0; i < walkMaxDepth+10; i++ {
		deep.WriteString(`{"a":`)
	}
	deep.WriteString(`"x"`)
	deep.WriteString(strings.Repeat("}", walkMaxDepth+10))
	if got := passthroughPromptFor([]byte(deep.String()), false, 0); got.Unreadable == "" {
		t.Error("a body nested past the cap is read")
	}
	if got := passthroughPromptFor([]byte("plain text"), false, 0); got.Unreadable != "" || strings.Join(got.Segments, "\n") != "plain text" {
		t.Errorf("a text body that is not JSON is inspected as text: %+v", got)
	}
	if got := passthroughPromptFor([]byte{0x89, 'P', 'N', 'G', 0, 1, 2}, false, 0); got.Unreadable == "" {
		t.Errorf("a binary body that is not JSON must take the fail mode: %+v", got)
	}
	if got := passthroughPromptFor([]byte("<html>"), true, 0); got.Unreadable == "" {
		t.Error("a JSON content type with a body that is not JSON is read")
	}
}

func TestScanReplyTextAndCalls(t *testing.T) {
	for _, c := range []struct {
		name, body string
		text       []string
		calls      []string // name:arguments
	}{
		{"chat", `{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"hi","tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]},"finish_reason":"tool_calls"}],"usage":{"total_tokens":3}}`, []string{"hi"}, []string{`f:{"a":1}`}},
		{"legacy function_call", `{"choices":[{"message":{"role":"assistant","function_call":{"name":"f","arguments":"{}"}}}]}`, nil, []string{"f:{}"}},
		{"responses", `{"object":"response","instructions":"echoed","tools":[{"description":"echoed"}],"output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]},{"type":"function_call","call_id":"c","name":"f","arguments":"{\"a\":1}"},{"type":"shell_call","id":"s","action":{"commands":["x"]}},{"type":"mcp_call","name":"m","arguments":"{}","output":"result text"}]}`, []string{"hi", "result text"}, []string{`f:{"a":1}`, `shell_call:{"commands":["x"]}`, `m:{}`}},
		{"anthropic", `{"type":"message","content":[{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"f","input":{"a":"b & c"}}],"stop_reason":"tool_use"}`, []string{"hi"}, []string{`f:{"a":"b & c"}`}},
		{"gemini", `{"candidates":[{"content":{"parts":[{"text":"hi"},{"functionCall":{"name":"f","args":{"a":1}}}]},"finishReason":"STOP"}],"modelVersion":"v1"}`, []string{"hi"}, []string{`f:{"a":1}`}},
		{"converse", `{"output":{"message":{"content":[{"text":"hi"},{"toolUse":{"toolUseId":"t","name":"f","input":{"a":1}}}]}},"stopReason":"tool_use"}`, []string{"hi"}, []string{`f:{"a":1}`}},
		{"ollama", `{"model":"m","message":{"role":"assistant","content":"hi","tool_calls":[{"function":{"name":"f","arguments":{"a":1}}}]},"done":true}`, []string{"hi"}, []string{`f:{"a":1}`}},
	} {
		sc, err := scanReplyJSON([]byte(c.body), false, 0)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var calls []string
		for _, call := range sc.Calls {
			calls = append(calls, call.Function.Name+":"+call.Function.Arguments)
		}
		if strings.Join(sc.Segments, "|") != strings.Join(c.text, "|") || strings.Join(calls, "|") != strings.Join(c.calls, "|") {
			t.Errorf("%s: text %q calls %q, want %q %q", c.name, sc.Segments, calls, c.text, c.calls)
		}
	}
	sc, ok := scanReplyBody([]byte("{\"message\":{\"content\":\"a\"}}\n{\"message\":{\"content\":\"b\"},\"done\":true}\n"), 0)
	if !ok || strings.Join(sc.Segments, "|") != "a|b" {
		t.Errorf("ndjson: %+v %v", sc, ok)
	}
	if _, ok := scanReplyBody([]byte("<html>"), 0); ok {
		t.Error("html read as a reply")
	}
}

// A call that spans events is assembled across them, for every stream shape.
func TestSSEToolCallsAssemblesAnthropicAndChatLegacyCalls(t *testing.T) {
	s := newSSEToolCalls(0)
	for _, ev := range []string{
		`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu","name":"f","input":{}}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}`,
	} {
		s.Feed(ev)
	}
	if !s.Open() {
		t.Fatal("an open tool_use block is not held")
	}
	s.Feed(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}`)
	s.Feed(`{"type":"content_block_stop","index":1}`)
	if s.Open() || s.Broken() {
		t.Fatal("a finished block is still open")
	}
	if raw := string(s.Take()); !strings.Contains(raw, `"name":"f"`) || !strings.Contains(raw, `{\"a\":1}`) {
		t.Fatalf("anthropic call: %s", raw)
	}
	s.Feed(`{"choices":[{"delta":{"function_call":{"name":"g","arguments":"{}"}}}]}`)
	if !s.Open() {
		t.Fatal("a legacy function_call is not held")
	}
	s.Feed(`{"choices":[{"delta":{},"finish_reason":"function_call"}]}`)
	if raw := string(s.Take()); !strings.Contains(raw, `"name":"g"`) {
		t.Fatalf("legacy call: %s", raw)
	}
	// The snapshot in response.completed adds a call once.
	s.AddCalls([]sseToolCall{{Type: "function"}})
	s.AddCalls([]sseToolCall{{Type: "function"}})
	if raw := string(s.Take()); strings.Count(raw, `"type":"function"`) != 1 {
		t.Fatalf("a repeated call was added twice: %s", raw)
	}
}
