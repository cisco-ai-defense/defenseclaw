// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The token scan must answer exactly as the full decode it replaced
// (legacyRouteOnlyHumanText, kept below as the reference).
func TestRouteOnlyHumanTextMatchesTheFullDecode(t *testing.T) {
	long := strings.Repeat("é", 3*routeOnlyTextCap) + "tail"
	reminder := "<system-reminder>be brief</system-reminder>"
	cases := []string{
		``, `null`, `[]`, `{`, `{"messages":[}`, `{"messages":"x"}`, `{"messages":null}`, `{"messages":[null]}`,
		`{"messages":[1]}`, `{"messages":[{"role":5,"content":"hi"}]}`, `{"messages":[{"role":null,"content":"hi"}]}`,
		`{"messages":[{"role":"user","content":"hi"}]}`,
		`{"messages":[{"role":"user","content":"tool_result"}]}`,
		`{"messages":[{"role":"user","content":{"type":"text","text":"obj"}}]}`,
		`{"messages":[{"role":"user","content":[{"text":"late","type":"text"},{"type":"image","source":{}}]}]}`,
		`{"messages":[{"role":"user","content":[{"type":"input_text","text":"a"},{"type":"text","text":""},{"text":"b"}]}]}`,
		`{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"out"}]}]}]}`,
		`{"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"x"},{"role":"user","content":"` + reminder + `"}]}`,
		`{"messages":[{"role":"user","content":[{"type":"image"}]},{"role":"user","content":"second"},{"role":"user","content":[{"type":"image_url"}]}]}`,
		`{"messages":[{"role":"user","content":"q"},{"role":"tool","content":"r"}]}`,
		`{"messages":[{"content":"before role","role":"user"}]}`,
		`{"messages":[{"role":"user","content":[{"text":"converse"},{"image":{"format":"png"}}]}],"max_tokens":1e400}`,
		`{"Messages":[{"Role":"user","Content":[{"Type":"text","Text":"folded"}]}]}`,
		`{"messages":[{"role":"user","content":[5,"tool_result",{"type":7,"text":"t"},{"type":"text","text":9}]}]}`,
		`{"tools":[],"messages":[{"role":"user","content":"x"}]}`,
		`{"tools":[ ],"messages":[{"role":"user","content":"x"}]}`,
		`{"messages":[{"role":"user","content":"x"}],"tools" : null}`,
		`{"messages":[{"role":"user","content":"x"}],"tools":[{"name":"Bash"}],"stream":true}`,
		`{"messages":[{"role":"user","content":"x"}],"tools":{}}`,
		`{"messages":[{"role":"user","content":"` + long + `"}]}`,
		`{"messages":[{"role":"user","content":[{"type":"text","text":"` + long + `"},{"type":"text","text":"more"}]}]}`,
		`{"input":"plain"}`, `{"input":null}`, `{"input":{"a":1}}`, `{"input":7}`, `{"input":"` + reminder + `say"}`,
		`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"codex"}]},{"type":"function_call_output","output":"o"}]}`,
		`{"input":[{"type":"message","role":"developer","content":"dev"},{"role":"user","content":"u"}]}`,
		`{"input":[{"type":"message","role":5,"content":"bad role"},"str",null,{"role":"user","type":"reasoning","content":"r"}]}`,
		`{"input":[{"role":"user","content":[{"type":"input_image"}]},{"role":"user","content":"` + long + `"}],"tools":[1]}`,
		`{"messages":[{"role":"user","content":"m"}],"input":[{"role":"user","content":"i"}]}`,
	}
	for i, body := range cases {
		for _, family := range []string{"messages", "responses", "chat", "invoke"} {
			assertHumanTextSame(t, fmt.Sprintf("case %d %s", i, family), family, []byte(body))
		}
	}
}

func assertHumanTextSame(t *testing.T, name, family string, body []byte) {
	t.Helper()
	wt, wh, wtt, wi := legacyRouteOnlyHumanText(family, body)
	gt, gh, gtt, gi := routeOnlyHumanText(family, body)
	if wt != gt || wh != gh || wtt != gtt || wi != gi {
		t.Fatalf("%s: got (%q %v %v %v), the full decode gives (%q %v %v %v); body %.300s",
			name, clip(gt), gh, gtt, gi, clip(wt), wh, wtt, wi, body)
	}
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:40] + "..." + s[len(s)-40:]
	}
	return s
}

// Random conversations of every block shape the agents send.
func TestRouteOnlyHumanTextMatchesTheFullDecodeRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(110))
	for i := 0; i < 3000; i++ {
		family := []string{"messages", "responses"}[i%2]
		assertHumanTextSame(t, fmt.Sprintf("random %d", i), family, randomRouteBody(rng, family))
	}
}

func randomRouteText(rng *rand.Rand) any {
	words := []string{"fix the build", "<system-reminder>ctx</system-reminder>", "", "tool_result", "summarize", "é", "<system-reminder>open"}
	if rng.Intn(40) == 0 {
		return strings.Repeat("ab", routeOnlyTextCap+rng.Intn(3*routeOnlyTextCap))
	}
	switch rng.Intn(6) {
	case 0:
		return nil
	case 1:
		return rng.Intn(9)
	}
	return words[rng.Intn(len(words))] + words[rng.Intn(len(words))]
}

func randomRouteBlock(rng *rand.Rand) any {
	kinds := []any{"text", "input_text", "image", "input_image", "image_url", "tool_result", "tool_use", "thinking", "", nil, 3}
	b := map[string]any{}
	if rng.Intn(5) > 0 {
		b["type"] = kinds[rng.Intn(len(kinds))]
	}
	if rng.Intn(4) > 0 {
		b["text"] = randomRouteText(rng)
	}
	if rng.Intn(4) == 0 {
		b["content"] = []any{map[string]any{"type": "text", "text": randomRouteText(rng)}}
	}
	if rng.Intn(15) == 0 {
		return randomRouteText(rng)
	}
	return b
}

func randomRouteContent(rng *rand.Rand) any {
	switch rng.Intn(6) {
	case 0:
		return randomRouteText(rng)
	case 1:
		return nil
	}
	var blocks []any
	for j := rng.Intn(4); j >= 0; j-- {
		blocks = append(blocks, randomRouteBlock(rng))
	}
	return blocks
}

func randomRouteBody(rng *rand.Rand, family string) []byte {
	roles := []any{"user", "assistant", "tool", "system", "developer", "user", "user"}
	var list []any
	for j := rng.Intn(7); j >= 0; j-- {
		m := map[string]any{"role": roles[rng.Intn(len(roles))], "content": randomRouteContent(rng)}
		if family == "responses" {
			types := []any{"message", "", "function_call_output", "reasoning", "message", 4}
			m["type"] = types[rng.Intn(len(types))]
		}
		if rng.Intn(25) == 0 {
			list = append(list, randomRouteText(rng))
			continue
		}
		list = append(list, m)
	}
	body := map[string]any{"model": "m", "stream": true}
	key := "messages"
	if family == "responses" {
		key = "input"
		if rng.Intn(5) == 0 {
			body[key] = randomRouteText(rng)
		}
	}
	if _, set := body[key]; !set {
		body[key] = list
	}
	switch rng.Intn(4) {
	case 0:
		body["tools"] = []any{}
	case 1:
		body["tools"] = []any{map[string]any{"name": "Bash"}}
	case 2:
		body["tools"] = nil
	}
	raw, _ := json.Marshal(body)
	return raw
}

// largeRouteBody is a Claude Code shaped body of about size bytes: tool
// loops whose tool_result bodies carry the bulk, then the user prompt.
func largeRouteBody(size int, prompt string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"model":"claude-sonnet","system":[{"type":"text","text":"you are helpful"}],"messages":[`)
	chunk := strings.Repeat("line of file output 0123456789\\n", 4096)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, `{"role":"user","content":"step %d"},`, i)
		fmt.Fprintf(&b, `{"role":"assistant","content":[{"type":"tool_use","id":"t%d","name":"Read","input":{"file_path":"/x"}}]},`, i)
		fmt.Fprintf(&b, `{"role":"user","content":[{"type":"tool_result","tool_use_id":"t%d","content":[{"type":"text","text":"%s"}]}]},`, i, chunk)
	}
	fmt.Fprintf(&b, `{"role":"user","content":[{"type":"text","text":"<system-reminder>todo</system-reminder>%s"}]}],`, prompt)
	b.WriteString(`"tools":[{"name":"Read","input_schema":{"type":"object"}}],"max_tokens":32000,"stream":true}`)
	return b.Bytes()
}

// A 48 MiB body: the newest prompt is found, and the scan allocates far
// less than one more copy of the body (the decode it replaced copied every
// content field).
func TestRouteOnlyHumanTextLargeBody(t *testing.T) {
	body := largeRouteBody(48<<20, "why does the build fail")
	assertHumanTextSame(t, "large", "messages", body)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	text, hasTools, toolTurn, images := routeOnlyHumanText("messages", body)
	runtime.ReadMemStats(&after)
	if text != "why does the build fail" || !hasTools || toolTurn || images {
		t.Fatalf("text=%q tools=%v toolTurn=%v images=%v", text, hasTools, toolTurn, images)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(len(body)/4) {
		t.Fatalf("the scan allocated %d bytes for a %d byte body", alloc, len(body))
	}
	// The kept text is capped even when the prompt is huge.
	huge := largeRouteBody(1<<20, strings.Repeat("ab", 2*routeOnlyTextCap))
	if text, _, _, _ := routeOnlyHumanText("messages", huge); len(text) != routeOnlyTextCap {
		t.Fatalf("text is not capped: %d", len(text))
	}
}

func BenchmarkRouteOnlyHumanText(b *testing.B) {
	for _, size := range []int{64 << 10, 2 << 20, 32 << 20} {
		body := largeRouteBody(size, "explain the failing test")
		for _, impl := range []struct {
			name string
			fn   func(string, []byte) (string, bool, bool, bool)
		}{{"scan", routeOnlyHumanText}, {"fulldecode", legacyRouteOnlyHumanText}} {
			b.Run(fmt.Sprintf("%s/%dKiB", impl.name, size>>10), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				for i := 0; i < b.N; i++ {
					impl.fn("messages", body)
				}
			})
		}
	}
}

// legacyRouteOnlyHumanText is the full decode routeOnlyHumanText replaced
// (S1 slice 5a), kept as the reference the scan must match.
func legacyRouteOnlyHumanText(family string, body []byte) (text string, hasTools, toolTurn, images bool) {
	var probe struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Input json.RawMessage `json:"input"`
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return "", false, false, false
	}
	hasTools = len(bytes.TrimSpace(probe.Tools)) > 2
	if family == config.RoutingAPIResponses {
		var s string
		if json.Unmarshal(probe.Input, &s) == nil {
			return capText(stripReminders(s)), hasTools, false, false
		}
		var items []struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		_ = json.Unmarshal(probe.Input, &items)
		for i := len(items) - 1; i >= 0; i-- {
			it := items[i]
			if i == len(items)-1 && strings.HasSuffix(it.Type, "_output") {
				toolTurn = true
			}
			if it.Role == "user" && (it.Type == "" || it.Type == "message") {
				t, img := legacyContentText(it.Content)
				images = images || img
				if t = capText(stripReminders(t)); t != "" {
					return t, hasTools, toolTurn, images
				}
			}
		}
		return "", hasTools, toolTurn, images
	}
	for i := len(probe.Messages) - 1; i >= 0; i-- {
		m := probe.Messages[i]
		if i == len(probe.Messages)-1 && (m.Role == "tool" || bytes.Contains(m.Content, []byte("\"tool_result\""))) {
			toolTurn = true
		}
		if m.Role != "user" {
			continue
		}
		t, img := legacyContentText(m.Content)
		images = images || img
		if t = capText(stripReminders(t)); t != "" {
			return t, hasTools, toolTurn, images
		}
	}
	return "", hasTools, toolTurn, images
}

// contentText joins the text blocks of a content field (string or block
// list); tool_result blocks are skipped.
func legacyContentText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, false
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &blocks)
	var parts []string
	images := false
	for _, b := range blocks {
		switch b.Type {
		case "text", "input_text":
			parts = append(parts, b.Text)
		case "image", "input_image", "image_url":
			images = true
		case "":
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
	}
	return strings.Join(parts, "\n"), images
}
