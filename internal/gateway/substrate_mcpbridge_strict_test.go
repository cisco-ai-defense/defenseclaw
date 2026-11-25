// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// tixiLaptopReq decodes a request the way a Go MCP server does
// (mark3labs/mcp-go uses encoding/json struct decoding: keys match with
// case folding and the last duplicate wins).
type tixiLaptopReq struct {
	Method string `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

// TestMCPBridgeStrictKeys (GAP-0838): a frame with a duplicate key or a key
// that only folds to method, params, name or arguments (case, U+017F,
// U+212A) is refused with invalid_message and a denied row; it never reaches
// the laptop. The laptop end decodes with a Go struct and must never see the
// blocked call. Keys inside arguments are judged with the arguments.
func TestMCPBridgeStrictKeys(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	blocked := tixgBlockedArgs
	refused := map[float64]string{
		1:  `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"exec","arguments":` + blocked + `}}`,
		2:  `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","Arguments":` + blocked + `}}`,
		3:  `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}},"paramſ":{"name":"exec","arguments":` + blocked + `}}`,
		4:  `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","arguments":{"command":"ls"},"argumentſ":` + blocked + `}}`,
		5:  `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}},"param\u017f":{"name":"exec","arguments":` + blocked + `}}`,
		6:  `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"exec","name":"read_note","arguments":` + blocked + `}}`,
		7:  `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}},"params":{"name":"exec","arguments":` + blocked + `}}`,
		8:  `{"jsonrpc":"2.0","id":8,"method":"tools/list","method":"tools/call","params":{"name":"exec","arguments":` + blocked + `}}`,
		9:  `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"NAME":"exec","name":"read_note","arguments":` + blocked + `}}`,
		10: `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"exec","arguments":{"command":"ls"},"arguments":` + blocked + `}}`,
		15: `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"read_note","K":1,"k":2,"arguments":{"id":"a"}}}`,
		11: `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_note","K":1,"k":2,"arguments":{"id":"a"}}}`,
		12: `{"jsonrpc":"2.0","id":12,"method":"Tools/Call","params":{"name":"exec","arguments":` + blocked + `}}`,
		13: `{"jsonrpc":"2.0","id":13,"method":"tools/call ","params":{"name":"exec","arguments":` + blocked + `}}`,
		14: `{"jsonrpc":"2.0","id":14,"ID":99,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}}}`,
	}
	send := func(s string) {
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= len(refused); i++ {
		send(refused[float64(i)])
	}
	// Nested: keys inside arguments and a params key inside params are the
	// call's own data. They pass the parse; a folded twin of a blocked
	// argument is still judged and denied.
	send(`{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a","ID":"b","Name":"exec","Arguments":{"Method":"x"}}}}`)
	send(`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"},"params":{"name":"exec","arguments":` + blocked + `}}}`)
	send(`{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"exec","arguments":{"command":"ls","Command":` + strings.TrimPrefix(blocked, `{"command":`) + `}}`)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	answers := map[float64]string{}
	for len(answers) < len(refused)+1 {
		m := tixgRead(t, agent)
		id, _ := m["id"].(float64)
		e, _ := m["error"].(map[string]any)
		msg, _ := e["message"].(string)
		answers[id] = msg
	}
	for id := range refused {
		if !strings.HasPrefix(answers[id], "invalid_message: ") {
			t.Errorf("frame %v answered %q, want invalid_message", id, answers[id])
		}
	}
	if !strings.HasPrefix(answers[22], "mcp_call_denied: The guard denied tool notes.exec: ") {
		t.Errorf("folded twin of a blocked argument answered %q, want mcp_call_denied", answers[22])
	}
	var got []string
	for len(got) < 3 {
		_ = laptop.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, p, err := laptop.ReadMessage()
		if err != nil {
			t.Fatalf("laptop read: %v", err)
		}
		var r tixiLaptopReq
		if err := json.Unmarshal(p, &r); err != nil {
			t.Fatalf("laptop got %q: %v", p, err)
		}
		if r.Method == "tools/call" && (strings.Contains(strings.ToLower(r.Params.Name), "exec") || strings.Contains(fmt.Sprint(r.Params.Arguments), "--no-preserve-root")) {
			t.Fatalf("the laptop's Go decoder reads a blocked call: %s", p)
		}
		got = append(got, r.Method+" "+r.Params.Name)
	}
	if want := "tools/call read_note|tools/call read_note|notifications/initialized "; strings.Join(got, "|") != want {
		t.Fatalf("laptop saw %q, want %q", strings.Join(got, "|"), want)
	}
	tixiWaitDenied(t, b, len(refused)+1)
}

// TestMCPBridgeOversizeAnswer (GAP-0839): a laptop answer over
// message_max_bytes answers the agent's pending request with a JSON-RPC
// message_too_large error with its id. With no id to read the agent gets a
// control error frame; an oversize laptop request is refused to the laptop
// with its own id. Each one is a denied row.
func TestMCPBridgeOversizeAnswer(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	big := strings.Repeat("a", 1<<20)
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"` + big + `"}]}}`,
		`{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"` + big + `"}]},"id":8}`,
		`{"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{"x":"` + big + `"}}`,
		`{"jsonrpc":"2.0","id":10,"result":{"content":[]}}`,
	} {
		if err := laptop.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(c *websocket.Conn) (int, map[string]any) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		kind, p, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("not JSON: %q", p)
		}
		return kind, m
	}
	if kind, m := read(agent); kind != websocket.BinaryMessage || m["id"] != float64(7) ||
		!strings.HasPrefix(m["error"].(map[string]any)["message"].(string), "message_too_large: ") {
		t.Fatalf("agent got %v for the oversize answer to request 7, want a message_too_large error with id 7", m)
	}
	if kind, m := read(agent); kind != websocket.TextMessage || m["type"] != "error" || m["code"] != "message_too_large" {
		t.Fatalf("agent got %v for an oversize answer with no readable id, want a control error frame", m)
	}
	if _, m := read(agent); m["id"] != float64(10) || m["result"] == nil {
		t.Fatalf("agent got %v, want the answer to request 10 (nothing for the laptop's own oversize request)", m)
	}
	for _, want := range []any{nil, nil, float64(9)} {
		if _, m := read(laptop); m["id"] != want || !strings.HasPrefix(m["error"].(map[string]any)["message"].(string), "message_too_large: ") {
			t.Fatalf("laptop got %v, want message_too_large with id %v", m, want)
		}
	}
	tixiWaitDenied(t, b, 3)
}

func tixiWaitDenied(t *testing.T, b *tixgBridge, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		n := 0
		for _, a := range b.audits {
			if a["event"] == "substrate.mcp.denied" {
				n++
			}
		}
		b.mu.Unlock()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d denied rows, want %d", n, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
