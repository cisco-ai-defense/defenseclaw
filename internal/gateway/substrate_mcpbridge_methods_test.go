// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestMCPBridgeJudgesEveryMethod (GAP-0841): resources/read, prompts/get,
// completion/complete and resources/subscribe are judged by the same verdict
// as a tools/call (tool names resources_read, prompts_get, ..., the params as
// the arguments). A denied one never reaches the laptop server and writes a
// denied row; a method that is not on the bridge allow list is refused with
// a JSON-RPC method-not-found error and a denied row. The benign MCP client
// traffic still reaches the laptop as before.
func TestMCPBridgeJudgesEveryMethod(t *testing.T) {
	// Test-only rule fixture: arguments naming the laptop SSH key are
	// denied, everything else gets the real verdict.
	type judged struct{ tool, args string }
	var mu sync.Mutex
	var calls []judged
	real := substrateMCPJudge
	substrateMCPJudge = func(a *APIServer, ctx context.Context, reg registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
		mu.Lock()
		calls = append(calls, judged{req.MCP.Tool, string(req.Args)})
		mu.Unlock()
		if strings.Contains(string(req.Args), "id_rsa") {
			return SubstrateCalloutVerdict{V: "1", Verdict: "deny", Source: "tool_rules", Reason: "GAP0841-FIXTURE laptop key read", Severity: "HIGH"}
		}
		return real(a, ctx, reg, req)
	}
	t.Cleanup(func() { substrateMCPJudge = real })

	b := newTixgBridge(t, false)
	const readCmd = `{"uri":"file:///notes/a.txt","command":"rm -rf / --no-preserve-root"}`
	if v := real(b.fixture.api, t.Context(), b.reg, substrateCalloutRequest{V: "1",
		MCP: calloutapi.MCP{Server: "notes", Tool: "resources_read", Transport: "stdio"}, Args: json.RawMessage(readCmd)}); v.Verdict != "deny" {
		t.Fatalf("direct verdict %+v, want deny (the test needs a read the shipped rules block)", v)
	}
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	send := func(s string) {
		t.Helper()
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	expectErr := func(id any, code float64, prefix string) {
		t.Helper()
		m := tixgRead(t, agent)
		e, _ := m["error"].(map[string]any)
		msg, _ := e["message"].(string)
		if m["id"] != id || e == nil || e["code"] != code || !strings.HasPrefix(msg, prefix) {
			t.Fatalf("answer %v, want id %v code %v %q", m, id, code, prefix)
		}
	}
	const key = "file:///home/alice/.ssh/id_rsa"
	// Laptop data through the methods tools/call rules never saw.
	send(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"` + key + `"}}`)
	expectErr(float64(1), -32001, "mcp_call_denied: The guard denied tool notes.resources_read: GAP0841-FIXTURE")
	send(`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"show","arguments":{"file":"~/.ssh/id_rsa"}}}`)
	expectErr(float64(2), -32001, "mcp_call_denied: The guard denied tool notes.prompts_get: GAP0841-FIXTURE")
	send(`{"jsonrpc":"2.0","id":"c3","method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///{path}"},"argument":{"name":"path","value":"/home/alice/.ssh/id_rsa"}}}`)
	expectErr("c3", -32001, "mcp_call_denied: The guard denied tool notes.completion_complete: GAP0841-FIXTURE")
	send(`{"jsonrpc":"2.0","id":4,"method":"resources/subscribe","params":{"uri":"` + key + `"}}`)
	expectErr(float64(4), -32001, "mcp_call_denied: The guard denied tool notes.resources_subscribe: GAP0841-FIXTURE")
	// The shipped tool rules read a read's params as a tools/call's
	// arguments: the command a tools/call would be denied for is denied here.
	send(`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":` + readCmd + `}`)
	expectErr(float64(5), -32001, "mcp_call_denied: The guard denied tool notes.resources_read: ")
	// A notification form is judged too and gets no answer.
	send(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"` + key + `"}}`)
	// Methods off the bridge allow list are refused, request or notification.
	send(`{"jsonrpc":"2.0","id":6,"method":"notes/dump","params":{"path":"/home/alice"}}`)
	expectErr(float64(6), -32601, "mcp_method_not_bridged: ")
	send(`{"jsonrpc":"2.0","method":"x/leak","params":{"path":"/home/alice"}}`)
	send(`{"jsonrpc":"2.0","id":7,"method":"secrets/list"}`)
	expectErr(float64(7), -32601, "mcp_method_not_bridged: ")
	// A folded or padded spelling of an allowed method is not that method.
	send(`{"jsonrpc":"2.0","id":8,"method":"Resources/Read","params":{"uri":"` + key + `"}}`)
	expectErr(float64(8), -32600, "invalid_message: ")
	send(`{"jsonrpc":"2.0","id":9,"method":" prompts/get","params":{"name":"show"}}`)
	expectErr(float64(9), -32600, "invalid_message: ")
	// A notification has no id; a message that is neither a request nor a
	// response is not JSON-RPC.
	send(`{"jsonrpc":"2.0","id":10,"method":"notifications/leak"}`)
	expectErr(float64(10), -32600, "invalid_message: ")
	send(`{"jsonrpc":"2.0","id":11,"params":{"uri":"` + key + `"}}`)
	expectErr(float64(11), -32600, "invalid_message: ")
	// A judged read with params that are not an object is refused.
	send(`{"jsonrpc":"2.0","id":12,"method":"resources/read","params":["` + key + `"]}`)
	expectErr(float64(12), -32600, "invalid_message: ")

	// Benign controls: what an MCP client sends, and its answers to the
	// laptop's own requests, still reach the laptop in order.
	benign := []string{
		`{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":21,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":22,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":23,"method":"resources/list","params":{"cursor":"x"}}`,
		`{"jsonrpc":"2.0","id":24,"method":"resources/templates/list"}`,
		`{"jsonrpc":"2.0","id":25,"method":"prompts/list"}`,
		`{"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}}}`,
		`{"jsonrpc":"2.0","id":27,"method":"resources/read","params":{"uri":"file:///notes/a.txt"}}`,
		`{"jsonrpc":"2.0","id":28,"method":"prompts/get","params":{"name":"summary","arguments":{"topic":"q4"}}}`,
		`{"jsonrpc":"2.0","id":29,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"summary"},"argument":{"name":"topic","value":"q"}}}`,
		`{"jsonrpc":"2.0","id":30,"method":"logging/setLevel","params":{"level":"info"}}`,
		`{"jsonrpc":"2.0","id":31,"method":"resources/subscribe","params":{"uri":"file:///notes/a.txt"}}`,
		`{"jsonrpc":"2.0","id":32,"method":"resources/unsubscribe","params":{"uri":"file:///notes/a.txt"}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":26}}`,
		`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`,
		`{"jsonrpc":"2.0","id":"s1","result":{"roots":[]}}`,
		`{"jsonrpc":"2.0","id":"s2","error":{"code":-1,"message":"no"}}`,
	}
	for _, s := range benign {
		send(s)
	}
	var got []string
	for len(got) < len(benign) {
		m := tixgRead(t, laptop)
		if m["method"] == nil {
			got = append(got, "answer "+m["id"].(string))
			continue
		}
		method := m["method"].(string)
		got = append(got, method)
		p, _ := m["params"].(map[string]any)
		uri, _ := p["uri"].(string)
		if strings.Contains(strings.ToLower(method), "leak") || strings.Contains(method, "dump") || strings.Contains(uri, "id_rsa") {
			t.Fatalf("a refused message reached the laptop: %v", m)
		}
	}
	want := "initialize|notifications/initialized|ping|tools/list|resources/list|resources/templates/list|prompts/list|" +
		"tools/call|resources/read|prompts/get|completion/complete|logging/setLevel|resources/subscribe|resources/unsubscribe|" +
		"notifications/cancelled|notifications/roots/list_changed|answer s1|answer s2"
	if strings.Join(got, "|") != want {
		t.Fatalf("laptop saw\n %s\nwant\n %s", strings.Join(got, "|"), want)
	}
	// The laptop's answer to the allowed read reaches the agent unchanged.
	if err := laptop.WriteMessage(websocket.BinaryMessage, []byte(`{"jsonrpc":"2.0","id":27,"result":{"contents":[]}}`)); err != nil {
		t.Fatal(err)
	}
	if m := tixgRead(t, agent); m["id"] != float64(27) || m["result"] == nil {
		t.Fatalf("answer %v", m)
	}

	// Each judged method was judged as its tool name with its params as the
	// arguments (prompts/get and completion/complete twice: on their
	// arguments and on their whole params, RV-0841b F1); methods with no
	// laptop data the rules read were not judged.
	mu.Lock()
	var tools []string
	for _, c := range calls {
		tools = append(tools, c.tool)
	}
	first := calls[0]
	mu.Unlock()
	if first.tool != "resources_read" || first.args != `{"uri":"`+key+`"}` {
		t.Fatalf("first verdict read %+v, want resources_read with the params", first)
	}
	if want := "resources_read|prompts_get|completion_complete|resources_subscribe|resources_read|resources_read|" +
		"read_note|resources_read|prompts_get|prompts_get|completion_complete|completion_complete|resources_subscribe"; strings.Join(tools, "|") != want {
		t.Fatalf("verdicts %s, want %s", strings.Join(tools, "|"), want)
	}

	// Rows: 6 judged denials (with tool and method) and 7 refusals.
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		var judgedRows, notBridged, other int
		for _, a := range b.audits {
			if a["event"] != "substrate.mcp.denied" {
				continue
			}
			tool, _ := a["tool"].(string)
			switch {
			case tool != "" && a["method"] != nil && a["method"] != "tools/call":
				judgedRows++
			case a["reason"] == "mcp_method_not_bridged" && a["method"] != nil:
				notBridged++
			case a["reason"] == "invalid_message":
				other++
			}
		}
		b.mu.Unlock()
		if judgedRows == 6 && notBridged == 3 && other == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("denied rows: %d judged, %d not bridged, %d other (want 6, 3, 5)", judgedRows, notBridged, other)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
