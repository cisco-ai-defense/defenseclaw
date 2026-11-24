// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
)

// tixgCommand is the command of tixgBlockedArgs, which the shipped rules
// deny as a tools/call (CMD-RM-RF).
var tixgCommand = func() string {
	var m map[string]string
	if err := json.Unmarshal([]byte(tixgBlockedArgs), &m); err != nil {
		panic(err)
	}
	return m["command"]
}()

func tixgSend(t *testing.T, c *websocket.Conn, s string) {
	t.Helper()
	if err := c.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
		t.Fatal(err)
	}
}

// tixgExpectErr reads the bridge's error answer to the message just sent.
// A message the bridge forwarded to the laptop instead fails by name
// (tixgLaptopUntilBarrier), not on a read timeout.
func tixgExpectErr(t *testing.T, agent, laptop *websocket.Conn, id any, code float64, substr string) {
	t.Helper()
	if seen := tixgLaptopUntilBarrier(t, agent, laptop); len(seen) > 0 {
		t.Fatalf("the bridge forwarded %q to the laptop, want it refused with id %v code %v %q", seen, id, code, substr)
	}
	m := tixgRead(t, agent)
	e, _ := m["error"].(map[string]any)
	msg, _ := e["message"].(string)
	if m["id"] != id || e == nil || e["code"] != code || !strings.Contains(msg, substr) {
		t.Fatalf("answer %v, want id %v code %v with %q", m, id, code, substr)
	}
}

// tixgLaptopSees reads n messages on the laptop end and returns their
// methods (or "answer <id>"), failing on any message that names the blocked
// command.
func tixgLaptopSees(t *testing.T, laptop *websocket.Conn, n int) string {
	t.Helper()
	var got []string
	for len(got) < n {
		_ = laptop.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, p, err := laptop.ReadMessage()
		if err != nil {
			t.Fatalf("laptop read: %v (saw %v)", err, got)
		}
		if strings.Contains(string(p), tixgCommand) {
			t.Fatalf("a denied message reached the laptop: %.200s", p)
		}
		var m map[string]any
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("laptop got %q", p)
		}
		if method, ok := m["method"].(string); ok {
			got = append(got, method)
		} else {
			got = append(got, fmt.Sprint("answer ", m["id"]))
		}
	}
	return strings.Join(got, "|")
}

// TestMCPBridgeJudgesPromptAndCompletionArguments (RV-0841 F1, GAP-0841):
// prompts/get is judged on its arguments and completion/complete on the
// argument it completes (with the context arguments), so a shipped tool rule
// that denies a tools/call (CMD-RM-RF on a command argument) denies the same
// arguments here. Judged on the whole params object they sat one level too
// deep for the structured rules and were allowed.
func TestMCPBridgeJudgesPromptAndCompletionArguments(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	cmd, _ := json.Marshal(tixgCommand)
	// The parity anchor: the shipped rule denies the tools/call.
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":`+tixgBlockedArgs+`}}`)
	tixgExpectErr(t, agent, laptop, float64(1), -32001, "CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"x","arguments":{"command":`+string(cmd)+`}}}`)
	tixgExpectErr(t, agent, laptop, float64(2), -32001, "notes.prompts_get: matched: CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":3,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"command","value":`+string(cmd)+`}}}`)
	tixgExpectErr(t, agent, laptop, float64(3), -32001, "notes.completion_complete: matched: CMD-RM-RF")
	// The context arguments are read too, also when the completed argument
	// has the same name.
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":4,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"topic","value":"q"},"context":{"arguments":{"command":`+string(cmd)+`}}}}`)
	tixgExpectErr(t, agent, laptop, float64(4), -32001, "CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":5,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"command","value":"ls"},"context":{"arguments":{"command":`+string(cmd)+`}}}}`)
	tixgExpectErr(t, agent, laptop, float64(5), -32001, "CMD-RM-RF")
	// Arguments that are not the object the spec gives are refused, never
	// judged as no arguments.
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"name":"x","arguments":[`+string(cmd)+`]}}`)
	tixgExpectErr(t, agent, laptop, float64(6), -32600, "invalid_message: ")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":7,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"value":`+string(cmd)+`}}}`)
	tixgExpectErr(t, agent, laptop, float64(7), -32600, "invalid_message: ")

	// Benign controls reach the laptop.
	benign := []string{
		`{"jsonrpc":"2.0","id":20,"method":"prompts/get","params":{"name":"summary","arguments":{"topic":"q4"}}}`,
		`{"jsonrpc":"2.0","id":21,"method":"prompts/get","params":{"name":"summary"}}`,
		`{"jsonrpc":"2.0","id":22,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"summary"},"argument":{"name":"topic","value":"q"},"context":{"arguments":{"lang":"en"}}}}`,
		`{"jsonrpc":"2.0","id":23,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///notes/{name}"},"argument":{"name":"name","value":"a"}}}`,
	}
	for _, s := range benign {
		tixgSend(t, agent, s)
	}
	if got, want := tixgLaptopSees(t, laptop, len(benign)), "prompts/get|prompts/get|completion/complete|completion/complete"; got != want {
		t.Fatalf("laptop saw %s, want %s", got, want)
	}
}

// tixgPadded is tixgBlockedArgs with a pad string of n bytes before or after
// the command.
func tixgPadded(n int, after bool) string {
	cmd, _ := json.Marshal(tixgCommand)
	pad := `"a":"` + strings.Repeat("A", n) + `"`
	if after {
		return `{"command":` + string(cmd) + `,` + pad + `}`
	}
	return `{` + pad + `,"command":` + string(cmd) + `}`
}

// TestMCPBridgeLargeArgumentsAreJudged (GAP-1094): arguments past the bounds
// of the argument reading (a string over 64 KiB, over 256 KiB in all, more
// than 512 members, deeper than 16) made the structured rules read nothing,
// so padding turned a denied command into an allowed one. The bridge now
// judges bounded projections of such arguments as well and floors the
// verdict at the unknown tier: the padded command is denied as the small
// call is, and a large benign call is allowed with an alert row, never a
// silent allow.
func TestMCPBridgeLargeArgumentsAreJudged(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	id := 0
	for _, n := range []int{70 << 10, 200 << 10, 900 << 10} {
		for _, after := range []bool{false, true} {
			id++
			tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, id, tixgPadded(n, after)))
			tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
		}
	}
	cmd, _ := json.Marshal(tixgCommand)
	var members []string
	for i := range 600 {
		members = append(members, fmt.Sprintf(`"k%03d":1`, i))
	}
	others := []string{
		// More than 512 members, deeper than 16, a key over 4 KiB, a pad
		// inside a nested object, several pads over 256 KiB in all.
		`{` + strings.Join(members, ",") + `,"command":` + string(cmd) + `}`,
		`{"a":` + strings.Repeat("[", 17) + strings.Repeat("]", 17) + `,"command":` + string(cmd) + `}`,
		`{"` + strings.Repeat("K", 5000) + `":1,"command":` + string(cmd) + `}`,
		`{"o":{"x":"` + strings.Repeat("A", 70<<10) + `"},"command":` + string(cmd) + `}`,
		`{"p1":"` + strings.Repeat("A", 60000) + `","p2":"` + strings.Repeat("A", 60000) + `","p3":"` + strings.Repeat("A", 60000) +
			`","p4":"` + strings.Repeat("A", 60000) + `","p5":"` + strings.Repeat("A", 60000) + `","command":` + string(cmd) + `}`,
	}
	for _, args := range others {
		id++
		tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, id, args))
		tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
	}
	// The judged reads inherit it.
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":"r1","method":"resources/read","params":`+strings.Replace(tixgPadded(70<<10, false), `{`, `{"uri":"file:///notes/a.txt",`, 1)+`}`)
	tixgExpectErr(t, agent, laptop, "r1", -32001, "CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":"p1","method":"prompts/get","params":{"name":"x","arguments":`+tixgPadded(200<<10, true)+`}}`)
	tixgExpectErr(t, agent, laptop, "p1", -32001, "CMD-RM-RF")

	// Benign large calls are carried, with an alert row that names the
	// bound, as the hook path records a truncated reading.
	content, _ := json.Marshal(strings.Repeat("hello world\n", 20000))
	benign := []string{
		`{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"write_note","arguments":{"path":"/notes/a.txt","content":` + string(content) + `}}}`,
		`{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"write_note","arguments":{"path":"/notes/b.txt","content":"short"}}}`,
	}
	for _, s := range benign {
		tixgSend(t, agent, s)
	}
	if got, want := tixgLaptopSees(t, laptop, len(benign)), "tools/call|tools/call"; got != want {
		t.Fatalf("laptop saw %s, want %s", got, want)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		var alerts []string
		for _, a := range b.audits {
			if a["event"] == "substrate.mcp.alert" {
				reason, _ := a["reason"].(string)
				alerts = append(alerts, fmt.Sprint(a["tool"], " ", a["method"], " ", reason))
			}
		}
		b.mu.Unlock()
		if len(alerts) == 1 && strings.HasPrefix(alerts[0], "write_note tools/call "+boundedTruncatedTitle) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("alert rows %q, want one for the large write_note", alerts)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSubstrateMCPVerdictLargeArgumentsFloor (GAP-1094): the verdict of
// arguments past the reading's bounds is at least the unknown tier: alert
// (allow with the evaluation-limit finding) in the default pack, deny where
// guardrail.cascade.unknown is block. Arguments within the bounds keep
// their verdict and get no finding.
func TestSubstrateMCPVerdictLargeArgumentsFloor(t *testing.T) {
	b := newTixgBridge(t, false)
	verdict := func(args string) SubstrateCalloutVerdict {
		return b.fixture.api.substrateMCPVerdict(t.Context(), b.reg, substrateCalloutRequest{V: "1",
			MCP: calloutapi.MCP{Server: "notes", Tool: "write_note", Transport: "stdio"}, Args: json.RawMessage(args)})
	}
	large := `{"path":"/notes/a.txt","content":"` + strings.Repeat("hello ", 12000) + `"}`
	small := `{"path":"/notes/a.txt","content":"hello"}`
	if v := verdict(small); v.Verdict != "allow" || len(v.Findings) != 0 {
		t.Fatalf("small benign call %+v, want a plain allow", v)
	}
	if v := verdict(large); v.Verdict != "allow" || !slices.Contains(v.Findings, evaluationLimitRuleID) ||
		!strings.HasPrefix(v.Reason, boundedTruncatedTitle) {
		t.Fatalf("large benign call %+v, want allow with %s", v, evaluationLimitRuleID)
	}
	b.fixture.api.scannerCfg.Guardrail.Cascade.Unknown = config.CascadeBlock
	if v := verdict(large); v.Verdict != "deny" || !slices.Contains(v.Findings, evaluationLimitRuleID) {
		t.Fatalf("large benign call with cascade.unknown block %+v, want deny", v)
	}
	if v := verdict(small); v.Verdict != "allow" || len(v.Findings) != 0 {
		t.Fatalf("small benign call with cascade.unknown block %+v, want a plain allow", v)
	}
}

// TestMCPBridgeNotificationAllowList (RV-0841 F3, F4): only the client
// notifications of the MCP spec are carried; any other notifications/*
// spelling is refused with a denied row, and an id, result or error key in
// another case is refused as ambiguous. A top-level value that is not an
// object is named as such, and only an array as a batch.
func TestMCPBridgeNotificationAllowList(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	const key = "file:///home/alice/.ssh/id_rsa"
	refusedSilently := []string{
		`{"jsonrpc":"2.0","method":"notifications/x/../../resources/read","params":{"uri":"` + key + `"}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"` + key + `"}}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"` + key + `"}}`,
	}
	for _, s := range refusedSilently {
		tixgSend(t, agent, s)
	}
	tixgSend(t, agent, `{"jsonrpc":"2.0","method":"notifications/initialized","ID":5}`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: ")
	tixgSend(t, agent, `{"jsonrpc":"2.0","method":"Notifications/Initialized"}`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: the JSON-RPC method is not exactly notifications/initialized")
	tixgSend(t, agent, `{"jsonrpc":"2.0","Id":"s1","result":{}}`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: ")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":"s2","Error":{"code":1,"message":"x"}}`)
	tixgExpectErr(t, agent, laptop, "s2", -32600, "invalid_message: ")
	tixgSend(t, agent, `"tools/call"`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: the MCP message is not one JSON-RPC object")
	tixgSend(t, agent, `7`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: the MCP message is not one JSON-RPC object")
	tixgSend(t, agent, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	tixgExpectErr(t, agent, laptop, nil, -32600, "invalid_message: JSON-RPC batches are not bridged")

	benign := []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t","progress":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`,
		`{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"t1","status":"working"}}`,
		`{"jsonrpc":"2.0","id":"s3","result":{}}`,
	}
	for _, s := range benign {
		tixgSend(t, agent, s)
	}
	want := "notifications/initialized|notifications/cancelled|notifications/progress|notifications/roots/list_changed|notifications/tasks/status|answer s3"
	if got := tixgLaptopSees(t, laptop, len(benign)); got != want {
		t.Fatalf("laptop saw %s, want %s", got, want)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		var notBridged []string
		for _, a := range b.audits {
			if a["event"] == "substrate.mcp.denied" && a["reason"] == "mcp_method_not_bridged" {
				notBridged = append(notBridged, fmt.Sprint(a["method"]))
			}
		}
		b.mu.Unlock()
		if len(notBridged) == len(refusedSilently) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not-bridged rows %q, want %d", notBridged, len(refusedSilently))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSubstrateMCPCutKeepsWholeWords (GAP-1094): a projection cuts a long
// string at a word boundary, so the cut never makes a word the call did not
// carry ("/home/me/build" never becomes "/"), and stays valid UTF-8.
func TestSubstrateMCPCutKeepsWholeWords(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		tail bool
		want string
	}{
		{"rm -rf /home/me/build", 8, false, "rm -rf"},
		{"rm -rf /home/me/build", 7, false, "rm -rf "},
		{"build/me/home/ -rf rm", 8, true, "x -rf rm"},
		{"AAAAAAAAAA", 4, false, "AAAA"},
		{"AAAAAAAAAA", 6, true, "AAAA"},
		{"ééééé", 3, false, "é"},
		{"ééééé", 5, true, "é"},
		{"short", 64, false, "short"},
	} {
		if got := substrateMCPCut(c.s, c.n, c.tail); got != c.want {
			t.Errorf("cut(%q, %d, tail=%v) = %q, want %q", c.s, c.n, c.tail, got, c.want)
		}
	}
}

// TestSubstrateMCPVerdictMemberWindows (GAP-1094): more top-level members
// than the reading keeps are judged in windows, so a command after 600
// members whose keys sort first is still read; projections always fit the
// reading's bounds.
func TestSubstrateMCPVerdictMemberWindows(t *testing.T) {
	b := newTixgBridge(t, false)
	cmd, _ := json.Marshal(tixgCommand)
	var members []string
	for i := range 600 {
		members = append(members, fmt.Sprintf(`"a%03d":"x"`, i))
	}
	args := `{` + strings.Join(members, ",") + `,"command":` + string(cmd) + `}`
	v := b.fixture.api.substrateMCPVerdict(t.Context(), b.reg, substrateCalloutRequest{V: "1",
		MCP: calloutapi.MCP{Server: "notes", Tool: "read_file", Transport: "stdio"}, Args: json.RawMessage(args)})
	if v.Verdict != "deny" || !strings.Contains(v.Reason, "CMD-RM-RF") {
		t.Fatalf("verdict %+v, want deny CMD-RM-RF", v)
	}
	for _, p := range substrateMCPArgsProjections(json.RawMessage(args)) {
		if issue := actionfacts.ArgsLimitIssue(p); issue != "" {
			t.Fatalf("projection over the bounds (%s): %.120s", issue, p)
		}
	}
}

func TestMCPBridgeConflictingReadValues(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	cmd, _ := json.Marshal(tixgCommand)
	cases := []string{
		`{"command":"x","scripT":` + string(cmd) + `}`,
		`{"cmd":"echo hi","script":` + string(cmd) + `}`,
		`{"Command":"x","command":` + string(cmd) + `}`,
		`{"cmd":"x","command":"echo hi","script":` + string(cmd) + `,"commandline":"x"}`,
		`{"scr\u0130pt":` + string(cmd) + `,"command":"x"}`,
	}
	for i, args := range cases {
		tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, i+100, args))
		tixgExpectErr(t, agent, laptop, float64(i+100), -32001, "CMD-RM-RF")
	}
	var spellings []string
	for i := range 9 {
		key := []byte("commandline")
		key[i] -= 'a' - 'A'
		spellings = append(spellings, fmt.Sprintf("%q:%q", string(key), "echo hi"))
	}
	overflow := "{" + strings.Join(spellings, ",") + "}"
	bridge := &substrateMCPBridge{a: b.fixture.api, reg: b.reg, s: &substrateStream{target: "notes"}}
	v := bridge.judge(t.Context(), "tools/call", substrateMCPJudgedCall{
		tool: "read_file", args: []json.RawMessage{json.RawMessage(overflow)},
	})
	if v.Verdict != "allow" || !slices.Contains(v.Findings, evaluationLimitRuleID) {
		t.Fatalf("nine spellings: verdict %s findings %v, want allow with an evaluation-limit finding", v.Verdict, v.Findings)
	}
	var distinct []string
	for i := range 10 {
		key := []byte("commandline")
		key[i] -= 'a' - 'A'
		distinct = append(distinct, fmt.Sprintf("%q:%q", string(key), fmt.Sprintf("echo %d", i)))
	}
	v = bridge.judge(t.Context(), "tools/call", substrateMCPJudgedCall{
		tool: "read_file", args: []json.RawMessage{json.RawMessage("{" + strings.Join(distinct, ",") + "}")},
	})
	if v.Verdict != "allow" || !slices.Contains(v.Findings, evaluationLimitRuleID) {
		t.Fatalf("ten distinct values: verdict %s findings %v, want allow with an evaluation-limit finding", v.Verdict, v.Findings)
	}
}

// Case variants of two aliases exceed four projection windows without
// exceeding the bridge frame limit. The denied value must be read anywhere.
func TestMCPBridgeCaseVariantFlood(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	cmd, _ := json.Marshal(tixgCommand)
	id := 200
	for _, n := range []int{1600, 5000} {
		for _, at := range []int{0, n / 2, n - 1} {
			var members []string
			for i := 0; i < n; i++ {
				base, mask := "commandline", i
				if i >= 1600 {
					base, mask = "shellcommand", i-1600
				}
				var key strings.Builder
				for _, r := range base {
					if r >= 'a' && r <= 'z' {
						if mask&1 != 0 {
							r -= 'a' - 'A'
						}
						mask >>= 1
					}
					key.WriteRune(r)
				}
				k, _ := json.Marshal(key.String())
				v := `"echo hi"`
				if i == at {
					v = string(cmd)
				}
				members = append(members, string(k)+":"+v)
			}
			args := "{" + strings.Join(members, ",") + "}"
			tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, id, args))
			tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
			id++
		}
	}
	// A different recognized field can also occupy all projection windows
	// while the command is a separate member of the same object.
	for _, n := range []int{1600, 5000} {
		for _, at := range []int{0, n / 2, n} {
			var members []string
			for i := 0; i < n; i++ {
				mask := i
				var key strings.Builder
				for _, r := range "workingdirectory" {
					if mask&1 != 0 {
						r -= 'a' - 'A'
					}
					mask >>= 1
					key.WriteRune(r)
				}
				k, _ := json.Marshal(key.String())
				members = append(members, string(k)+`:"/notes"`)
			}
			members = append(members, "")
			copy(members[at+1:], members[at:])
			members[at] = `"scripT":` + string(cmd)
			args := "{" + strings.Join(members, ",") + "}"
			tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, id, args))
			tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
			id++
		}
	}
}
