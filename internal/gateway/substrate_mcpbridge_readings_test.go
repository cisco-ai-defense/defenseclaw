// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

var tixgBarrierSeq atomic.Int64

// tixgLaptopUntilBarrier sends a ping after the messages just sent and
// returns what the laptop got before it (the method, or "answer <id>", and
// the start of each message). The bridge handles an agent's messages in
// order, so whatever it forwarded arrives first and a test names it instead
// of waiting out a read timeout.
func tixgLaptopUntilBarrier(t *testing.T, agent, laptop *websocket.Conn) []string {
	t.Helper()
	pid := fmt.Sprintf("tixg-barrier-%d", tixgBarrierSeq.Add(1))
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":"`+pid+`","method":"ping"}`)
	var got []string
	for {
		_ = laptop.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, p, err := laptop.ReadMessage()
		if err != nil {
			t.Fatalf("laptop read before the ping barrier: %v (saw %q)", err, got)
		}
		if strings.Contains(string(p), `"`+pid+`"`) {
			return got
		}
		var m map[string]any
		_ = json.Unmarshal(p, &m)
		what, ok := m["method"].(string)
		if !ok {
			what = fmt.Sprint("answer ", m["id"])
		}
		got = append(got, fmt.Sprintf("%s %.160s", what, p))
	}
}

// tixgMethods is the method part of tixgLaptopUntilBarrier's entries.
func tixgMethods(seen []string) string {
	var out []string
	for _, s := range seen {
		out = append(out, strings.SplitN(s, " {", 2)[0])
	}
	return strings.Join(out, "|")
}

// RV-0841b F1 (substrate-1:GAP-0841): prompts/get and completion/complete
// are judged on their arguments as a tools/call is, and on their whole
// params as before, so a rule that reads the prompt name, the completion
// reference or _meta still holds them. With the test-only fixture rule
// (arguments naming the laptop key are denied) each of these was blocked at
// fa5cf8f802 and forwarded at 8c221c0216. Many small members ahead of the
// command (F3) are denied through the bridge too.
func TestMCPBridgeJudgesPromptNameRefAndMetaAgain(t *testing.T) {
	marker := "id_" + "rsa"
	real := substrateMCPJudge
	substrateMCPJudge = func(a *APIServer, ctx context.Context, reg registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
		if strings.Contains(string(req.Args), marker) {
			return SubstrateCalloutVerdict{V: "1", Verdict: "deny", Source: "tool_rules", Reason: "GAP0841B-FIXTURE laptop key read", Severity: "HIGH"}
		}
		return real(a, ctx, reg, req)
	}
	t.Cleanup(func() { substrateMCPJudge = real })

	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	key := "/home/alice/." + "ssh/" + marker
	denied := []string{
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"show ` + key + `"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"` + key + `","arguments":{"topic":"q"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"x","_meta":{"p":"` + key + `"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file://` + key + `{x}"},"argument":{"name":"x","value":""}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"` + key + `"},"argument":{"name":"x","value":"a"}}}`,
	}
	for i, s := range denied {
		tixgSend(t, agent, s)
		tixgExpectErr(t, agent, laptop, float64(i+1), -32001, "GAP0841B-FIXTURE")
	}

	cmd, _ := json.Marshal(tixgCommand)
	var members []string
	for i := range 1600 {
		members = append(members, fmt.Sprintf(`"a%05d":"x"`, i))
	}
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file","arguments":{`+
		strings.Join(members, ",")+`,"command":`+string(cmd)+`}}}`)
	tixgExpectErr(t, agent, laptop, float64(6), -32001, "CMD-RM-RF")

	benign := []string{
		`{"jsonrpc":"2.0","id":20,"method":"prompts/get","params":{"name":"summary","arguments":{"topic":"q4"},"_meta":{"progressToken":"t"}}}`,
		`{"jsonrpc":"2.0","id":21,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///notes/{name}"},"argument":{"name":"name","value":"a"}}}`,
	}
	for _, s := range benign {
		tixgSend(t, agent, s)
	}
	if got, want := tixgMethods(tixgLaptopUntilBarrier(t, agent, laptop)), "prompts/get|completion/complete"; got != want {
		t.Fatalf("laptop saw %s, want %s (benign prompt and completion calls are carried)", got, want)
	}
}

// RV-0841b F5 (substrate-1:GAP-0841): a null field carries no data, so it is
// judged as absent and a clean call is carried, as at fa5cf8f802; a numeric
// argument name is read by its number. A command beside a null argument is
// still denied, and a field of the wrong shape (an array, a string) is still
// refused.
func TestMCPBridgeNullPromptAndCompletionFieldsAreAbsent(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	carried := []string{
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"x","arguments":null}}`,
		`{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"x","value":"a"},"context":null}}`,
		`{"jsonrpc":"2.0","id":3,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"x","value":"a"},"context":{"arguments":null}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":null,"context":{"arguments":{"lang":"en"}}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":7,"value":"a"}}}`,
	}
	for _, s := range carried {
		tixgSend(t, agent, s)
	}
	want := "prompts/get|completion/complete|completion/complete|completion/complete|completion/complete"
	if seen := tixgLaptopUntilBarrier(t, agent, laptop); tixgMethods(seen) != want {
		for range len(carried) - len(seen) {
			if m := tixgRead(t, agent); m["error"] != nil {
				t.Errorf("refused: %v", m["error"])
			}
		}
		t.Fatalf("laptop saw %q, want %s (null fields are absent, a numeric name is read)", seen, want)
	}

	cmd, _ := json.Marshal(tixgCommand)
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":10,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":null,"context":{"arguments":{"command":`+string(cmd)+`}}}}`)
	tixgExpectErr(t, agent, laptop, float64(10), -32001, "CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":12,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"x","value":"a"},"context":"command"}}`)
	tixgExpectErr(t, agent, laptop, float64(12), -32600, "invalid_message: ")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":13,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":"x"}}`)
	tixgExpectErr(t, agent, laptop, float64(13), -32600, "invalid_message: ")
}

func tixgVerdict(t *testing.T, b *tixgBridge, tool, args string) SubstrateCalloutVerdict {
	t.Helper()
	return b.fixture.api.substrateMCPVerdict(t.Context(), b.reg, substrateCalloutRequest{V: "1",
		MCP: calloutapi.MCP{Server: "notes", Tool: tool, Transport: "stdio"}, Args: json.RawMessage(args)})
}

// RV-0841b F2 (substrate-1:GAP-1094): a long string whose tail is a shell
// separator and a denied command is denied as the small call is. The tail
// cut dropped the split word and left the projection starting with the
// separator, so the shell reader read nothing and the call was an alert;
// the cut now puts a placeholder word where the dropped word was.
func TestSubstrateMCPVerdictTailCommandAfterSeparator(t *testing.T) {
	b := newTixgBridge(t, false)
	for _, sep := range []string{" ; ", " && ", " | ", ";", "\n", " ;\n"} {
		small, _ := json.Marshal(map[string]string{"command": "x" + sep + tixgCommand})
		if v := tixgVerdict(t, b, "read_file", string(small)); v.Verdict != "deny" {
			t.Fatalf("small call with %q: %+v, want deny (the test needs a separator the shell rules read)", sep, v)
		}
		large, _ := json.Marshal(map[string]string{"command": strings.Repeat("A", 70000) + sep + tixgCommand})
		if v := tixgVerdict(t, b, "read_file", string(large)); v.Verdict != "deny" || !strings.Contains(v.Reason, "CMD-RM-RF") {
			t.Errorf("70 KB pad then %q then the command: %s %q %v, want deny CMD-RM-RF like the small call", sep, v.Verdict, v.Reason, v.Findings)
		}
	}
	for _, c := range []struct {
		s, want string
		n       int
	}{
		// The cut keeps two bytes for the placeholder.
		{"AAAAAAAA ; rm x", "x ; rm x", 10}, // a split word
		{"AAAAAAAA;rm x", "x;rm x", 9},
		{"AAAAAAAA && rm x", "x && rm x", 11},
		{"AAAA ; rm x", "x ; rm x", 9}, // a word that ends at the cut
		{"AAAA rm x", "x rm x", 6},     // rm stays an argument
		{"AAAA ;rm x", "rm x", 6},      // and a command after a separator
		{"AAAA ;\nrm x", "rm x", 6},
	} {
		if got := substrateMCPCut(c.s, c.n, true); got != c.want {
			t.Errorf("tail cut(%q, %d) = %q, want %q (a placeholder where the dropped word was)", c.s, c.n, got, c.want)
		}
	}
}

// RV-0841b F3 (substrate-1:GAP-1094): the argument keys the structured
// reading reads (command, path, url, ...) go into the first window of a
// projection, so any number of small members ahead of the command is denied
// as the small call is, at the same bounded number of projections.
func TestSubstrateMCPVerdictReadKeysInFirstWindow(t *testing.T) {
	b := newTixgBridge(t, false)
	cmd, _ := json.Marshal(tixgCommand)
	for _, n := range []int{1600, 5000} {
		for _, val := range []string{`"x"`, `1`} {
			var members []string
			for i := range n {
				members = append(members, fmt.Sprintf(`"a%05d":%s`, i, val))
			}
			args := `{` + strings.Join(members, ",") + `,"command":` + string(cmd) + `}`
			if v := tixgVerdict(t, b, "read_file", args); v.Verdict != "deny" || !strings.Contains(v.Reason, "CMD-RM-RF") {
				t.Errorf("%d members of %s then the command: %s %q %v, want deny CMD-RM-RF", n, val, v.Verdict, v.Reason, v.Findings)
			}
			if got := len(substrateMCPArgsProjections(json.RawMessage(args))); got > 8 {
				t.Errorf("%d members: %d projections, want at most 8", n, got)
			}
		}
	}
}

// RV-0841b F6 (substrate-1:GAP-1094): only the call's own reading goes to the
// LLM judge; its bounded projections are read by the rules alone, so a
// large call costs one judge round trip, as a small one does.
func TestSubstrateMCPProjectionsSkipTheJudge(t *testing.T) {
	b := newTixgBridge(t, false)
	api := b.fixture.api
	api.scannerCfg.Guardrail.DetectionStrategy = "regex_judge"
	api.scannerCfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true,
		HookConnectors: []string{sandboxauth.CanonicalConnector(b.reg.Connector)}}
	mock := &mockLLMProvider{err: errors.New("judge down")}
	api.SetHookJudge(&LLMJudge{cfg: &api.scannerCfg.Guardrail.Judge, model: "test-model", provider: mock, rp: &guardrail.RulePack{}})

	small := `{"path":"/notes/a.txt","content":"hello"}`
	tixgVerdict(t, b, "write_note", small)
	if n := boundedJudgeCalls(mock); n != 1 {
		t.Fatalf("a small call asked the judge %d times, want 1 (the test needs the judge on)", n)
	}
	var members []string
	for i := range 1600 {
		members = append(members, fmt.Sprintf(`"k%05d":"%s"`, i, strings.Repeat("hello ", 30)))
	}
	large := `{"path":"/notes/a.txt",` + strings.Join(members, ",") + `}`
	if len(substrateMCPArgsProjections(json.RawMessage(large))) < 2 {
		t.Fatal("the large call has no projections; the test needs some")
	}
	tixgVerdict(t, b, "write_note", large)
	if n := boundedJudgeCalls(mock) - 1; n != 1 {
		t.Fatalf("a large call asked the judge %d times, want 1 (projections are read by the rules alone)", n)
	}
	// A deterministic argument denial short-circuits before the primary
	// params reading. This pins the accepted RV-0841c F2 behavior: neither
	// AID nor the judge needs to run after a stricter verdict is final.
	t.Run("denied arguments stop before primary", func(t *testing.T) {
		real := substrateMCPJudge
		var seen []bool
		substrateMCPJudge = func(_ *APIServer, ctx context.Context, _ registry.Registration, _ substrateCalloutRequest) SubstrateCalloutVerdict {
			seen = append(seen, substrateMCPReadingOf(ctx).rulesOnly)
			return SubstrateCalloutVerdict{V: "1", Verdict: "deny", Source: "tool_rules"}
		}
		t.Cleanup(func() { substrateMCPJudge = real })
		bridge := &substrateMCPBridge{a: b.fixture.api, reg: b.reg, s: &substrateStream{target: "notes"}}
		v := bridge.judge(t.Context(), "prompts/get", substrateMCPJudgedCall{
			tool: "prompts_get", args: []json.RawMessage{json.RawMessage(tixgBlockedArgs)},
			params: json.RawMessage("{}"),
		})
		if v.Verdict != "deny" || len(seen) != 1 || !seen[0] {
			t.Fatalf("deny short circuit: verdict %s, rulesOnly calls %v; want one rules-only denial", v.Verdict, seen)
		}
	})

}
