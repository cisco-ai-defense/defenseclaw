// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"time"

	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"strings"
	"testing"
)

// GAP-1105: a conflict inside the shared reader's nested envelope, or
// between that envelope and its parent, cannot hide a denied command.
func TestMCPBridgeNestedConflictingReadValues(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	cmd, _ := json.Marshal(tixgCommand)
	nested, _ := json.Marshal(`{"command":"x","script":` + string(cmd) + `}`)
	cases := []struct {
		method, args string
	}{
		{"tools/call", `{"input":{"command":"x","script":` + string(cmd) + `}}`},
		{"tools/call", `{"command":"x","input":{"script":` + string(cmd) + `}}`},
		{"tools/call", `{"request":{"parameters":{"command":"x","scripT":` + string(cmd) + `}}}`},
		{"tools/call", `{"args":{"command":"x","script":` + string(cmd) + `}}`},
		{"tools/call", `{"input":` + string(nested) + `}`},
		{"tools/call", `{"command":"x","input":` + string(cmd) + `}`},
		{"completion/complete", `{"input":{"command":"x","script":` + string(cmd) + `}}`},
	}
	for i, tc := range cases {
		id := i + 800
		var frame string
		if tc.method == "completion/complete" {
			frame = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"topic","value":"q"},"context":{"arguments":%s}}}`, id, tc.args)
		} else {
			frame = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, id, tc.args)
		}
		tixgSend(t, agent, frame)
		tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
	}
	// The completion argument and its context are merged into one reader
	// object. Their conflicting values must be judged separately.
	tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":899,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"script","value":%s},"context":{"arguments":{"input":{"command":"x"}}}}}`, string(cmd)))
	tixgExpectErr(t, agent, laptop, float64(899), -32001, "CMD-RM-RF")
}

// Distinct variants must be whole, conflict-free readings; the benign
// baseline command must not suppress the denied nested command.
func TestSubstrateMCPNestedReadFieldVariants(t *testing.T) {
	cmd, _ := json.Marshal(tixgCommand)
	for _, args := range []string{
		`{"input":{"command":"x","script":` + string(cmd) + `}}`,
		`{"command":"x","input":{"script":` + string(cmd) + `}}`,
		`{"request":{"parameters":{"command":"x","scripT":` + string(cmd) + `}}}`,
	} {
		base, alts, changed, overflow, _ := substrateMCPReadFieldVariantsUpTo(json.RawMessage(args), int(^uint(0)>>1))
		if !changed || overflow || len(alts) == 0 {
			t.Fatalf("variants for %s: changed=%v overflow=%v alternates=%d", args, changed, overflow, len(alts))
		}
		found := false
		for _, candidate := range append([]json.RawMessage{base}, alts...) {
			if strings.Contains(string(candidate), tixgCommand) && !strings.Contains(string(candidate), `"command":"x"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("no complete denied-command reading for %s", args)
		}
	}
	// Choosing the second envelope also keeps its path value, so this is
	// a complete reading of every field visible in that envelope.
	args := `{"input":{"command":"x","path":"/notes/first"},"parameters":{"script":` + string(cmd) + `,"path":"/notes/second"}}`
	_, alts, changed, overflow, _ := substrateMCPReadFieldVariantsUpTo(json.RawMessage(args), int(^uint(0)>>1))
	if !changed || overflow {
		t.Fatalf("two envelopes: changed=%v overflow=%v", changed, overflow)
	}
	complete := false
	for _, alt := range alts {
		if strings.Contains(string(alt), tixgCommand) && strings.Contains(string(alt), "/notes/second") &&
			!strings.Contains(string(alt), "/notes/first") {
			complete = true
		}
	}
	if !complete {
		t.Fatalf("second-envelope command had no complete candidate: %s", alts)
	}
}

// GAP-1105: concurrent large frames for one actor cannot occupy multiple
// rule evaluators. A normal call still proceeds while one is held.
func TestMCPBridgeOverCapActorJudgeLimit(t *testing.T) {
	real := substrateMCPJudge
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	substrateMCPJudge = func(_ *APIServer, _ context.Context, _ registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
		if len(req.Args) > actionfacts.MaxArgsJSONBytes {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		return SubstrateCalloutVerdict{V: "1", Verdict: "allow"}
	}
	t.Cleanup(func() { substrateMCPJudge = real })
	b := &substrateMCPBridge{st: &substrateState{}, reg: registry.Registration{Atespace: "test", UID: "actor"}, s: &substrateStream{target: "notes"}}
	large := substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(strings.Repeat(" ", actionfacts.MaxArgsJSONBytes+1))}}
	done := make(chan SubstrateCalloutVerdict, 1)
	go func() { done <- b.judge(t.Context(), "tools/call", large) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first over-cap reading did not enter")
	}
	if v := b.judge(t.Context(), "tools/call", substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(`{"command":"echo hi"}`)}}); v.Verdict != "allow" {
		t.Fatalf("normal call blocked by over-cap call: %+v", v)
	}
	if v := b.judge(t.Context(), "tools/call", large); v.Verdict != "deny" || !strings.Contains(v.Reason, "over-cap actor budget") {
		t.Fatalf("second over-cap call: %+v, want bounded refusal", v)
	}
	close(release)
	if v := <-done; v.Verdict != "allow" {
		t.Fatalf("first over-cap call: %+v", v)
	}
}

// The per-call byte cap prevents a large alias set from multiplying the
// frame into many full rules evaluations.
func TestSubstrateMCPReadFieldByteBudget(t *testing.T) {
	var members []string
	for i, key := range []string{"command", "cmd", "script", "rawcommand"} {
		members = append(members, fmt.Sprintf("%q:%q", key, fmt.Sprintf("echo %d %s", i, strings.Repeat("A", 60000))))
	}
	raw := json.RawMessage("{" + strings.Join(members, ",") + "}")
	const budget = 130 << 10
	base, alts, changed, overflow, byteExhausted := substrateMCPReadFieldVariantsUpTo(raw, budget)
	if !changed || !overflow || !byteExhausted || len(alts) == 0 {
		t.Fatalf("variants changed=%v overflow=%v alternates=%d; want bounded coverage and an unknown-tier floor", changed, overflow, len(alts))
	}
	bytes := len(base)
	for _, alt := range alts {
		bytes += len(alt)
	}
	if bytes > budget {
		t.Fatalf("candidate bytes %d exceed budget %d", bytes, budget)
	}
}

// A long payload still carries its non-empty field kind, while projections
// stay small enough that a benign write is not scanned twice at 64 KiB.
func TestSubstrateMCPPayloadProjectionWork(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"path": "/notes/a.txt", "content": strings.Repeat("hello world ", 18000)})
	projections := substrateMCPArgsProjections(raw)
	if len(projections) != 1 {
		t.Fatalf("large payload has %d projections, want one compact reading", len(projections))
	}
	for _, p := range projections {
		if len(p) > 1024 || actionfacts.ArgsLimitIssue(p) != "" {
			t.Fatalf("payload projection bytes=%d issue=%s, want a small readable object", len(p), actionfacts.ArgsLimitIssue(p))
		}
		var object map[string]any
		if err := json.Unmarshal(p, &object); err != nil || object["path"] != "/notes/a.txt" || object["content"] == "" {
			t.Fatalf("payload projection lost path or content kind: %s (%v)", p, err)
		}
	}
}

// A completion can carry two overlapping argument readings. If their
// alternate values exceed the call-wide byte budget, the bridge refuses
// rather than forwarding an unresolved ambiguity.
func TestMCPBridgeByteExhaustionRefuses(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	aliases := []string{"command", "cmd", "script", "rawcommand", "raw_command", "raw-command", "shellcommand", "shell_command", "shell-command"}
	contextArgs := make(map[string]any, len(aliases))
	for i, key := range aliases {
		contextArgs[key] = fmt.Sprintf("echo %d %s", i, strings.Repeat("A", 60000))
	}
	params := map[string]any{
		"ref":      map[string]any{"type": "ref/prompt", "name": "x"},
		"argument": map[string]any{"name": "command", "value": "echo changed " + strings.Repeat("C", 60000)},
		"context":  map[string]any{"arguments": contextArgs},
	}
	frame, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 901, "method": "completion/complete", "params": params})
	tixgSend(t, agent, string(frame))
	tixgExpectErr(t, agent, laptop, float64(901), -32001, "byte budget exhausted")
	// A single long benign command needs both head and tail projections.
	// It has no competing read value and keeps the configured unknown tier.
	long, _ := json.Marshal(strings.Repeat("A", 70000))
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":902,"method":"tools/call","params":{"name":"read_file","arguments":{"command":`+string(long)+`}}}`)
	if seen := tixgMethods(tixgLaptopUntilBarrier(t, agent, laptop)); seen != "tools/call" {
		t.Fatalf("benign long command was refused: laptop saw %q", seen)
	}
}
