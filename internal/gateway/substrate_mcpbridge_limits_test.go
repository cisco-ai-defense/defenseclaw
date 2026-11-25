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

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The bridge must honor the shared reader's envelope bound. The ping barrier
// proves that a strict unknown-tier refusal happens before laptop forwarding.
func TestMCPBridgeReaderEnvelopeDepth(t *testing.T) {
	b := newTixgBridge(t, false)
	b.fixture.api.scannerCfg.Guardrail.Cascade.Unknown = config.CascadeBlock
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	cmd, _ := json.Marshal(tixgCommand)
	for i, depth := range []int{3, 4, actionfacts.MaxArgsProjectionDepth + 1} {
		t.Run(fmt.Sprintf("depth-%d-row-%d", depth, i), func(t *testing.T) {
			args := string(cmd)
			for j := 0; j < depth; j++ {
				args = fmt.Sprintf(`{"input":%s}`, args)
			}
			id := float64(980 + i)
			frame := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, int(id), args)
			tixgSend(t, agent, frame)
			tixgExpectErr(t, agent, laptop, id, -32001, boundedTruncatedTitle)
		})
	}
	// The last readable depth still uses the actual command rule.
	args := string(cmd)
	for j := 0; j < actionfacts.MaxArgsProjectionDepth; j++ {
		args = fmt.Sprintf(`{"input":%s}`, args)
	}
	tixgSend(t, agent, fmt.Sprintf(`{"jsonrpc":"2.0","id":990,"method":"tools/call","params":{"name":"read_file","arguments":%s}}`, args))
	tixgExpectErr(t, agent, laptop, float64(990), -32001, "CMD-RM-RF")
	tixgSend(t, agent, `{"jsonrpc":"2.0","id":991,"method":"tools/call","params":{"name":"read_file","arguments":{"input":{"command":"echo safe"}}}}`)
	if got := tixgMethods(tixgLaptopUntilBarrier(t, agent, laptop)); got != "tools/call" {
		t.Fatalf("benign readable envelope was not forwarded: %q", got)
	}
}

// Both default and strict policy must record the reader's depth issue.
func TestSubstrateMCPReaderEnvelopeDepthFinding(t *testing.T) {
	b := newTixgBridge(t, false)
	args := json.RawMessage(`{"input":{"request":{"parameters":{"command":"echo safe"}}}}`)
	verdict := func() SubstrateCalloutVerdict {
		bridge := &substrateMCPBridge{a: b.fixture.api, st: b.fixture.api.substrateState(), reg: b.reg, s: &substrateStream{target: "notes"}}
		return bridge.judge(t.Context(), "tools/call", substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{args}})
	}
	if v := verdict(); v.Verdict != "allow" || !slices.Contains(v.Findings, evaluationLimitRuleID) {
		t.Fatalf("default depth finding: %+v", v)
	}
	b.fixture.api.scannerCfg.Guardrail.Cascade.Unknown = config.CascadeBlock
	if v := verdict(); v.Verdict != "deny" || !slices.Contains(v.Findings, evaluationLimitRuleID) {
		t.Fatalf("strict depth finding: %+v", v)
	}
}

// Every bound enforced by ArgsLimitIssue enters the one-active-call actor
// admission, including bounds reached before the total byte cap.
func TestSubstrateMCPReaderLimitsUseActorAdmission(t *testing.T) {
	members := make(map[string]int, actionfacts.MaxJSONMembers+1)
	for i := 0; i <= actionfacts.MaxJSONMembers; i++ {
		members[fmt.Sprintf("k%d", i)] = i
	}
	memberRaw, _ := json.Marshal(members)
	scalarRaw, _ := json.Marshal(map[string]string{"command": strings.Repeat("x", 70<<10)})
	keyRaw, _ := json.Marshal(map[string]int{strings.Repeat("k", 5<<10): 1})
	depthRaw := json.RawMessage(strings.Repeat("[", actionfacts.MaxJSONDepth+1) + "0" + strings.Repeat("]", actionfacts.MaxJSONDepth+1))
	byteRaw, _ := json.Marshal(map[string]string{"content": strings.Repeat("x", actionfacts.MaxArgsJSONBytes)})
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{"scalar", scalarRaw}, {"key", keyRaw}, {"members", memberRaw},
		{"json-depth", depthRaw}, {"total-bytes", byteRaw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if issue := actionfacts.ArgsLimitIssue(tc.raw); issue == "" {
				t.Fatal("fixture did not reach a reader limit")
			}
			for _, c := range []substrateMCPJudgedCall{
				{tool: "read_file", args: []json.RawMessage{tc.raw}},
				{tool: "read_file", params: tc.raw},
			} {
				if !substrateMCPOverCap(c) {
					t.Fatalf("%s reader limit missed actor admission (bytes=%d)", tc.name, len(tc.raw))
				}
			}
		})
	}
}
