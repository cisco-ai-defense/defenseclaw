// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// substrate-1 GAP-0340: Devin and Copilot name no tool invocation, but their
// result carries the call's command and output, so a credentials read of a
// Substrate actor joins its result by session and command. A failed read
// that provably read nothing is cleared; everything else still refuses the
// actor's next upload at the hook and at the egress callout.

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

type gap0340Step struct {
	pre  bool // a pre-tool call (else its result)
	cmd  string
	ok   bool   // the result reports success
	text string // the result's output
	sess string // "" is s1
}

func gap0340Event(conn string, s gap0340Step) map[string]interface{} {
	sess := s.sess
	if sess == "" {
		sess = "s1"
	}
	text := s.text
	if !s.ok {
		text = "Exit code 1\n" + s.text
	}
	switch conn {
	case "copilot":
		args, _ := json.Marshal(map[string]string{"command": s.cmd})
		ev := map[string]interface{}{"_event": "preToolUse", "sessionId": sess, "timestamp": float64(1), "cwd": "/work",
			"toolName": "bash", "toolArgs": string(args)}
		switch {
		case s.pre:
		case s.ok:
			ev["_event"] = "postToolUse"
			ev["toolResult"] = map[string]interface{}{"resultType": "success", "textResultForLlm": text}
		default:
			ev["_event"] = "postToolUseFailure"
			ev["toolResult"] = map[string]interface{}{"resultType": "failure", "textResultForLlm": text}
		}
		return ev
	default: // devin
		ev := map[string]interface{}{"hook_event_name": "PreToolUse", "session_id": sess, "tool_name": "exec",
			"tool_input": map[string]interface{}{"command": s.cmd}}
		if !s.pre {
			ev["hook_event_name"] = "PostToolUse"
			ev["tool_response"] = text
		}
		return ev
	}
}

func TestGAP0340CommandJoinDevin(t *testing.T) { gap0340CommandJoin(t, "devin") }

func TestGAP0340CommandJoinCopilot(t *testing.T) { gap0340CommandJoin(t, "copilot") }

// gap0340CommandJoin runs the rows on conn in the default and the managed
// strict pack (the chain decision does not depend on the pack; every pack
// runs in TestSecretReadChainStartDevin and TestSecretReadChainStartCopilot).
func gap0340CommandJoin(t *testing.T, conn string) {
	const missing = "cat: .env: No such file or directory"
	pre := func(cmd string) gap0340Step { return gap0340Step{pre: true, cmd: cmd} }
	res := func(cmd string, ok bool, text string) gap0340Step { return gap0340Step{cmd: cmd, ok: ok, text: text} }
	// want: "clear" (no refusal anywhere), "refuse" (the hook refuses the
	// upload with the chain and the callout refuses), "pending" (the read is
	// still pending: the callout refuses, as for a paired call whose result
	// has not come; the hook judges the upload against completed reads only),
	// "reported" (the step is reported unrecorded to the callout, review
	// rch3 R1, as for a paired call's result with no call).
	for _, tc := range []struct {
		name  string
		steps []gap0340Step
		want  string
	}{
		{"missing file, cleared", []gap0340Step{pre("cat .env"), res("cat .env", false, missing)}, "clear"},
		{"two missing files, cleared", []gap0340Step{pre("cat .env .env.local"),
			res("cat .env .env.local", false, missing+"\ncat: .env.local: No such file or directory")}, "clear"},
		{"printed and failed", []gap0340Step{pre("cat .env ."), res("cat .env .", false, "API_KEY=canary-1\ncat: .: Is a directory")}, "refuse"},
		{"success", []gap0340Step{pre("cat .env"), res("cat .env", true, "API_KEY=canary-1")}, "refuse"},
		{"same command twice, the second printed", []gap0340Step{pre("cat .env"), pre("cat .env"),
			res("cat .env", false, missing), res("cat .env", true, "API_KEY=canary-1")}, "refuse"},
		{"missing-file text plus other output", []gap0340Step{pre("cat .env"), res("cat .env", false, missing+"\nAPI_KEY=canary-1")}, "refuse"},
		{"no result yet", []gap0340Step{pre("cat .env")}, "pending"},
		{"result of another command", []gap0340Step{pre("cat .env"), res("cat .env.local", false, "cat: .env.local: No such file or directory")}, "pending"},
		{"result in another session", []gap0340Step{pre("cat .env"), {cmd: "cat .env", text: missing, sess: "s2"}}, "pending"},
		{"a result with no call before it", []gap0340Step{res("cat .env", true, "API_KEY=canary-1")}, "reported"},
	} {
		for _, p := range chainStartPacks {
			if p.name != "default" && p.name != "managed-strict" {
				continue
			}
			t.Run(p.name+"/"+tc.name, func(t *testing.T) {
				r, chains, contract := chainStartReplica(t, conn, p.pack, p.managed)
				for _, s := range tc.steps {
					chainStartHook(t, r, conn, contract, gap0340Event(conn, s))
				}
				got, _ := chainStartHook(t, r, conn, contract, gap0340Event(conn, pre(chainStartSend)))
				v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
					Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
				})
				if err != nil {
					t.Fatal(err)
				}
				chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress)
				blocked := got.Action == guardrailActionBlock
				switch tc.want {
				case "clear":
					if v.Deny || v.Unrecorded != "" || chain || blocked {
						t.Fatalf("after a cleared read: callout %+v, hook %q %v", v, got.Action, got.RuleIDs)
					}
				case "refuse":
					if !v.Deny || !chain || !blocked {
						t.Fatalf("after a read: callout %+v, hook %q %v, want both refused with the chain", v, got.Action, got.RuleIDs)
					}
				case "pending":
					if !v.Deny || v.Rule != guardrail.ToolChainSecretReadThenEgress {
						t.Fatalf("while the read is pending: callout %+v, want refused by the secret-read chain", v)
					}
				case "reported":
					if v.Unrecorded == "" {
						t.Fatalf("a result with no call: callout %+v, want the step reported unrecorded", v)
					}
				}
			})
		}
	}
}
