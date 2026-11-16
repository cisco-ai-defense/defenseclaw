// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// A further result of a call the leader resolved (substrate-1 GAP-0348,
// GAP-0345; the 1.0.10 lead's ruling, STEER 2 2026-11-16). Claude Code posts
// PostToolUseFailure and then PostToolUse for one failed Bash call (SMK-CH2,
// 10 of 10 cells), Cursor postToolUseFailure and postToolUse, and the kit
// retries a post. A result with the same call identity, on either replica,
// joins the resolved call: a replay with no unrecorded mark. A result that
// joins nothing (its call reached no leader) is still marked (R1), and a
// further result whose content may show the read still chains: it never
// clears a read.

const (
	gap0348Read    = "cat .env.production"
	gap0348Missing = "cat: .env.production: No such file or directory"
)

func gap0348Post(id, stdout, stderr string) map[string]interface{} {
	post := claudeToolResult("PostToolUse", "s1", id)
	post["tool_input"] = map[string]interface{}{"command": gap0348Read}
	post["tool_response"] = map[string]interface{}{"stdout": stdout, "stderr": stderr, "interrupted": false, "isImage": false}
	return post
}

func gap0348Pre() map[string]interface{} {
	return claudeToolEvent("PreToolUse", "s1", "read-1", gap0348Read)
}

func gap0348Fail(text string) map[string]interface{} {
	return gap0342Fail("s1", "read-1", gap0348Read, text)
}

func gap0348Stop() map[string]interface{} {
	return map[string]interface{}{"hook_event_name": "Stop", "session_id": "s1"}
}

type gap0348Step struct {
	onB bool
	ev  map[string]interface{}
}

func a348(ev map[string]interface{}) gap0348Step { return gap0348Step{ev: ev} }
func b348(ev map[string]interface{}) gap0348Step { return gap0348Step{onB: true, ev: ev} }

// gap0348Run posts the steps on two replicas sharing one leader, then the
// actor's upload on replica A, and returns every hook answer, the upload's
// and the leader's egress verdict.
func gap0348Run(t *testing.T, steps []gap0348Step) ([]agentHookResponse, agentHookResponse, chainstate.EgressVerdict) {
	t.Helper()
	a, b, chains, onA, onB := gap0342Pair(t)
	var hooks []agentHookResponse
	for _, s := range steps {
		r := a
		if s.onB {
			onB()
			r = b
		} else {
			onA()
		}
		hooks = append(hooks, r.hook(t, "tok-alice", s.ev))
	}
	onA()
	upload, v := gap0342Egress(t, a, chains, subUID1, "tok-alice", "upload")
	return hooks, upload, v
}

func TestGAP0348SecondResultOfAClearedReadIsAReplay(t *testing.T) {
	benign := gap0348Post("read-1", "", gap0348Missing)
	for _, row := range []struct {
		name  string
		steps []gap0348Step
	}{
		{"failure-then-posttooluse", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), a348(benign)}},
		{"failure-on-B-then-posttooluse-on-A", []gap0348Step{a348(gap0348Pre()), b348(gap0348Fail(gap0348Missing)), a348(benign)}},
		{"failure-on-A-then-posttooluse-on-B", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), b348(benign)}},
		{"exact-duplicate", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), a348(gap0348Fail(gap0348Missing))}},
		{"exact-duplicate-on-B", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), b348(gap0348Fail(gap0348Missing))}},
		{"result-after-Stop", []gap0348Step{a348(gap0348Pre()), a348(gap0348Stop()), a348(gap0348Fail(gap0348Missing))}},
		{"second-result-after-Stop", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), a348(gap0348Stop()), b348(benign)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			hooks, upload, v := gap0348Run(t, row.steps)
			for i, h := range hooks {
				if slices.Contains(h.RuleIDs, substrateChainUnrecordedRule) {
					t.Fatalf("step %d: %q %v, want no unrecorded mark", i, h.Action, h.RuleIDs)
				}
			}
			if v.Deny || v.Unrecorded != "" || upload.Action == guardrailActionBlock {
				t.Fatalf("upload %q %v, callout %+v: want allowed and no unrecorded mark", upload.Action, upload.RuleIDs, v)
			}
		})
	}
}

func TestGAP0348SecondResultThatShowsTheReadStillChains(t *testing.T) {
	printed := gap0348Post("read-1", "API_KEY=canary-1", "")
	for _, row := range []struct {
		name  string
		steps []gap0348Step
	}{
		{"cleared-then-printed-posttooluse", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), a348(printed)}},
		{"cleared-on-B-then-printed-on-A", []gap0348Step{a348(gap0348Pre()), b348(gap0348Fail(gap0348Missing)), a348(printed)}},
		{"cleared-then-printed-on-B", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), b348(printed)}},
		{"duplicate-failure-that-printed", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)),
			a348(gap0348Fail("API_KEY=canary-1\n" + gap0348Missing))}},
		{"printed-then-cleared", []gap0348Step{a348(gap0348Pre()), a348(printed), b348(gap0348Fail(gap0348Missing))}},
		{"cleared-then-Stop-then-printed", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)), a348(gap0348Stop()), a348(printed)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, upload, v := gap0348Run(t, row.steps)
			gap0342Refused(t, row.name, upload, v)
		})
	}
}

// The R1 decision: the actor window's Missing is marked whatever the session
// says (review rk347 P3-1), a root join covers a session miss after Stop.
func TestGAP0348ResultCallUnjoined(t *testing.T) {
	const (
		missing  = audit.ToolChainPendingMissing
		resolved = audit.ToolChainPendingResolved
		replay   = audit.ToolChainPendingReplay
		noJoin   = audit.ToolChainPendingNoJoin
	)
	for _, tc := range []struct {
		name          string
		session, root audit.ToolChainPendingStatus
		bound, failed bool
		want          bool
	}{
		{"no actor window: session missing", missing, "", false, false, true},
		{"no actor window: session resolved", resolved, "", false, false, false},
		{"session replay over an actor-window miss (P3-1)", replay, missing, true, false, true},
		{"session resolved over an actor-window miss", resolved, missing, true, false, true},
		{"both missing", missing, missing, true, false, true},
		{"after Stop: session missing, actor window resolved", missing, resolved, true, false, false},
		{"further result: both replay", replay, replay, true, false, false},
		{"session missing, actor window replay", missing, replay, true, false, false},
		{"session missing, actor window no join", missing, noJoin, true, false, true},
		{"actor window failed (reported by the caller)", missing, "", true, true, false},
	} {
		if got := resultCallUnjoined(tc.session, tc.bound, tc.root, tc.failed); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// R1 stays: a result that joins no call the leader knows is still marked.
func TestGAP0348UnjoinedResultIsStillMarked(t *testing.T) {
	for _, row := range []struct {
		name  string
		steps []gap0348Step
	}{
		{"no-call", []gap0348Step{a348(gap0348Fail(gap0348Missing))}},
		{"another-call-id", []gap0348Step{a348(gap0348Pre()), a348(gap0342Fail("s1", "read-2", gap0348Read, gap0348Missing))}},
		{"another-session", []gap0348Step{a348(gap0348Pre()), a348(gap0348Fail(gap0348Missing)),
			a348(gap0342Fail("s2", "read-1", gap0348Read, gap0348Missing))}},
	} {
		t.Run(row.name, func(t *testing.T) {
			hooks, _, v := gap0348Run(t, row.steps)
			if last := hooks[len(hooks)-1]; !slices.Contains(last.RuleIDs, substrateChainUnrecordedRule) || v.Unrecorded == "" {
				t.Fatalf("last hook %q %v, callout %+v: want the unjoined result marked unrecorded", last.Action, last.RuleIDs, v)
			}
		})
	}
}

// Cursor posts postToolUseFailure and then postToolUse for a failed shell
// call, as Claude Code does.
func TestGAP0348CursorSecondResult(t *testing.T) {
	const read = "cat .env"
	missing := "cat: .env: No such file or directory"
	for _, row := range []struct {
		name, second string
		refuse       bool
	}{{"benign", missing, false}, {"printed", "API_KEY=canary-1", true}} {
		t.Run(row.name, func(t *testing.T) {
			r, chains, contract := chainStartReplica(t, "cursor", "default", false)
			pre, fail, send := chainStartEvents("cursor", "s1", "c1", read, chainStartRow{id: "fail", read: read, text: missing})
			_, second, _ := chainStartEvents("cursor", "s1", "c1", read, chainStartRow{id: "second", read: read, ok: true, text: row.second})
			var hooks []agentHookResponse
			for _, ev := range []map[string]interface{}{pre, fail, second} {
				h, _ := chainStartHook(t, r, "cursor", contract, ev)
				hooks = append(hooks, h)
			}
			got, _ := chainStartHook(t, r, "cursor", contract, send)
			v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
				Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
			})
			if err != nil {
				t.Fatal(err)
			}
			for i, h := range hooks {
				if slices.Contains(h.RuleIDs, substrateChainUnrecordedRule) {
					t.Fatalf("step %d: %q %v, want no unrecorded mark", i, h.Action, h.RuleIDs)
				}
			}
			chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress)
			if v.Deny != row.refuse || chain != row.refuse || v.Unrecorded != "" {
				t.Fatalf("upload %q %v, callout %+v: want refused=%v by the chain, no unrecorded mark", got.Action, got.RuleIDs, v, row.refuse)
			}
		})
	}
}

// substrate-1 GAP-0352 (SMK-CH3 on stk at 2712b0be1b, 10 of 10 cells): after
// the PostToolUseFailure of a missing .env.production, Claude Code's
// PostToolUse for the same call carried no output; the replay took it for a
// result that may have read and started the chain, so the upload was blocked.
// The first result is the real Claude Code 2.1.322 body (captured on dev,
// evidence/substrate-1/kind347/ccprobe). A further result of a call whose
// read was proven to fail chains only if its own content shows a read.
func gap0352RealFailure() map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PostToolUseFailure", "session_id": "s1", "permission_mode": "bypassPermissions",
		"prompt_id": "8292d70b-0139-47c7-8641-286496fcc90f", "tool_name": "Bash", "tool_use_id": "read-1",
		"tool_input": map[string]interface{}{"command": gap0348Read, "description": "Read .env.production file"},
		"error":      "Exit code 1\n" + gap0348Missing, "is_interrupt": false, "duration_ms": float64(41),
	}
}

func gap0352Post(response interface{}, set bool) map[string]interface{} {
	post := claudeToolResult("PostToolUse", "s1", "read-1")
	post["tool_input"] = map[string]interface{}{"command": gap0348Read, "description": "Read .env.production file"}
	delete(post, "tool_response")
	if set {
		post["tool_response"] = response
	}
	return post
}

func TestGAP0352FurtherResultWithNoReadDoesNotChain(t *testing.T) {
	seconds := []struct {
		name string
		post map[string]interface{}
	}{
		{"empty-stdout-stderr", gap0352Post(map[string]interface{}{"stdout": "", "stderr": "", "interrupted": false, "isImage": false}, true)},
		{"no-tool-response", gap0352Post(nil, false)},
		{"empty-string", gap0352Post("", true)},
		{"repeats-the-failure", gap0352Post("Exit code 1\n"+gap0348Missing, true)},
	}
	orders := []struct {
		name   string
		layout func(fail, post map[string]interface{}) []gap0348Step
	}{
		{"same-replica", func(f, p map[string]interface{}) []gap0348Step {
			return []gap0348Step{a348(gap0348Pre()), a348(f), a348(p)}
		}},
		{"failure-on-B", func(f, p map[string]interface{}) []gap0348Step {
			return []gap0348Step{a348(gap0348Pre()), b348(f), a348(p)}
		}},
		{"posttooluse-on-B", func(f, p map[string]interface{}) []gap0348Step {
			return []gap0348Step{a348(gap0348Pre()), a348(f), b348(p)}
		}},
	}
	for _, o := range orders {
		for _, s := range seconds {
			t.Run(o.name+"/"+s.name, func(t *testing.T) {
				hooks, upload, v := gap0348Run(t, o.layout(gap0352RealFailure(), s.post))
				for i, h := range hooks {
					if slices.Contains(h.RuleIDs, substrateChainUnrecordedRule) {
						t.Fatalf("step %d: %q %v, want no unrecorded mark", i, h.Action, h.RuleIDs)
					}
				}
				if v.Deny || v.Unrecorded != "" || upload.Action == guardrailActionBlock ||
					slices.Contains(upload.RuleIDs, guardrail.ToolChainSecretReadThenEgress) {
					t.Fatalf("upload %q %v, callout %+v: want allowed, no chain, no unrecorded mark", upload.Action, upload.RuleIDs, v)
				}
			})
		}
	}
}

// The positives stay refused when the further result shows the read.
func TestGAP0352FurtherResultThatPrintedStillChains(t *testing.T) {
	for _, row := range []struct {
		name  string
		steps []gap0348Step
	}{
		{"real-failure-then-printed-string", []gap0348Step{a348(gap0348Pre()), a348(gap0352RealFailure()), a348(gap0352Post("API_KEY=canary-1", true))}},
		{"real-failure-on-B-then-printed-stdout", []gap0348Step{a348(gap0348Pre()), b348(gap0352RealFailure()),
			a348(gap0352Post(map[string]interface{}{"stdout": "API_KEY=canary-1", "stderr": "", "interrupted": false, "isImage": false}, true))}},
		{"real-failure-then-failure-that-printed", []gap0348Step{a348(gap0348Pre()), a348(gap0352RealFailure()),
			a348(gap0348Fail("API_KEY=canary-1\n" + gap0348Missing))}},
		{"printed-then-real-failure", []gap0348Step{a348(gap0348Pre()), a348(gap0348Post("read-1", "API_KEY=canary-1", "")), a348(gap0352RealFailure())}},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, upload, v := gap0348Run(t, row.steps)
			gap0342Refused(t, row.name, upload, v)
		})
	}
}
