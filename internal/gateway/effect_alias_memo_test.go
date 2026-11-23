// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func aliasMemoFixture(path string) (effects.Result, []*semanticpb.EffectFact) {
	source := effects.Effect{
		Kind: effects.KindLink, LinkTarget: true, TargetState: effects.TargetStateKnown,
		RoleState: effects.RoleStateKnown, Target: effects.Target{Type: effects.TargetPath,
			Path: "/home/u/.ssh/id_rsa", Flavor: effects.FlavorPOSIX},
		Origin: effects.Origin{Command: 1},
	}
	at := effects.Effect{Kind: effects.KindLink, Target: effects.Target{
		Type: effects.TargetPath, Path: path, Flavor: effects.FlavorPOSIX},
		Origin: effects.Origin{Command: 1}}
	fact := &semanticpb.EffectFact{TargetState: "known", RoleState: "known",
		Target: &semanticpb.EffectTarget{Path: source.Target.Path, Protected: []*semanticpb.ProtectedMatch{
			{Set: effectrules.SetCredentials, State: "known", Reason: "exact"},
		}}}
	return effects.Result{Effects: []effects.Effect{source, at}}, []*semanticpb.EffectFact{fact, {}}
}

func TestEffectAliasMemoBoundsAndConcurrency(t *testing.T) {
	var memo effectAliasMemo
	request := shadowLiveRequest("")
	result, facts := aliasMemoFixture("/home/u/work/alias")
	for i := 0; i < effectAliasSessionLimit+8; i++ {
		request.sessionID = fmt.Sprintf("bounded-%d", i)
		memo.remember(request, result, facts, effects.FlavorPOSIX)
	}
	if len(memo.sessions) > effectAliasSessionLimit {
		t.Fatalf("sessions %d exceeds %d", len(memo.sessions), effectAliasSessionLimit)
	}
	before := len(memo.sessions)
	request.sessionID = strings.Repeat("x", effectAliasMaxSessionBytes+1)
	memo.remember(request, result, facts, effects.FlavorPOSIX)
	if len(memo.sessions) != before {
		t.Fatal("oversized session key entered the memo")
	}
	request.sessionID = "alias-count"
	for i := 0; i < effectAliasPerSessionLimit+8; i++ {
		r, f := aliasMemoFixture(fmt.Sprintf("/home/u/work/alias-%d", i))
		memo.remember(request, r, f, effects.FlavorPOSIX)
	}
	key, _ := aliasKey(request)
	if got := len(memo.sessions[key].aliases); got != effectAliasPerSessionLimit {
		t.Fatalf("aliases %d, want %d", got, effectAliasPerSessionLimit)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				memo.remember(request, result, facts, effects.FlavorPOSIX)
				memo.uses(request, effects.Result{Effects: []effects.Effect{{
					Kind: effects.KindRead, Target: effects.Target{Path: "/home/u/work/alias"},
				}}})
			}
		}()
	}
	wg.Wait()
	// Expiration is per alias, even when a newer alias keeps the session live.
	memo.mu.Lock()
	old := memo.sessions[key].aliases["/home/u/work/alias"]
	old.at = time.Now().Add(-effectAliasTTL - time.Second)
	memo.sessions[key].aliases["/home/u/work/alias"] = old
	memo.mu.Unlock()
	read := effects.Result{Effects: []effects.Effect{{Kind: effects.KindRead,
		TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
		Target: effects.Target{Path: "/home/u/work/alias"}}}}
	if got := memo.uses(request, read); len(got) != 0 {
		t.Fatalf("expired alias produced a proof: %+v", got)
	}
}

func TestEffectAliasMemoRelinkAndDeleteInvalidate(t *testing.T) {
	var memo effectAliasMemo
	request := shadowLiveRequest("")
	request.sessionID = "memo-invalidate"
	const path = "/home/u/work/alias"
	linked, facts := aliasMemoFixture(path)
	read := effects.Result{Effects: []effects.Effect{{Kind: effects.KindRead,
		TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
		Target: effects.Target{Path: path}}}}
	memo.remember(request, linked, facts, effects.FlavorPOSIX)
	if got := memo.uses(request, read); len(got) != 1 {
		t.Fatalf("linked credential read proofs = %+v, want one", got)
	}
	ordinary, ordinaryFacts := aliasMemoFixture(path)
	ordinaryFacts[0].Target.Protected = nil
	memo.remember(request, ordinary, ordinaryFacts, effects.FlavorPOSIX)
	if got := memo.uses(request, read); len(got) != 0 {
		t.Fatalf("relinked alias retained credential proof: %+v", got)
	}
	memo.remember(request, linked, facts, effects.FlavorPOSIX)
	memo.remember(request, effects.Result{Effects: []effects.Effect{{Kind: effects.KindDelete,
		Target: effects.Target{Path: path}}}}, nil, effects.FlavorPOSIX)
	if got := memo.uses(request, read); len(got) != 0 {
		t.Fatalf("deleted alias retained credential proof: %+v", got)
	}
}
