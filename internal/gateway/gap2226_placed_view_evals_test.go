// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

// gap2226PlacedViewCommands are copy-mode calls whose placed readings the
// semantic rules judge: the rd-hs-45-0 cost shape, a here-string fan, and
// calls whose placed readings block or alert (a key read, a hook-config
// write, an audit database removal, an authorized-keys append after $CMD),
// so kept results must give the same findings, allow and block alike.
func gap2226PlacedViewCommands() []string {
	lines := func(n int, format string) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, format, i)
		}
		return b.String()
	}
	ssh, key, keys := ".s"+"sh", "id_"+"ed25519", "authorized"+"_keys"
	return []string{
		"cd .cache\nbash <<< 'true'\n" + lines(45, "cd /tmp/rk4r%d && ls\n") + "ls",
		"cd .cache\nbash <<< 'true'\n" + lines(60, "touch f%d\n") + "ls",
		"cd .cache\nbash <<< 'true'\n" + lines(8, "cd /tmp/w%d && ls\n") + "cd ../" + ssh + " && cat " + key,
		"cd .cache\nbash <<< 'true'\n" + lines(8, "touch f%d\n") + "echo '{}' > ../.claude/settings.json",
		"cd .cache\nbash <<< 'true'\n" + lines(8, "ls d%d\n") + "rm ../.defenseclaw/audit.db",
		"cd .cache\n$CMD\n" + lines(7, "cd s%d\n") + "cd ../" + ssh + "\necho k >> " + keys,
		"cd project && bash <<< 'true'\ncat ../" + ssh + "/" + key + "\nls",
	}
}

// TestGAP2226PlacedViewEvalsKeepEveryFinding pins the placed readings' kept
// rule results (guestViewEvals) to fresh ones: a hook that judges the same
// placed readings again (a repeat, a twin, a call between) gets the same
// findings and spends the same budget as a hook with no memo, under each
// shipped pack (rel-1-0-10:GAP-2226, substrate-1 GAP-0502).
func TestGAP2226PlacedViewEvalsKeepEveryFinding(t *testing.T) {
	home := "/home/alice"
	generation := snapshotRulePackGeneration("")
	request := func(command string, memo *guestReadingMemo) trustedActionRequest {
		return trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, ActiveHome: home},
			LegacyText: command, Connector: "claudecode", EnforcementCapable: true,
			SkipLocalFilesystemResolution: true, SandboxGuestCWD: home,
			generation: generation, budget: newTrustedActionBudget(false), guestMemo: memo}
	}
	judge := func(command string, memo *guestReadingMemo) (string, uint64) {
		r := request(command, memo)
		findings := dispatchTrustedAction(t.Context(), r)
		return fmt.Sprintf("%+v", findings), r.budget.consumed
	}
	commands := gap2226PlacedViewCommands()
	judgedSome, kept := false, 0
	for at, command := range commands {
		want, wantCost := judge(command, nil)
		memo := &guestReadingMemo{}
		other := commands[(at+1)%len(commands)]
		for round, text := range []string{command, command, other, command, command + "\nls"} {
			got, cost := judge(text, memo)
			if text != command {
				continue
			}
			if got != want || cost != wantCost {
				t.Fatalf("call %d round %d: findings or cost differ with kept results:\n got %s (cost %d)\nwant %s (cost %d)", at, round, got, cost, want, wantCost)
			}
		}
		if strings.Contains(want, "RuleID:") {
			judgedSome = true
		}
		for _, entry := range memo.placed {
			for _, reading := range entry.readings {
				if len(reading.evals.first.results) != 0 {
					kept++
				}
			}
		}
	}
	if !judgedSome || kept == 0 {
		t.Fatalf("the calls gave no finding (%v) or kept no result (%d): the test reads nothing", judgedSome, kept)
	}
	t.Logf("%d calls, %d placed readings with kept results", len(commands), kept)
	// A budget that ends among the placed readings ends at the same rule:
	// a kept result is charged its cost as a fresh one is.
	full := map[string]string{}
	for _, command := range commands {
		full[command], _ = judge(command, nil)
	}
	saved := trustedActionDispatchMaxCost
	t.Cleanup(func() { trustedActionDispatchMaxCost = saved })
	cut, judged := 0, 0
	var limits []uint64
	for limit := 40.0; limit < 400_000; limit *= 1.2 {
		limits = append(limits, uint64(limit))
	}
	for _, limit := range limits {
		trustedActionDispatchMaxCost = limit
		for at, command := range commands {
			if at < 2 && limit%3 != 0 {
				continue // the two long cost shapes, at a third of the budgets
			}
			judged++
			want, _ := judge(command, nil)
			if want != full[command] {
				cut++
			}
			memo := &guestReadingMemo{}
			for round := range 3 {
				if got, _ := judge(command, memo); got != want {
					t.Fatalf("budget %d, call %d round %d: findings differ with kept results:\n got %s\nwant %s", limit, at, round, got, want)
				}
			}
		}
	}
	if cut == 0 {
		t.Fatal("no budget of the sweep changed a finding: the sweep reads nothing")
	}
	t.Logf("budget sweep: %d of %d judgments cut by the budget, identical with kept results", cut, judged)
}

// TestGAP2226PlacedViewEvalTableIsFresh pins each kept read of a
// guestViewEvalTable to the read it stands for, and a nil table to a fresh
// read every time.
func TestGAP2226PlacedViewEvalTableIsFresh(t *testing.T) {
	generation := snapshotRulePackGeneration("")
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: "rm -rf ../.defenseclaw", CWD: "/home/alice/.cache", ActiveHome: "/home/alice"})
	var evals guestViewEvals
	table := evals.lock(generation)
	evals.unlock()
	// A reading judged once keeps no projection: it would stay live for
	// the hook and never be read again.
	if _, code := table.project(&facts); table.projected || table.projection != nil {
		t.Fatalf("a first judgment kept its projection (code %v)", code)
	}
	if again := evals.lock(generation); again != table {
		t.Fatal("a second lock gives another table for the same generation")
	}
	evals.unlock()
	if projection, _ := table.project(&facts); !table.projected || table.projection != projection {
		t.Fatal("a second judgment did not keep its projection")
	}
	var none *guestViewEvalTable
	for range 2 {
		for _, view := range []*guestViewEvalTable{table, none} {
			projection, code := view.project(&facts)
			wantProjection, wantCode := semantic.Project(facts)
			if code != wantCode || !reflect.DeepEqual(fmt.Sprint(projection), fmt.Sprint(wantProjection)) {
				t.Fatal("a kept projection differs from a fresh one")
			}
			enforcement, _, _ := view.enforcementOf(&facts)
			if !reflect.DeepEqual(enforcement, facts.EnforcementProjection()) {
				t.Fatal("a kept enforcement projection differs from a fresh one")
			}
			for rule, candidate := range generation.semanticRules {
				if view.eligibleFor(rule, &candidate, &facts) != candidate.owner.eligible(facts) {
					t.Fatalf("rule %s: kept eligibility differs from a fresh one", candidate.rule.ID)
				}
			}
		}
	}
	none.keep(0, semantic.Result{Matched: true})
	if _, found := none.result(0); found {
		t.Fatal("a nil table keeps a result")
	}
	// A kept result is the fresh one and is charged the same cost.
	projection, _ := semantic.Project(facts)
	charged := 0
	for rule, candidate := range generation.semanticRules {
		fresh, kept := newTrustedActionBudget(false), newTrustedActionBudget(false)
		want, wantCode, wantOK := fresh.eval(t.Context(), candidate, 0, projection)
		slot := guestKeptSlot(rule, false)
		for round := range 2 {
			got, code, ok := kept.evalKept(t.Context(), candidate, 0, projection, table, slot)
			if got != want || code != wantCode || ok != wantOK || kept.consumed != fresh.consumed*uint64(round+1) {
				t.Fatalf("rule %s round %d: kept eval %+v %s %v cost %d, fresh %+v %s %v cost %d", candidate.rule.ID, round, got, code, ok, kept.consumed, want, wantCode, wantOK, fresh.consumed)
			}
		}
		if _, found := table.result(slot); wantCode == semantic.EvalOK && !found {
			t.Fatalf("rule %s: a complete result was not kept", candidate.rule.ID)
		}
		if fresh.consumed != 0 {
			charged++
		}
	}
	if charged == 0 {
		t.Fatal("no rule charged a cost: the check reads nothing")
	}
	// One slot per rule and projection, whatever order the results come
	// in; a table per generation.
	slots := map[int]bool{}
	for rule := range generation.semanticRules {
		for _, enforcement := range []bool{false, true} {
			slot := guestKeptSlot(rule, enforcement)
			if slots[slot] {
				t.Fatalf("rule %d enforcement %v: slot %d is another rule's or projection's", rule, enforcement, slot)
			}
			slots[slot] = true
		}
	}
	probe := &guestViewEvalTable{generation: generation}
	want := map[int]uint64{}
	for _, put := range []struct {
		rule        int
		enforcement bool
		cost        uint64
	}{{3, true, 7}, {5, false, 5}, {1, false, 3}, {3, false, 4}, {3, true, 9}, {0, true, 1}} {
		slot := guestKeptSlot(put.rule, put.enforcement)
		probe.keep(slot, semantic.Result{Cost: put.cost})
		want[slot] = put.cost
	}
	for slot := range 12 {
		got, found := probe.result(slot)
		if cost, kept := want[slot]; found != kept || got.Cost != cost {
			t.Fatalf("slot %d: kept %v cost %d, want %v cost %d", slot, found, got.Cost, kept, cost)
		}
	}
	if len(probe.results) != len(want) || !slices.IsSortedFunc(probe.results, func(a, b guestKeptEval) int { return a.slot - b.slot }) {
		t.Fatalf("kept results are not one per slot in slot order: %+v", probe.results)
	}
	other := &compiledRulePackCategories{}
	otherTable := evals.lock(other)
	evals.unlock()
	if otherTable == table || evals.lock(generation) != table {
		t.Fatal("two generations share a table")
	}
	evals.unlock()
	if evals.lock(other) != otherTable {
		t.Fatal("a second lock gives another table for the same second generation")
	}
	evals.unlock()
}
