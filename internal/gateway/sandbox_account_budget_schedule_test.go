// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// budgetSchedule is an open-loop stream of relayed hook calls from the
// sandboxes of one account: each of sandboxes sandboxes starts perSecond
// calls a second for duration, whether or not the calls before were answered.
// Every call is a proposal and, when it is answered, its delivery receipt.
// Each request stays open as long as the rendered hook (a proposal) and the
// gateway (a receipt) wait, the worst case for the open request bounds.
type budgetSchedule struct {
	sandboxes, perSecond int
	duration             time.Duration
}

// budgetOutcome is what a schedule produced: calls started, calls whose
// proposal and receipt were both admitted, and the refusals by who refused
// and why.
type budgetOutcome struct {
	calls, answered int
	// refused counts refused requests by "<binding|account> <reason>".
	refused map[string]int
	// firstRefused is the index, in start order, of the first refused call
	// (-1 when none was).
	firstRefused int
}

func (o budgetOutcome) refusedTotal() int {
	total := 0
	for _, n := range o.refused {
		total += n
	}
	return total
}

// runBudgetSchedule drives the real admission primitives of the managed
// sandbox ingress on a virtual clock: the sandboxauth.Limiter of the bindings
// (rate bucket and open request slots) and the hookCallerLimiter of the
// account (the class budgets, keyed as hookCallerAdmissionKey keys them), in
// the order api_sandbox_ingress.go and admitHookCaller call them. No call
// sleeps and no wall clock is read, so the result is the same on every run
// and in every build, race included.
func runBudgetSchedule(t *testing.T, s budgetSchedule) budgetOutcome {
	t.Helper()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	cfg := sandboxauth.DefaultLimiterConfig()
	cfg.Now = clock
	bindings := sandboxauth.NewLimiter(cfg)
	account := &hookCallerLimiter{now: clock}

	first, retry := connector.SandboxHookAttemptBudgets()
	answer, receiptOpen := max(first, retry), sandboxHookReceiptWindow

	const identity = "1000"
	admissionKey := func(receipt bool) string {
		r := httptest.NewRequest(http.MethodPost, sandboxrelay.PathHookPrefix+"claude-code", nil)
		if receipt {
			r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		return hookCallerAdmissionKey(identity, r)
	}
	pendingKey, receiptKey := admissionKey(false), admissionKey(true)
	if pendingKey != identity+"|"+sandboxBudgetPending || receiptKey != identity+"|"+sandboxBudgetReceipt {
		t.Fatalf("admission keys %q and %q are not the pending and receipt classes", pendingKey, receiptKey)
	}

	out := budgetOutcome{refused: map[string]int{}, firstRefused: -1}
	type event struct {
		at    time.Duration
		phase int // releases (0) run before a request that starts at the same instant
		seq   int
		run   func()
	}
	var events []event
	add := func(at time.Duration, phase int, run func()) {
		events = append(events, event{at: at, phase: phase, seq: len(events), run: run})
	}
	// refuse records one refused request: err is what a binding limiter
	// returned, reason what the account limiter answered.
	refuse := func(call int, who string, err error, reason string) {
		if err != nil {
			reason, _ = sandboxHookRefusal(err)
		}
		out.refused[who+" "+reason]++
		if out.firstRefused < 0 || call < out.firstRefused {
			out.firstRefused = call
		}
	}

	perSandbox := int(s.duration/time.Second) * s.perSecond
	started := 0
	for n := 0; n < perSandbox; n++ {
		for sb := 0; sb < s.sandboxes; sb++ {
			call := started
			at := time.Duration(n) * time.Second / time.Duration(s.perSecond)
			b := sandboxauth.Binding{ID: fmt.Sprintf("sb_%d", sb)}
			started++
			var releases []func()
			ok := true
			// A refused request ends at once and gives its slots back.
			releaseAll := func() {
				for _, release := range releases {
					release()
				}
				releases = nil
			}
			add(at, 1, func() {
				// The proposal: a slot of the binding, a slot of the account
				// and, once the body is read, the rate token of each.
				rel, err := bindings.AcquirePendingHook(b)
				if err != nil {
					refuse(call, "binding", err, "")
					ok = false
					return
				}
				releases = append(releases, rel)
				rel2, _, reason, _ := account.acquire(pendingKey)
				if reason != "" {
					refuse(call, "account", nil, reason)
					ok = false
					releaseAll()
					return
				}
				releases = append(releases, rel2)
				if err := bindings.ChargeHookBody(b, false); err != nil {
					refuse(call, "binding", err, "")
					ok = false
					releaseAll()
					return
				}
				if reason := account.chargeClass(identity + "|" + sandboxBudgetHook); reason != "" {
					refuse(call, "account", nil, reason)
					ok = false
					releaseAll()
				}
			})
			add(at+answer, 0, func() {
				releaseAll()
				if !ok {
					return
				}
				// The receipt of the answered proposal, a request of its own.
				rel, err := bindings.AcquireReceipt(b)
				if err != nil {
					refuse(call, "binding-receipt", err, "")
					ok = false
					return
				}
				rel2, _, reason, _ := account.acquire(receiptKey)
				if reason != "" {
					rel()
					refuse(call, "account-receipt", nil, reason)
					ok = false
					return
				}
				releases = append(releases, rel, rel2)
			})
			add(at+answer+receiptOpen, 0, func() {
				releaseAll()
				if ok {
					out.answered++
				}
			})
		}
	}
	out.calls = started
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		if events[i].phase != events[j].phase {
			return events[i].phase < events[j].phase
		}
		return events[i].seq < events[j].seq
	})
	start := now
	for _, e := range events {
		now = start.Add(e.at)
		e.run()
	}
	return out
}

// The streams of the managed sandbox lane (rel-1-0-6 GAP-0490) are admitted
// in full: one sandbox at 22 calls a second, two sandboxes of one account at
// 22 each (44 a second together, over the sustained 40 a second for a moment
// but inside the burst of 100 for these 10 s), and four at the documented
// account rate (4 x 10). Not one call may be refused, for its rate or for the
// open request bounds, while every request stays open as long as it may.
func TestSandboxAccountBudgetSchedule(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    budgetSchedule
	}{
		{"one sandbox at 22 a second", budgetSchedule{1, 22, 10 * time.Second}},
		{"two sandboxes at 22 a second", budgetSchedule{2, 22, 10 * time.Second}},
		{"four sandboxes at the account rate", budgetSchedule{4, sandboxUserHookRate / 4, 10 * time.Second}},
		{"four sandboxes at the account rate for a minute", budgetSchedule{4, sandboxUserHookRate / 4, time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runBudgetSchedule(t, tc.s)
			if out.refusedTotal() != 0 || out.answered != out.calls {
				t.Fatalf("%d of %d calls answered, refused %v", out.answered, out.calls, out.refused)
			}
		})
	}
}

// Past its budget an account is refused only for the excess: its burst plus
// its sustained rate are admitted, the refusals name the rate (not the open
// request bounds), and none comes before the burst is spent.
func TestSandboxAccountBudgetRefusesOnlyTheExcess(t *testing.T) {
	// Four sandboxes at 24 a second (96 together) for 10 s: the account
	// bucket holds a burst of 100 and refills 40 a second.
	out := runBudgetSchedule(t, budgetSchedule{4, 24, 10 * time.Second})
	accountRate := "account " + managedHookReasonRateLimited
	admitted := out.calls - out.refused[accountRate]
	if other := out.refusedTotal() - out.refused[accountRate]; other != 0 {
		t.Fatalf("refusals other than the account rate: %v", out.refused)
	}
	// The bucket admits the burst and the refill up to the last call (9.99 s).
	if low, high := sandboxUserHookBurst+sandboxUserHookRate*9, sandboxUserHookBurst+sandboxUserHookRate*10+1; admitted < low || admitted > high {
		t.Fatalf("%d of %d calls admitted, want %d to %d (burst %d, %d a second)", admitted, out.calls, low, high, sandboxUserHookBurst, sandboxUserHookRate)
	}
	if out.firstRefused < sandboxUserHookBurst {
		t.Fatalf("a call was refused at position %d, inside the burst of %d", out.firstRefused, sandboxUserHookBurst)
	}

	// One sandbox sustained above its own 25 a second (40 a second for 20 s,
	// inside the account budget) is refused by its binding for the excess
	// only: its burst of 100 plus 25 a second.
	out = runBudgetSchedule(t, budgetSchedule{1, 40, 20 * time.Second})
	if other := out.refusedTotal() - out.refused["binding "+sandboxReasonBindingRate]; other != 0 {
		t.Fatalf("refusals other than the binding rate: %v", out.refused)
	}
	admitted = out.calls - out.refusedTotal()
	if low, high := sandboxauth.DefaultHookBurst+sandboxauth.DefaultHookRPS*19, sandboxauth.DefaultHookBurst+sandboxauth.DefaultHookRPS*20+1; admitted < low || admitted > high {
		t.Fatalf("%d of %d calls admitted, want %d to %d (burst %d, %d a second)", admitted, out.calls, low, high, sandboxauth.DefaultHookBurst, sandboxauth.DefaultHookRPS)
	}
}
