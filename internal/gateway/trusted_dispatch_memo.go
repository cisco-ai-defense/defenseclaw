package gateway

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// trustedDispatchMemo judges each distinct request of one hook call once
// (rel-1-0-10:GAP-1472). The readings of a call ask for the same twin or
// simple-command pass again and again: sudo tee F <<< WORD dispatched 32
// requests, only 14 of them distinct, and each repeat ran every reader a
// second time. A repeat of a request the memo holds is answered with the
// first run's findings, after it replays what that run told the request (the
// out-parameters below) and charges the budget the run charged.
//
// A repeat is answered from the memo only when a run of it would give the
// same answer:
//   - the request is the same in every field (reflect.DeepEqual; a Substrate
//     actor's home places are compared as the set they point at), the shared
//     state it points at is the same object (pointer identity: ctx, budget,
//     cap floor, rule generation, readings), it records into no function
//     (record, recordTelemetry, recordEffectShadow) and asks for no
//     out-parameter the memo does not replay (guestWriteClaimOnly);
//   - the first run left the hook call's own budgets and causes as it found
//     them (hookpaths.HookCallState, the cap floor, the reach of the budget,
//     the shared evaluations, the session's page), and the repeat finds
//     them in that state;
//   - the budget has room for the cost again without reaching its bound, so
//     no rule of the repeat would have been refused for the budget.
//
// The memo lives in the context of the outermost dispatch, so it never
// outlives the hook call; there is no cache across calls.
type trustedDispatchMemo struct {
	mu      sync.Mutex
	entries map[string][]*trustedDispatchMemoEntry
}

type trustedDispatchMemoEntry struct {
	ctx      context.Context
	key      trustedActionRequest // pointer fields cleared (trustedDispatchMemoKey)
	refs     trustedDispatchMemoRefs
	state    trustedDispatchState // before and after the first run
	cost     uint64               // budget the first run charged
	outs     trustedDispatchOuts
	findings []RuleFinding
}

// trustedDispatchMemoRefs is the shared state of a request, compared by
// identity: two requests with the same refs read and write the same objects.
type trustedDispatchMemoRefs struct {
	budget            *trustedActionBudget
	capFloor          *capFloorState
	generation        *compiledRulePackCategories
	targetMemo        *hookpaths.TargetMemo
	windowsTwinHosts  *windowsTwinHostReadings
	windowsPowerShell *windowsHintedReading
	// tiers is the pack tier table the tier gates read (one table per pack
	// directory, packTable), compared by identity.
	tiers *decide.Table
	// outs records which out-parameters are asked for (non-nil): a nil one
	// may change what the readers do.
	outs [6]bool
}

// trustedDispatchOuts is what a run told the request's out-parameters.
type trustedDispatchOuts struct {
	overBudgetOmission, unresolvedTarget, resolvedTarget, nonWriteMention bool
	// unknownMention is the GAP-0843 out-parameter: like nonWriteMention, the
	// readers only test it for nil and set it to true, never read it.
	unknownMention bool
	unprovenTarget unprovenWrite
	unprovenSet    bool
}

// trustedDispatchState is the hook-call state a run may spend or set.
type trustedDispatchState struct {
	consumed     uint64
	reached      bool
	evals        int
	floorTwins   int
	floorStopped bounded.CapSet
	call         hookpaths.CallState
	// page is the session's page (pageOrigins), which a navigation call
	// sets and a page script reads.
	page string
}

// same reports whether the state other leaves a run judged as in s.
func (s trustedDispatchState) same(other trustedDispatchState) bool {
	return s.reached == other.reached && s.evals == other.evals &&
		s.floorTwins == other.floorTwins && s.floorStopped == other.floorStopped &&
		s.call == other.call && s.page == other.page
}

// trustedDispatchMemoOff turns the memo off, so a test can compare a call's
// answer with and without it (TestTrustedDispatchMemoSameAnswer). Production
// never sets it.
var trustedDispatchMemoOff atomic.Bool

type trustedDispatchMemoKey struct{}

func trustedDispatchMemoFrom(ctx context.Context) *trustedDispatchMemo {
	if ctx == nil {
		return nil
	}
	memo, _ := ctx.Value(trustedDispatchMemoKey{}).(*trustedDispatchMemo)
	return memo
}

// dispatchTrustedAction judges request (dispatchTrustedActionOnce). The
// outermost dispatch of a call begins its memo; the dispatches inside it,
// its twins and simple-command passes, are judged through the memo. The
// findings of a reading 1.0.10 did not have are marked as such
// (withFloorRaiseOnlyMark).
func dispatchTrustedAction(parent context.Context, request trustedActionRequest) []RuleFinding {
	return withFloorRaiseOnlyMark(request, dispatchTrustedActionMemo(parent, request), 0)
}

func dispatchTrustedActionMemo(parent context.Context, request trustedActionRequest) []RuleFinding {
	if trustedDispatchMemoOff.Load() {
		return dispatchTrustedActionOnce(parent, request)
	}
	memo := trustedDispatchMemoFrom(parent)
	if memo == nil {
		if parent == nil {
			parent = context.Background()
		}
		memo = &trustedDispatchMemo{}
		trustedDispatchRun(request)
		return dispatchTrustedActionOnce(context.WithValue(parent, trustedDispatchMemoKey{}, memo), request)
	}
	return memo.dispatch(parent, request)
}

// trustedDispatchRunHook is a test-only seam: when non-nil it is told each
// request the dispatch judges with the memo on (a repeat the memo answers is
// not judged), so a test can count the dispatches one hook call costs
// (rel-1-0-10:GAP-1593). Unlike trustedActionFaultHook it leaves the memo on.
// Production never sets it.
var trustedDispatchRunHook func(trustedActionRequest)

func trustedDispatchRun(request trustedActionRequest) {
	if trustedDispatchRunHook != nil {
		trustedDispatchRunHook(request)
	}
}

func (memo *trustedDispatchMemo) dispatch(ctx context.Context, request trustedActionRequest) []RuleFinding {
	if request.record != nil || request.recordTelemetry != nil || request.recordEffectShadow != nil ||
		request.aliasPending != nil || request.guestWriteClaimOnly != nil ||
		trustedActionFaultHook != nil || trustedSimpleCommandsFaultHook != nil {
		trustedDispatchRun(request)
		return dispatchTrustedActionOnce(ctx, request)
	}
	bucket := request.Input.Tool + "\x00" + request.Input.Command + "\x00" + request.LegacyText
	key, refs := trustedDispatchMemoKeyOf(request)
	// The goroutine's hook call is found once: the dispatch below runs in it
	// (or begins and ends its own when none is open), so before and after
	// read the same call (hookpaths.Call). A request of a dispatch on this
	// goroutine carries the call that dispatch found (hookCall), which is
	// not found again; the dispatch below joins it.
	call := hookpaths.FoundHookCall(request.hookCall)
	before := trustedDispatchStateOf(call, request)
	if hit := memo.lookup(ctx, bucket, key, refs, before); hit != nil {
		if request.budget != nil {
			request.budget.consumed += hit.cost
		}
		hit.outs.replay(request)
		return cloneRuleFindings(hit.findings)
	}
	run := request
	var outs trustedDispatchOuts
	run.overBudgetOmission = freshOut(request.overBudgetOmission, &outs.overBudgetOmission)
	run.unresolvedTarget = freshOut(request.unresolvedTarget, &outs.unresolvedTarget)
	run.resolvedTarget = freshOut(request.resolvedTarget, &outs.resolvedTarget)
	run.nonWriteMention = freshOut(request.nonWriteMention, &outs.nonWriteMention)
	run.unknownMention = freshOut(request.unknownMention, &outs.unknownMention)
	if request.unprovenTarget != nil {
		run.unprovenTarget = &outs.unprovenTarget
	}
	trustedDispatchRun(request)
	findings := dispatchTrustedActionOnceIn(ctx, run, call)
	outs.unprovenSet = outs.unprovenTarget != unprovenWrite{}
	outs.replay(request)
	after := trustedDispatchStateOf(call, request)
	if ctx.Err() == nil && !before.reached && before.same(after) && after.consumed >= before.consumed {
		memo.store(bucket, &trustedDispatchMemoEntry{
			ctx: ctx, key: key, refs: refs, state: before,
			cost: after.consumed - before.consumed, outs: outs, findings: cloneRuleFindings(findings),
		})
	}
	return findings
}

func (memo *trustedDispatchMemo) lookup(ctx context.Context, bucket string, key trustedActionRequest, refs trustedDispatchMemoRefs, now trustedDispatchState) *trustedDispatchMemoEntry {
	if ctx.Err() != nil || now.reached {
		return nil
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	for _, entry := range memo.entries[bucket] {
		if entry.ctx != ctx || entry.refs != refs || !entry.state.same(now) {
			continue
		}
		// Room for the cost again, short of the bound: no rule of a run
		// now would be refused for the budget (trustedActionBudget.eval).
		if refs.budget != nil && now.consumed+entry.cost >= trustedActionDispatchMaxCost {
			continue
		}
		if reflect.DeepEqual(entry.key, key) {
			return entry
		}
	}
	return nil
}

func (memo *trustedDispatchMemo) store(bucket string, entry *trustedDispatchMemoEntry) {
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if memo.entries == nil {
		memo.entries = make(map[string][]*trustedDispatchMemoEntry)
	}
	memo.entries[bucket] = append(memo.entries[bucket], entry)
}

// trustedDispatchMemoKeyOf splits request into the value compared by
// reflect.DeepEqual and the shared state compared by identity. The caches a
// run fills for its own input (simpleMemo) are left out: a pure function of
// the input, they never change an answer.
func trustedDispatchMemoKeyOf(request trustedActionRequest) (trustedActionRequest, trustedDispatchMemoRefs) {
	refs := trustedDispatchMemoRefs{
		budget: request.budget, capFloor: request.capFloor, generation: request.generation,
		targetMemo: request.targetMemo, windowsTwinHosts: request.windowsTwinHosts,
		windowsPowerShell: request.windowsPowerShellReading, tiers: request.Tiers,
		outs: [6]bool{
			request.overBudgetOmission != nil, request.unresolvedTarget != nil, request.resolvedTarget != nil,
			request.nonWriteMention != nil, request.unprovenTarget != nil, request.unknownMention != nil,
		},
	}
	key := request
	key.budget, key.capFloor, key.generation, key.targetMemo = nil, nil, nil, nil
	key.windowsTwinHosts, key.windowsPowerShellReading, key.simpleMemo, key.Tiers = nil, nil, nil, nil
	key.overBudgetOmission, key.unresolvedTarget, key.resolvedTarget, key.nonWriteMention = nil, nil, nil, nil
	key.unprovenTarget, key.unknownMention = nil, nil
	// The hook call is the goroutine's, the same for every request of the
	// call; it is how a run finds it, not what it judges.
	key.hookCall = hookpaths.Call{}
	return key, refs
}

func trustedDispatchStateOf(call hookpaths.Call, request trustedActionRequest) trustedDispatchState {
	state := trustedDispatchState{call: call.State()}
	if request.sessionID != "" {
		state.page = pageOrigins.get(pageOriginKey(request.Connector, request.sessionID))
	}
	if budget := request.budget; budget != nil {
		state.consumed, state.reached, state.evals = budget.consumed, budget.reached, len(budget.evals)
	}
	if floor := request.capFloor; floor != nil {
		state.floorTwins, state.floorStopped = floor.twins, floor.stopped
	}
	return state
}

func freshOut(asked *bool, local *bool) *bool {
	if asked == nil {
		return nil
	}
	return local
}

// replay tells request's out-parameters what the run told its own, as the
// run would have: a flag only turns on, and the unproven target keeps the
// first class written to it.
func (outs trustedDispatchOuts) replay(request trustedActionRequest) {
	for _, out := range []struct {
		to  *bool
		set bool
	}{
		{request.overBudgetOmission, outs.overBudgetOmission},
		{request.unresolvedTarget, outs.unresolvedTarget},
		{request.resolvedTarget, outs.resolvedTarget},
		{request.nonWriteMention, outs.nonWriteMention},
		{request.unknownMention, outs.unknownMention},
	} {
		if out.to != nil && out.set {
			*out.to = true
		}
	}
	if request.unprovenTarget != nil && outs.unprovenSet && request.unprovenTarget.class == "" {
		*request.unprovenTarget = outs.unprovenTarget
	}
}

// cloneRuleFindings copies findings, their tags included, so a caller that
// edits its answer (DeleteFunc, a member's profile) edits no other.
func cloneRuleFindings(findings []RuleFinding) []RuleFinding {
	if findings == nil {
		return nil
	}
	out := slices.Clone(findings)
	for i := range out {
		out[i].Tags = slices.Clone(out[i].Tags)
	}
	return out
}
