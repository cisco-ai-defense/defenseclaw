// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
)

// substrateMCPHiddenReadings are the rules readings of a bridged call's
// hidden actions (substrateMCPArgumentScan.candidates, Rule H). Each one is
// a complete one-key reading of its own, judged by the rules alone and
// independent of every other reading of the call, so they run at once,
// beside the call's full reading, on at most substrateMCPHiddenWorkers
// goroutines, and substrateMCPBoundedVerdict folds them in scan order after
// it, stopping at the first deny, exactly as the one-by-one loop did. A
// call with N hidden actions still pays N readings of CPU; its latency is
// the slowest reading rather than their sum (substrate-1:GAP-1157). Every
// candidate is read: none is skipped, capped or marked unknown.
type substrateMCPHiddenReadings struct {
	candidates []json.RawMessage
	verdicts   []SubstrateCalloutVerdict
	done       chan struct{}
	cancel     context.CancelFunc
}

// substrateMCPHiddenWorkers is the most goroutines one call's hidden
// readings use: the free-candidate count, and no more than the CPUs.
func substrateMCPHiddenWorkers(n int) int {
	return max(1, min(n, substrateMCPFreeCandidates, runtime.GOMAXPROCS(0)))
}

// startSubstrateMCPHiddenReadings starts the readings of the candidates of
// rd that no earlier reading of the call judged (rd.judged), and marks them
// judged. Nil when there are none.
func startSubstrateMCPHiddenReadings(ctx context.Context, rd substrateMCPReading,
	judge func(context.Context, json.RawMessage) SubstrateCalloutVerdict) *substrateMCPHiddenReadings {
	if rd.scan == nil || len(rd.scan.candidates) == 0 {
		return nil
	}
	var candidates []json.RawMessage
	for _, c := range rd.scan.candidates {
		if rd.judged != nil {
			if rd.judged[string(c)] {
				continue
			}
			rd.judged[string(c)] = true
		}
		candidates = append(candidates, c)
	}
	if len(candidates) == 0 {
		return nil
	}
	hctx, cancel := context.WithCancel(ctx)
	h := &substrateMCPHiddenReadings{candidates: candidates, verdicts: make([]SubstrateCalloutVerdict, len(candidates)),
		done: make(chan struct{}), cancel: cancel}
	var next atomic.Int64
	var wg sync.WaitGroup
	for range substrateMCPHiddenWorkers(len(candidates)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(candidates) {
					return
				}
				h.verdicts[i] = substrateMCPHiddenReading(hctx, judge, candidates[i])
			}
		}()
	}
	go func() {
		wg.Wait()
		close(h.done)
	}()
	return h
}

// substrateMCPHiddenReading is one hidden action's verdict. A reading that
// panics is the evaluation-fault deny, as a fault in the hook path's
// readings is (evaluationFaultFindings): never an allow, never a crash of
// the gateway.
func substrateMCPHiddenReading(ctx context.Context, judge func(context.Context, json.RawMessage) SubstrateCalloutVerdict,
	candidate json.RawMessage) (v SubstrateCalloutVerdict) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logEvaluatorFault("substrate mcp hidden action reading", recovered)
			v = SubstrateCalloutVerdict{V: "1", Verdict: "deny", Source: "tool_rules", Severity: "HIGH",
				Reason: evaluatorFaultTitle, Findings: []string{parseFailureRuleID}}
		}
	}()
	return judge(ctx, candidate)
}

// wait returns the verdicts in candidate order once every reading is done.
func (h *substrateMCPHiddenReadings) wait() []SubstrateCalloutVerdict {
	if h == nil {
		return nil
	}
	<-h.done
	return h.verdicts
}

// stop ends readings the call no longer needs (an earlier deny) and waits
// for them, so none outlives the call.
func (h *substrateMCPHiddenReadings) stop() {
	if h == nil {
		return
	}
	h.cancel()
	<-h.done
}
