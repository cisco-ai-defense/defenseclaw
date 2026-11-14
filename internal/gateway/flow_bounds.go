// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The bounds of the secret-flow lane's work on the hook path (rel-1-0-10 S7,
// shadow-safety review P3-2). The lane parses the call, extracts its effects
// and steps a per-session state while the hook waits, so it carries the same
// three guards as the effect lane's shadow run, expressed with
// internal/guardrail/bounded so the lane is promotion-ready under the bound
// rule:
//
//   - input size: a command or argument text past flowLaneMaxBytes, or past
//     the parser input bound (shellparse.TooDeep), is not read (bounded.Bytes,
//     bounded.Depth);
//   - deadline: the extraction stops at flowLaneTimeCap and a run that missed
//     it does not step the state (bounded.Time);
//   - concurrency: at most flowLaneMaxConcurrent runs in flight in a process;
//     the others are skipped and counted, never queued behind the hook.
//
// In shadow a skipped run records nothing and changes no verdict. In on a
// skipped run adds the bound finding (boundedTruncatedFinding), so a truncated
// input is never a silent allow. The lane ships shadow-only in 1.0.10.
const (
	// flowLaneMaxBytes bounds the command or argument text one run reads. It is
	// the effect lane's bound (effectShadowMaxCommandBytes): above the largest
	// real call, and the parse before the walk cannot be interrupted, so the
	// size is the bound on its time and allocation.
	flowLaneMaxBytes = effectShadowMaxCommandBytes
	// flowLaneMaxConcurrent bounds the runs in flight in a process.
	flowLaneMaxConcurrent = 8
)

// flowLaneTimeCap is the wall-clock cap of one run. It is a variable only so
// tests can narrow it; production never changes it.
var flowLaneTimeCap = 50 * time.Millisecond

var (
	flowLaneSlots   = make(chan struct{}, flowLaneMaxConcurrent)
	flowLaneDropped atomic.Int64
	// flowLaneCapHits counts the runs each cap cut short, by bounded.Cap.
	flowLaneCapHits [16]atomic.Int64
)

// flowLaneBound is one run's bound state. Keep one per run, never copied or
// shared (bounded.Truncated).
type flowLaneBound struct {
	trunc    bounded.Truncated
	deadline time.Time
}

// startFlowLaneBound takes a concurrency slot and starts the clock. It returns
// nil when every slot is in use: the run is skipped and counted.
func startFlowLaneBound() *flowLaneBound {
	select {
	case flowLaneSlots <- struct{}{}:
	default:
		flowLaneDropped.Add(1)
		return nil
	}
	return &flowLaneBound{deadline: time.Now().Add(flowLaneTimeCap)}
}

// admit reports whether a text of this call is within the input bounds and
// records the cap it is not.
func (b *flowLaneBound) admit(text string) bool {
	if !b.trunc.Within(bounded.Bytes, len(text), flowLaneMaxBytes) {
		return false
	}
	if text != "" && shellparse.TooDeep(text) {
		b.trunc.Hit(bounded.Depth)
		return false
	}
	return true
}

// alive reports whether the run is still within its deadline.
func (b *flowLaneBound) alive() bool { return b.trunc.Before(time.Now(), b.deadline) }

// finish releases the slot and counts the caps the run hit. It returns them.
func (b *flowLaneBound) finish() bounded.CapSet {
	<-flowLaneSlots
	set := b.trunc.Set()
	if set.Any() {
		for _, c := range bounded.Caps() {
			if set.Has(c) {
				flowLaneCapHits[c].Add(1)
			}
		}
	}
	return set
}

// flowLaneBoundStats is the explain view of the bounds: the runs skipped for
// the concurrency cap and, per cap, the runs a bound cut short.
func flowLaneBoundStats() map[string]interface{} {
	caps := map[string]int64{}
	for _, c := range bounded.Caps() {
		if n := flowLaneCapHits[c].Load(); n > 0 {
			caps[c.String()] = n
		}
	}
	return map[string]interface{}{"slot_drops": flowLaneDropped.Load(), "cap_hits": caps}
}
