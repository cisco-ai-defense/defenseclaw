// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"time"
)

// judgeHealthWindow is how many recent LLM judge calls the health snapshot
// summarizes.
const judgeHealthWindow = 20

// judgeHealthTracker keeps the outcome of the recent LLM judge calls so the
// health snapshot can show a failing judge. A judge whose provider rejected
// every call was invisible outside the audit rows: the hook lane kept the rule
// verdicts and logged "hook judge unavailable" (GAP-1120, GAP-1288).
type judgeHealthTracker struct {
	mu          sync.Mutex
	outcomes    [judgeHealthWindow]bool // true = failed
	count, next int
	lastError   string
	lastFailure time.Time
}

var judgeHealth judgeHealthTracker

func (t *judgeHealthTracker) record(failed bool, summary string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outcomes[t.next] = failed
	t.next = (t.next + 1) % judgeHealthWindow
	if t.count < judgeHealthWindow {
		t.count++
	}
	if failed {
		t.lastError = boundedJudgeHealthValue(summary, 240)
		t.lastFailure = now
	}
}

func (t *judgeHealthTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outcomes = [judgeHealthWindow]bool{}
	t.count, t.next = 0, 0
	t.lastError, t.lastFailure = "", time.Time{}
}

// details returns the judge_* health details, or nil before the first call.
func (t *judgeHealthTracker) details() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count == 0 {
		return nil
	}
	failed := 0
	for i := 0; i < t.count; i++ {
		if t.outcomes[i] {
			failed++
		}
	}
	state := "ok"
	switch {
	case failed == t.count:
		state = "failing"
	case failed > 0:
		state = "degraded"
	}
	details := map[string]interface{}{
		"judge_state":        state,
		"judge_recent_calls": t.count,
		"judge_failed_calls": failed,
	}
	if failed > 0 {
		details["judge_last_error"] = t.lastError
		details["judge_last_failure_at"] = t.lastFailure.UTC().Format(time.RFC3339)
	}
	return details
}

// withJudgeHealth returns h with the judge_* details merged into a copy of
// its details map.
func withJudgeHealth(h SubsystemHealth) SubsystemHealth {
	judge := judgeHealth.details()
	if judge == nil {
		return h
	}
	merged := make(map[string]interface{}, len(h.Details)+len(judge))
	for k, v := range h.Details {
		merged[k] = v
	}
	for k, v := range judge {
		merged[k] = v
	}
	h.Details = merged
	return h
}
