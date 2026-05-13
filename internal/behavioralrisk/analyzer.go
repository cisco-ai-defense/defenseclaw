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

// Package behavioralrisk implements lightweight in-memory risk scoring for
// runtime agent activity. It adapts AIMS' multi-window analyzer to DefenseClaw
// without requiring Redis or a long-lived baseline service for the first PR.
package behavioralrisk

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

var windows = []time.Duration{time.Second, time.Minute, 10 * time.Minute, time.Hour, 24 * time.Hour}

var windowWeights = map[time.Duration]float64{
	time.Second:      0.30,
	time.Minute:      0.25,
	10 * time.Minute: 0.20,
	time.Hour:        0.15,
	24 * time.Hour:   0.10,
}

const (
	DefaultBaselineRPM = 60.0
	AlertMultiplier    = 3.0
	SuspendMultiplier  = 10.0
)

// Event is one runtime action to score.
type Event struct {
	AgentID    string
	TaskID     string
	ResourceID string
	Domain     string
	Operation  string
	Timestamp  time.Time
}

// BaselineStore provides per-agent p99 requests-per-minute baselines.
type BaselineStore interface {
	P99RPM(ctx context.Context, agentID string) (float64, error)
}

// StaticBaseline is a fixed baseline store used for local demos and tests.
type StaticBaseline struct {
	DefaultRPM float64
	ByAgent    map[string]float64
}

func (s StaticBaseline) P99RPM(_ context.Context, agentID string) (float64, error) {
	if s.ByAgent != nil {
		if v := s.ByAgent[agentID]; v > 0 {
			return v, nil
		}
	}
	if s.DefaultRPM > 0 {
		return s.DefaultRPM, nil
	}
	return DefaultBaselineRPM, nil
}

// Result is returned after every Analyze call.
type Result struct {
	Score         int
	ShouldAlert   bool
	ShouldSuspend bool
	Reason        string
	AgentID       string
	TaskID        string
	ResourceID    string
}

type counter struct {
	duration time.Duration
	events   []time.Time
}

func (c *counter) add(now time.Time) {
	c.events = append(c.events, now)
	c.prune(now)
}

func (c *counter) count(now time.Time) int {
	c.prune(now)
	return len(c.events)
}

func (c *counter) prune(now time.Time) {
	cutoff := now.Add(-c.duration)
	idx := 0
	for idx < len(c.events) && c.events[idx].Before(cutoff) {
		idx++
	}
	c.events = c.events[idx:]
}

type agentState struct {
	counters map[time.Duration]*counter
	domains  map[string]struct{}
	fsaState string
}

func newAgentState() *agentState {
	counters := make(map[time.Duration]*counter, len(windows))
	for _, w := range windows {
		counters[w] = &counter{duration: w}
	}
	return &agentState{counters: counters, domains: map[string]struct{}{}, fsaState: "idle"}
}

// Analyzer tracks risk state in memory. It is safe for concurrent use.
type Analyzer struct {
	mu        sync.Mutex
	states    map[string]*agentState
	baselines BaselineStore
}

func NewAnalyzer(baselines BaselineStore) *Analyzer {
	if baselines == nil {
		baselines = StaticBaseline{DefaultRPM: DefaultBaselineRPM}
	}
	return &Analyzer{states: map[string]*agentState{}, baselines: baselines}
}

// Analyze records an event and returns a 0-100 risk score.
func (a *Analyzer) Analyze(ctx context.Context, event Event) Result {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if strings.TrimSpace(event.AgentID) == "" {
		event.AgentID = "unknown-agent"
	}
	key := event.AgentID + "\x00" + event.TaskID
	a.mu.Lock()
	state := a.states[key]
	if state == nil {
		state = newAgentState()
		a.states[key] = state
	}
	for _, w := range windows {
		state.counters[w].add(event.Timestamp)
	}
	if event.Domain != "" && event.Domain != "public" {
		state.domains[event.Domain] = struct{}{}
	}
	fsa := updateFSA(state, event)
	crossDomainCount := len(state.domains)
	score := a.computeScoreLocked(ctx, state, event)
	a.mu.Unlock()

	if fsa {
		score = min(score+20, 100)
	}
	if crossDomainCount >= 3 {
		score = min(score+25, 100)
	}

	result := Result{Score: score, AgentID: event.AgentID, TaskID: event.TaskID, ResourceID: event.ResourceID}
	alertThreshold := int((AlertMultiplier / SuspendMultiplier) * 100)
	result.ShouldAlert = score >= alertThreshold
	result.ShouldSuspend = score >= 100
	if result.ShouldSuspend {
		result.Reason = fmt.Sprintf("behavioral risk score %d reached suspension threshold for agent %s", score, event.AgentID)
	} else if result.ShouldAlert {
		result.Reason = fmt.Sprintf("behavioral risk score %d reached alert threshold for agent %s", score, event.AgentID)
	}
	return result
}

func (a *Analyzer) computeScoreLocked(ctx context.Context, state *agentState, event Event) int {
	p99, err := a.baselines.P99RPM(ctx, event.AgentID)
	if err != nil || p99 <= 0 {
		p99 = DefaultBaselineRPM
	}
	var weighted float64
	for _, w := range windows {
		count := float64(state.counters[w].count(event.Timestamp))
		minutes := w.Minutes()
		if minutes <= 0 {
			minutes = float64(w) / float64(time.Minute)
		}
		rpm := count / minutes
		var sub float64
		if rpm >= p99*SuspendMultiplier {
			sub = 100
		} else if rpm > p99*AlertMultiplier {
			sub = 30 + ((rpm - p99*AlertMultiplier) / (p99*SuspendMultiplier - p99*AlertMultiplier) * 70)
		} else if rpm > p99 {
			sub = (rpm - p99) / (p99*AlertMultiplier - p99) * 30
		}
		weighted += windowWeights[w] * sub
	}
	return min(int(weighted), 100)
}

var fsaTransitions = map[string]map[string]string{
	"idle":          {"DESCRIBE": "schema_probed", "SELECT_BULK": "bulk_reading"},
	"schema_probed": {"DESCRIBE": "schema_probed", "SELECT_BULK": "bulk_reading"},
	"bulk_reading":  {"SELECT_BULK": "bulk_reading", "POST_EXT": "exfil_attempted"},
}

func updateFSA(state *agentState, event Event) bool {
	action := classify(event)
	if next, ok := fsaTransitions[state.fsaState][action]; ok {
		state.fsaState = next
	}
	if state.fsaState == "exfil_attempted" {
		state.fsaState = "idle"
		return true
	}
	return false
}

func classify(event Event) string {
	op := strings.ToUpper(strings.TrimSpace(event.Operation + " " + event.ResourceID))
	switch {
	case strings.Contains(op, "DESCRIBE"), strings.Contains(op, "INFORMATION_SCHEMA"), strings.Contains(op, "SHOW TABLES"):
		return "DESCRIBE"
	case strings.Contains(op, "SELECT *"), strings.Contains(op, "SELECT_BULK"), strings.Contains(op, "BULK"):
		return "SELECT_BULK"
	case strings.Contains(op, "POST_EXT"), strings.Contains(op, "EXTERNAL POST"), strings.Contains(op, "HTTP POST"):
		return "POST_EXT"
	default:
		return "OTHER"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
