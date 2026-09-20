// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package sensor

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// hostPlane consumes the kernel event stream, attributes each observation to
// the agent responsible for it, and accumulates per-agent sessions.
//
// The lineage gate lives here and nowhere else: an observation whose process
// has no AI agent above it is discarded before it can become a signal. That is
// the difference between this and a mediocre EDR, and it is also the primary
// false-positive control -- these tactics are far too ordinary on a developer
// machine to report without an actor attached.
type hostPlane struct {
	source     plane.Source
	tracker    *agentchain.Tracker
	indicators tactics.IndicatorSet
	window     time.Duration
	minStages  int

	mu       sync.Mutex
	sessions map[int]*agentchain.Session
	// gated counts observations discarded for having no agent above them. It
	// is the denominator that makes the lineage gate auditable rather than
	// invisible.
	gated int64
	// classified counts observations that became a tactic.
	classified int64
	running    bool
	coverage   plane.Coverage
}

func newHostPlane(
	source plane.Source, tracker *agentchain.Tracker,
	indicators tactics.IndicatorSet, window time.Duration, minStages int,
) *hostPlane {
	return &hostPlane{
		source: source, tracker: tracker, indicators: indicators,
		window: window, minStages: minStages,
		sessions: make(map[int]*agentchain.Session),
	}
}

// start begins consumption. A source that cannot start is reported to the
// caller rather than retried silently: the capability layer has already said
// the plane should work here, so a failure is a fact an operator needs.
func (h *hostPlane) start(ctx context.Context) error {
	if err := h.source.Start(ctx); err != nil {
		return err
	}
	h.mu.Lock()
	h.running = true
	h.coverage = h.source.Coverage()
	h.mu.Unlock()

	go h.consume(ctx)
	return nil
}

func (h *hostPlane) consume(ctx context.Context) {
	defer func() {
		h.mu.Lock()
		h.running = false
		h.mu.Unlock()
	}()
	events := h.source.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			h.handle(event)
		}
	}
}

func (h *hostPlane) handle(event plane.Event) {
	// Every exec teaches the tracker, whether or not it classifies. Lineage is
	// built from the whole process tree; discarding non-agent execs would break
	// attribution for the agent -> sh -> cat chain this exists to follow.
	switch event.Kind {
	case plane.KindExec:
		h.tracker.ObserveExec(event.PID, event.PPID, event.ResponsiblePID, event.Name, event.Cmdline)
	case plane.KindExit:
		h.tracker.ObserveExit(event.PID)
		return
	}

	match, ok := tactics.Classify(tactics.Observation{
		Kind:    string(event.Kind),
		PID:     event.PID,
		Name:    event.Name,
		Cmdline: event.Cmdline,
		Path:    event.Path,
		Detail:  event.Detail,
	}, h.indicators)
	if !ok {
		return
	}

	attribution, attributed := h.tracker.Attribute(event.PID)
	if !attributed {
		// The lineage gate. A developer running sudo produces nothing here.
		h.mu.Lock()
		h.gated++
		h.mu.Unlock()
		return
	}

	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.classified++
	session, exists := h.sessions[attribution.RootPID]
	if !exists {
		session = agentchain.NewSession(attribution.RootPID, attribution.AgentName, at)
		h.sessions[attribution.RootPID] = session
	}
	session.Record(agentchain.Observation{
		Tactic:     match.Tactic,
		SignalID:   match.SignalID,
		Title:      match.Title,
		Detail:     match.Detail,
		PID:        event.PID,
		Confidence: match.Confidence,
		At:         at,
	})
}

// hostFinding is one agent session, scored.
type hostFinding struct {
	RootPID   int
	AgentName string
	Score     int
	Signals   []scoring.Signal
	Stages    []tactics.Tactic
	FirstSeen time.Time
	LastSeen  time.Time
}

// harvest expires stale observations and returns the sessions that currently
// score at or above the floor.
//
// Expiry runs on every harvest rather than on a timer, so a chain is a chain
// within its window rather than over the lifetime of a long-running agent, and
// a session that has gone quiet decays out instead of scoring forever.
func (h *hostPlane) harvest(now time.Time, minRisk int) []hostFinding {
	cutoff := now.Add(-h.window)
	h.mu.Lock()
	defer h.mu.Unlock()

	findings := make([]hostFinding, 0, len(h.sessions))
	for rootPID, session := range h.sessions {
		session.Expire(cutoff)
		if len(session.Observations()) == 0 {
			delete(h.sessions, rootPID)
			continue
		}
		score, signals := session.Score(h.minStages)
		if score < minRisk {
			continue
		}
		findings = append(findings, hostFinding{
			RootPID: rootPID, AgentName: session.AgentName,
			Score: score, Signals: signals, Stages: session.TacticsSeen(),
			FirstSeen: session.FirstSeen, LastSeen: session.LastSeen,
		})
	}
	return findings
}

// stats reports what the gate did, so the lineage filter is auditable.
func (h *hostPlane) stats() (classified, gated int64, running bool, coverage plane.Coverage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.classified, h.gated, h.running, h.coverage
}

func (h *hostPlane) close() error {
	if h.source == nil {
		return nil
	}
	return h.source.Close()
}
