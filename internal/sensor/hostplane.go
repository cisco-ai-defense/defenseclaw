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
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
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

	mu sync.Mutex
	// sessions are keyed by the root process instance, not its pid: an agent
	// that reuses an exited agent's pid starts its own session (GAP-1372).
	sessions map[hostSessionKey]*agentchain.Session
	// gated counts observations discarded for having no agent above them. It
	// is the denominator that makes the lineage gate auditable rather than
	// invisible.
	gated int64
	// classified counts observations that became a tactic.
	classified int64
	running    bool
	coverage   plane.Coverage
}

// hostSessionKey keeps the first pid/start key stable through a late exec or
// a later poll, while instance separates pid reuse when start was unknown.
type hostSessionKey struct {
	process  procprobe.ProcKey
	instance uint64
}

func newHostPlane(
	source plane.Source, tracker *agentchain.Tracker,
	indicators tactics.IndicatorSet, window time.Duration, minStages int,
) *hostPlane {
	return &hostPlane{
		source: source, tracker: tracker, indicators: indicators,
		window: window, minStages: minStages,
		sessions: make(map[hostSessionKey]*agentchain.Session),
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
		h.tracker.ObserveExec(event.PID, event.PPID, event.ResponsiblePID, event.Name, event.Cmdline, time.Time{})
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
	root := hostSessionKey{
		process:  procprobe.KeyOf(attribution.RootPID, attribution.RootKeyStart),
		instance: attribution.RootInstance,
	}
	session, exists := h.sessions[root]
	if !exists {
		session = agentchain.NewSession(attribution.RootPID, attribution.AgentName, at)
		session.RootName = attribution.RootName
		h.sessions[root] = session
	}
	if session.RootStart.IsZero() && !attribution.RootStart.IsZero() {
		session.RootStart = attribution.RootStart
	}
	session.Record(agentchain.Observation{
		Tactic:     match.Tactic,
		SignalID:   match.SignalID,
		Title:      match.Title,
		Detail:     match.Detail,
		PID:        event.PID,
		Start:      h.tracker.StartOf(event.PID),
		Name:       event.Name,
		Path:       event.Path,
		Confidence: match.Confidence,
		At:         at,
	})
}

// hostFinding is one agent session, scored.
type hostFinding struct {
	RootPID int
	// RootStart is when the root process was created, zero when unknown.
	RootStart time.Time
	AgentName string
	// Processes are the session's process instances, root first, and
	// ConfigPaths the agent configuration files it wrote: what attributes
	// it to an account.
	Processes   []procRef
	ConfigPaths []string
	Score       int
	Signals     []scoring.Signal
	Stages      []tactics.Tactic
	FirstSeen   time.Time
	LastSeen    time.Time
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
	for root, session := range h.sessions {
		session.Expire(cutoff)
		if len(session.Observations()) == 0 {
			delete(h.sessions, root)
			continue
		}
		score, signals := session.Score(h.minStages)
		if score < minRisk {
			continue
		}
		processes, configPaths := sessionOwnerEvidence(root.process.PID, session.RootStart, session.RootName, session.LastSeen, session.Observations())
		findings = append(findings, hostFinding{
			RootPID: root.process.PID, RootStart: session.RootStart, AgentName: session.AgentName,
			Processes: processes, ConfigPaths: configPaths,
			Score: score, Signals: signals, Stages: session.TacticsSeen(),
			FirstSeen: session.FirstSeen, LastSeen: session.LastSeen,
		})
	}
	return findings
}

// sessionOwnerEvidence lists a session's process instances, root first,
// each with when the session last saw it, and the agent configuration files
// it wrote.
func sessionOwnerEvidence(
	rootPID int, rootStart time.Time, rootName string, lastSeen time.Time, observations []agentchain.Observation,
) ([]procRef, []string) {
	root := procprobe.KeyOf(rootPID, rootStart)
	processes := []procRef{{PID: rootPID, Start: rootStart, Name: rootName, At: lastSeen}}
	seen := map[procprobe.ProcKey]int{root: 0}
	var configPaths []string
	for _, observation := range observations {
		if observation.PID > 0 {
			key := procprobe.KeyOf(observation.PID, observation.Start)
			if index, ok := seen[key]; !ok {
				seen[key] = len(processes)
				processes = append(processes, procRef{
					PID: observation.PID, Start: observation.Start, Name: observation.Name, At: observation.At,
				})
			} else if observation.At.After(processes[index].At) {
				processes[index].At = observation.At
			}
		}
		if observation.SignalID == "agent_config_persistence" && observation.Path != "" {
			configPaths = append(configPaths, observation.Path)
		}
	}
	return processes, configPaths
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
