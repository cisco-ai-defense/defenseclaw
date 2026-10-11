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
	"strings"
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
	// started is set once a source has started, and done is closed when the
	// consumer of that source stops: a source whose stream ended is replaced
	// with a fresh one before Plane C starts again (GAP-1418).
	started bool
	done    chan struct{}

	// lifecycle holds the creations and exits seen since the owner book
	// last took them (GAP-1403), at most maxLifecycleEvents of them.
	lifecycle      pidEvents
	lifecycleCount int
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
	h.mu.Lock()
	source := h.source
	h.mu.Unlock()
	if err := source.Start(ctx); err != nil {
		return err
	}
	done := make(chan struct{})
	h.mu.Lock()
	h.running = true
	h.started = true
	h.done = done
	h.coverage = source.Coverage()
	h.mu.Unlock()

	go h.consume(ctx, source, done)
	return nil
}

func (h *hostPlane) consume(ctx context.Context, source plane.Source, done chan struct{}) {
	defer func() {
		h.mu.Lock()
		h.running = false
		h.mu.Unlock()
		close(done)
	}()
	events := source.Events()
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

// stopped is closed when the consumer of the started source stops; it is
// nil while no source has started.
func (h *hostPlane) stopped() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done == nil {
		return nil
	}
	return h.done
}

// ended reports a source that started and whose stream has since ended.
func (h *hostPlane) ended() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started && !h.running
}

// replaceSource closes the source whose stream ended and puts next in its
// place. A brokered stream cannot be started twice (its connection is gone
// and its buffer is closed), so a reconnect needs a fresh source. Sessions,
// counters and the lineage tracker carry over (GAP-1418).
func (h *hostPlane) replaceSource(next plane.Source) {
	h.mu.Lock()
	previous := h.source
	h.source = next
	h.started = false
	h.done = nil
	h.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
}

func (h *hostPlane) handle(event plane.Event) {
	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	// Every exec teaches the tracker, whether or not it classifies. Lineage is
	// built from the whole process tree; discarding non-agent execs would break
	// attribution for the agent -> sh -> cat chain this exists to follow.
	switch event.Kind {
	case plane.KindExec:
		h.tracker.ObserveExec(event.PID, event.PPID, event.ResponsiblePID, event.Name, event.Cmdline,
			agentchain.Creation{At: at, SID: event.UserSID})
		h.noteLifecycle(event, at)
	case plane.KindExit:
		h.tracker.ObserveExit(event.PID)
		h.noteLifecycle(event, at)
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

	instance := h.tracker.InstanceOf(event.PID)
	user := ""
	if event.UserSID != "" {
		user = event.User
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
	if session.RootBorn.IsZero() {
		session.RootBorn = attribution.RootBorn
	}
	session.Record(agentchain.Observation{
		Tactic:     match.Tactic,
		SignalID:   match.SignalID,
		Title:      match.Title,
		Detail:     match.Detail,
		PID:        event.PID,
		Start:      instance.Start,
		Born:       instance.Born,
		Instance:   instance.ID,
		User:       user,
		SID:        event.UserSID,
		Name:       event.Name,
		Path:       event.Path,
		Confidence: match.Confidence,
		At:         at,
	})
}

// maxLifecycleEvents bounds the creations and exits kept between two polls.
const maxLifecycleEvents = maxOwnerInstances

// noteLifecycle keeps a creation or exit for the owner book, which must hear
// that a pid was handed on before it attributes what the pid did next. It is
// called once the tracker has learnt the event, so it names the tracker's
// instance the event concerned.
func (h *hostPlane) noteLifecycle(event plane.Event, at time.Time) {
	if event.PID <= 0 {
		return
	}
	instance := h.tracker.InstanceOf(event.PID).ID
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lifecycleCount >= maxLifecycleEvents {
		if h.lifecycle.Overflow.IsZero() {
			h.lifecycle.Overflow = at
		}
		return
	}
	if h.lifecycle.ByPID == nil {
		h.lifecycle.ByPID = map[int][]pidEvent{}
	}
	h.lifecycle.ByPID[event.PID] = append(h.lifecycle.ByPID[event.PID],
		pidEvent{At: at, Exit: event.Kind == plane.KindExit, Instance: instance})
	h.lifecycleCount++
}

// takeLifecycle hands the creations and exits seen so far to the owner book.
func (h *hostPlane) takeLifecycle() pidEvents {
	h.mu.Lock()
	defer h.mu.Unlock()
	taken := h.lifecycle
	taken.Taken = time.Now()
	h.lifecycle, h.lifecycleCount = pidEvents{}, 0
	return taken
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
		processes, configPaths := sessionOwnerEvidence(procRef{
			PID: root.process.PID, Start: session.RootStart, Born: session.RootBorn, Instance: root.instance,
			Name: session.RootName, At: session.LastSeen,
		}, session.Observations())
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
// each with when the session last saw it and the account its events named,
// and the agent configuration files it wrote.
func sessionOwnerEvidence(root procRef, observations []agentchain.Observation) ([]procRef, []string) {
	type refKey struct {
		process  procprobe.ProcKey
		instance uint64
		sid      string
	}
	processes := []procRef{root}
	seen := map[refKey]int{{process: procprobe.KeyOf(root.PID, root.Start), instance: root.Instance}: 0}
	var configPaths []string
	for _, observation := range observations {
		if observation.PID > 0 {
			key := refKey{
				process:  procprobe.KeyOf(observation.PID, observation.Start),
				instance: observation.Instance, sid: strings.ToUpper(observation.SID),
			}
			if index, ok := seen[key]; !ok {
				seen[key] = len(processes)
				processes = append(processes, procRef{
					PID: observation.PID, Start: observation.Start, Name: observation.Name, At: observation.At,
					Born: observation.Born, Instance: observation.Instance, User: observation.User, SID: observation.SID,
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
// stats reads the coverage from the running source each time rather than
// the copy taken at start: a source that falls behind reports it while it
// lasts and stops once it has caught up (GAP-1473).
func (h *hostPlane) stats() (classified, gated int64, running bool, coverage plane.Coverage) {
	h.mu.Lock()
	classified, gated, running, coverage = h.classified, h.gated, h.running, h.coverage
	source := h.source
	h.mu.Unlock()
	if running && source != nil {
		coverage = source.Coverage()
	}
	return classified, gated, running, coverage
}

func (h *hostPlane) close() error {
	h.mu.Lock()
	source := h.source
	h.mu.Unlock()
	if source == nil {
		return nil
	}
	return source.Close()
}
