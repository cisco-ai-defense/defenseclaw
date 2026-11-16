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

package agentchain

import (
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// Observation is one tactic attributed to an agent session.
type Observation struct {
	Tactic   tactics.Tactic
	SignalID string
	Title    string
	Detail   string
	PID      int
	// Start is when the observed process was created and Name its image,
	// each empty when unknown. With PID they name the process instance, so
	// the owner of an observation is read for that process and not for a
	// later one that reused its pid (GAP-1372).
	Start time.Time
	Name  string
	// Born is when the event that started the process was logged and
	// Instance the lineage tracker's instance of it, each zero when
	// unknown: with the start unknown they still tell it from a later
	// process on its pid (GAP-1464).
	Born     time.Time
	Instance uint64
	// User and SID are the account the event itself named for the process
	// (the writer's token of a Windows file access), empty when it named
	// none. Unlike an owner looked up by pid it cannot be a later holder's.
	User, SID string
	// Path is the file the observation concerns, for file kinds. It names
	// the profile an agent's configuration lives in, which can attribute
	// the session to its account.
	Path       string
	Confidence float64
	At         time.Time
	// LastAt is the latest sighting of the same key, zero when it was seen
	// once. A stage the session reached early and again later can take its
	// place in the chain at either time, so an early, unrelated sighting
	// cannot hold a later real one out of order (GAP-1419).
	LastAt time.Time
	// between holds the sightings of the same key after At and before
	// LastAt, ascending and bounded by maxSightingsPerKey. Expiring the
	// earliest sighting then leaves a middle one that can still complete a
	// chain inside the window (GAP-1427).
	between []time.Time
}

// maxSightingsPerKey bounds the sightings one observation key keeps, so a
// loop that repeats one read cannot grow a session without bound.
const maxSightingsPerKey = 32

// sightings returns every time this observation was seen, ascending.
func (o Observation) sightings() []time.Time {
	times := make([]time.Time, 0, len(o.between)+2)
	times = append(times, o.At)
	times = append(times, o.between...)
	if o.LastAt.After(o.At) {
		times = append(times, o.LastAt)
	}
	return times
}

// setSightings stores ascending, distinct, non-empty times as At, between and
// LastAt.
func (o *Observation) setSightings(times []time.Time) {
	o.At, o.LastAt, o.between = times[0], time.Time{}, nil
	if last := len(times) - 1; last > 0 {
		o.LastAt = times[last]
		if last > 1 {
			o.between = append([]time.Time(nil), times[1:last]...)
		}
	}
}

// mergeSightings returns the distinct times of a and b, ascending. Over the
// bound it drops the inner sighting closest to the one before it, so the
// earliest and latest stay and the rest stay spread over the span.
func mergeSightings(a, b []time.Time) []time.Time {
	merged := make([]time.Time, 0, len(a)+len(b))
	merged = append(append(merged, a...), b...)
	sort.Slice(merged, func(i, j int) bool { return merged[i].Before(merged[j]) })
	distinct := merged[:0]
	for _, at := range merged {
		if len(distinct) == 0 || !at.Equal(distinct[len(distinct)-1]) {
			distinct = append(distinct, at)
		}
	}
	for len(distinct) > maxSightingsPerKey {
		drop := 1
		for index := 2; index < len(distinct)-1; index++ {
			if distinct[index].Sub(distinct[index-1]) < distinct[drop].Sub(distinct[drop-1]) {
				drop = index
			}
		}
		distinct = append(distinct[:drop], distinct[drop+1:]...)
	}
	return distinct
}

// Key deduplicates observations within a session. Two reads of the same
// credential by the same pid are one observation, not two, or a loop would
// look like escalating activity.
func (o Observation) Key() string {
	// Retain distinct file paths even when their signal and detail agree.
	// Ownership resolution needs every profile touched by the session.
	// Sightings under different accounts stay apart, so neither account's
	// sighting is folded into the other's (GAP-1464).
	return o.SignalID + "|" + o.Detail + "|" + o.Path + "|" + strings.ToUpper(o.SID)
}

// Session accumulates the observations attributed to one agent root pid.
type Session struct {
	RootPID int
	// RootStart is the kernel creation time when known, and RootBorn when
	// the event that started the root was logged, zero when unknown.
	RootStart time.Time
	RootBorn  time.Time
	// RootName is the root process's image name, empty when unknown.
	RootName     string
	AgentName    string
	FirstSeen    time.Time
	LastSeen     time.Time
	observations map[string]Observation
}

// NewSession starts a session for an agent root process.
func NewSession(rootPID int, agentName string, at time.Time) *Session {
	return &Session{
		RootPID: rootPID, AgentName: agentName, FirstSeen: at, LastSeen: at,
		observations: make(map[string]Observation),
	}
}

// Record adds an observation, keeping the highest-confidence sighting of a
// repeated key, the earliest time it was seen and the latest.
//
// Confidence and time are kept separately on purpose. Adopting a later
// sighting's timestamp along with its confidence would move the stage's start
// forward, and Progressed reads the sighting times to decide whether the
// session moved through its stages in order -- so re-observing an early stage
// more confidently could reorder a chain that had already formed, or form one
// that never happened. Every sighting is kept (bounded), so a stage that
// recurs still counts at each time it recurred.
func (s *Session) Record(observation Observation) {
	key := observation.Key()
	kept := observation
	if existing, ok := s.observations[key]; ok {
		times := mergeSightings(existing.sightings(), observation.sightings())
		if observation.Confidence <= existing.Confidence {
			kept = existing
		}
		kept.setSightings(times)
	}
	s.observations[key] = kept
	if observation.At.After(s.LastSeen) {
		s.LastSeen = observation.At
	}
}

// Expire drops observations older than cutoff, so a chain is a chain within a
// window rather than over the lifetime of a long-running agent.
//
// A key seen again inside the window keeps every sighting inside it, so the
// chain is still built from sightings within the window, and one that a
// middle sighting completes is not lost when the first expires (GAP-1427).
func (s *Session) Expire(cutoff time.Time) {
	for key, observation := range s.observations {
		times := observation.sightings()
		inside := times[:0]
		for _, at := range times {
			if !at.Before(cutoff) {
				inside = append(inside, at)
			}
		}
		switch {
		case len(inside) == 0:
			delete(s.observations, key)
		case len(inside) < len(times):
			observation.setSightings(inside)
			s.observations[key] = observation
		}
	}
}

// Observations returns the retained observations, ordered by time.
func (s *Session) Observations() []Observation {
	ordered := make([]Observation, 0, len(s.observations))
	for _, observation := range s.observations {
		ordered = append(ordered, observation)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].At.Equal(ordered[j].At) {
			return ordered[i].SignalID < ordered[j].SignalID
		}
		return ordered[i].At.Before(ordered[j].At)
	})
	return ordered
}

// TacticsSeen lists the distinct tactics observed, in chain order.
func (s *Session) TacticsSeen() []tactics.Tactic {
	present := make(map[tactics.Tactic]bool, len(s.observations))
	for _, observation := range s.observations {
		present[observation.Tactic] = true
	}
	seen := make([]tactics.Tactic, 0, len(present))
	for _, tactic := range tactics.ChainOrder {
		if present[tactic] {
			seen = append(seen, tactic)
		}
	}
	return seen
}

// Progressed reports whether the session moved forward through the chain.
//
// Requiring order rather than just a count is what separates an incident from
// a busy afternoon. An agent that reads a credential and later uploads
// something has progressed; one that uploads something and much later happens
// to read a config file has not.
//
// Every sighting of a stage counts, not only its first. A session whose first
// observation was an unrelated or low-confidence packaging step, and which
// then read a credential, minted a principal and packaged data for real, has
// moved through the chain in order; reading only each stage's first sighting
// put packaging first and never formed the chain (GAP-1419).
func (s *Session) Progressed(minimum int) bool {
	if len(s.TacticsSeen()) < minimum {
		return false
	}
	sightings := make([]stageSighting, 0, 2*len(s.observations))
	for _, observation := range s.observations {
		stage := tactics.ChainStage(observation.Tactic)
		if stage < 0 {
			continue
		}
		for _, at := range observation.sightings() {
			sightings = append(sightings, stageSighting{stage: stage, at: at})
		}
	}
	return orderedStages(sightings) >= minimum
}

// stageSighting is one time a chain stage was seen.
type stageSighting struct {
	stage int
	at    time.Time
}

// orderedStages returns the most stages the session moved through in order:
// the longest run of sightings whose chain stage and time both advance
// together.
//
// Counting forward-going pairs instead is not the same thing, and the
// difference decides whether a finding is critical. Stage times [5 6 1 2]
// contain two ascending pairs -- (5,6) and (1,2) -- so a pair count of two
// clears a three-stage threshold, while the longest actual progression is
// two stages. Two unrelated ascending pairs are not a chain.
//
// Sightings at the same instant are taken in chain order. The walk keeps,
// per stage, the longest run ending there, over the handful of ATT&CK
// tactics this package tracks.
func orderedStages(sightings []stageSighting) int {
	sort.Slice(sightings, func(i, j int) bool {
		if sightings[i].at.Equal(sightings[j].at) {
			return sightings[i].stage < sightings[j].stage
		}
		return sightings[i].at.Before(sightings[j].at)
	})
	best := make([]int, len(tactics.ChainOrder))
	longest := 0
	for _, sighting := range sightings {
		run := 1
		for earlier := 0; earlier < sighting.stage; earlier++ {
			if best[earlier]+1 > run {
				run = best[earlier] + 1
			}
		}
		if run > best[sighting.stage] {
			best[sighting.stage] = run
		}
		if run > longest {
			longest = run
		}
	}
	return longest
}

// Score sums the session's observations and adds the chain bonus when the
// session has progressed through enough stages to be a chain.
func (s *Session) Score(minChainStages int) (int, []scoring.Signal) {
	signals := make([]scoring.Signal, 0, len(s.observations)+1)
	for _, observation := range s.Observations() {
		weight, ok := scoring.HostPlaneWeight(observation.SignalID)
		if !ok {
			continue
		}
		signals = append(signals, scoring.Signal{
			ID:     observation.SignalID,
			Title:  observation.Title,
			Detail: observation.Detail,
			Weight: scoring.ConfidenceWeighted(weight, observation.Confidence),
		})
	}
	if s.Progressed(minChainStages) {
		stages := s.TacticsSeen()
		signals = append(signals, scoring.Signal{
			ID:     "agent_kill_chain",
			Title:  "agent moved through the kill chain",
			Detail: chainDetail(stages),
			Weight: scoring.WeightKillChain,
		})
	}
	return scoring.Total(signals), signals
}

func chainDetail(stages []tactics.Tactic) string {
	detail := ""
	for index, stage := range stages {
		if index > 0 {
			detail += " -> "
		}
		detail += string(stage)
	}
	return detail
}
