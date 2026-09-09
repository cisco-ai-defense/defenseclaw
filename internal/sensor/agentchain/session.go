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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// Observation is one tactic attributed to an agent session.
type Observation struct {
	Tactic     tactics.Tactic
	SignalID   string
	Title      string
	Detail     string
	PID        int
	Confidence float64
	At         time.Time
}

// Key deduplicates observations within a session. Two reads of the same
// credential by the same pid are one observation, not two, or a loop would
// look like escalating activity.
func (o Observation) Key() string {
	return o.SignalID + "|" + o.Detail
}

// Session accumulates the observations attributed to one agent root pid.
type Session struct {
	RootPID      int
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
// repeated key.
func (s *Session) Record(observation Observation) {
	existing, ok := s.observations[observation.Key()]
	if !ok || observation.Confidence > existing.Confidence {
		s.observations[observation.Key()] = observation
	}
	if observation.At.After(s.LastSeen) {
		s.LastSeen = observation.At
	}
}

// Expire drops observations older than cutoff, so a chain is a chain within a
// window rather than over the lifetime of a long-running agent.
func (s *Session) Expire(cutoff time.Time) {
	for key, observation := range s.observations {
		if observation.At.Before(cutoff) {
			delete(s.observations, key)
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

// FirstAt is when a tactic was first observed in this session, or the zero
// time when it was not.
func (s *Session) FirstAt(tactic tactics.Tactic) time.Time {
	var earliest time.Time
	for _, observation := range s.observations {
		if observation.Tactic != tactic {
			continue
		}
		if earliest.IsZero() || observation.At.Before(earliest) {
			earliest = observation.At
		}
	}
	return earliest
}

// Progressed reports whether the session moved forward through the chain.
//
// Requiring order rather than just a count is what separates an incident from
// a busy afternoon. An agent that reads a credential and later uploads
// something has progressed; one that uploads something and much later happens
// to read a config file has not.
func (s *Session) Progressed(minimum int) bool {
	seen := s.TacticsSeen()
	if len(seen) < minimum {
		return false
	}
	timeline := make([]time.Time, len(seen))
	for index, tactic := range seen {
		timeline[index] = s.FirstAt(tactic)
	}
	forward := 0
	for index := 0; index < len(timeline)-1; index++ {
		if !timeline[index].After(timeline[index+1]) {
			forward++
		}
	}
	return forward >= minimum-1
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
