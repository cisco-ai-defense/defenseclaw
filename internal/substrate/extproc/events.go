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

package extproc

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event names (the log.egress.* family, §11).
const (
	EventEgressAllowed = "log.egress.allowed"
	EventEgressBlocked = "log.egress.blocked"
)

// Event is one decided request as telemetry sees it. It never carries a
// query string, a credential, a placeholder or a body; Headers, when
// LogHeaders is on, are redacted.
type Event struct {
	Time          time.Time         `json:"time"`
	Event         string            `json:"event"`
	Atespace      string            `json:"atespace,omitempty"`
	Actor         string            `json:"actor,omitempty"`
	ActorUID      string            `json:"actor_uid,omitempty"`
	Profile       string            `json:"profile,omitempty"`
	Host          string            `json:"host,omitempty"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	Decision      string            `json:"decision"`
	Alert         bool              `json:"alert,omitempty"`
	Category      string            `json:"category,omitempty"`
	Source        string            `json:"source,omitempty"`
	Rule          string            `json:"rule,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Feed          string            `json:"feed,omitempty"`
	AskID         string            `json:"ask_id,omitempty"`
	Findings      []string          `json:"findings,omitempty"`
	BodyInspected bool              `json:"body_inspected"`
	BodyOverCap   bool              `json:"body_over_cap"`
	Headers       map[string]string `json:"headers,omitempty"`
	LatencyMicros int64             `json:"latency_us"`
}

// JSONLogSink writes one JSON line per event.
type JSONLogSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONLogSink writes to w.
func NewJSONLogSink(w io.Writer) *JSONLogSink { return &JSONLogSink{w: w} }

// EgressEvent implements EventSink.
func (s *JSONLogSink) EgressEvent(ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(append(b, '\n'))
}

// Finish records a decided request: its event and, except for DefenseClaw's
// own hosts, its observed_egress chain step.
func (e *Engine) Finish(req *Request, v Verdict) {
	if !v.OwnHost && req.IdentityErr == nil && req.Host != "" {
		e.chain.push(ChainStep{Kind: StepObservedEgress, Actor: req.Actor, Host: req.Host, Method: req.Method,
			Allowed: v.Allow, Time: e.now()})
	}
	if e.events == nil || (v.OwnHost && v.Allow) {
		return
	}
	ev := Event{
		Time: e.now(), Event: EventEgressAllowed, Decision: "allow",
		Atespace: req.Actor.Atespace, Actor: req.Actor.Name, ActorUID: req.Actor.UID, Profile: v.Profile,
		Host: req.Host, Method: clip(req.Method, 16), Path: e.red.Path(req.Path),
		Alert: v.Alert, Category: v.Category, Source: v.Source, Rule: v.Rule, Reason: v.Reason, Feed: v.Feed,
		AskID: v.AskID, Findings: v.Findings, BodyInspected: v.BodyInspected, BodyOverCap: v.BodyOverCap,
	}
	if !v.Allow {
		ev.Event, ev.Decision = EventEgressBlocked, "block"
	}
	if !req.Start.IsZero() {
		ev.LatencyMicros = e.now().Sub(req.Start).Microseconds()
	}
	if e.cfg.LogHeaders {
		ev.Headers = e.red.Headers(req.Headers)
	}
	func() {
		defer func() { _ = recover() }()
		e.events.EgressEvent(ev)
	}()
}
