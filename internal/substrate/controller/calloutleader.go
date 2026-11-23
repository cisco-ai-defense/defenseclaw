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

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// The controller's egress callout slot reads, through the leader
// (GAP-0505). Only the controller's ServiceAccount may get the atenet-egress
// ConfigMap, so the controller publishes each read
// (leader.MethodCalloutPublish) and gateway replicas ask the leader for the
// latest (leader.MethodCalloutStatus). The leader keeps one report in
// memory: after a leader change the slot is unknown until the controller's
// next read, at most calloutCheckEvery later.

// PublishedCallout is one slot read on the wire.
type PublishedCallout struct {
	Known    bool      `json:"known"`
	Ours     bool      `json:"ours"`
	Holder   string    `json:"holder,omitempty"`
	Err      string    `json:"error,omitempty"`
	FailMode string    `json:"fail_mode,omitempty"`
	Since    time.Time `json:"since"`
	ReadAt   time.Time `json:"read_at"`
}

// CalloutAnswer is the leader's answer to leader.MethodCalloutStatus.
type CalloutAnswer struct {
	// Published is the controller's latest read (nil: none since the
	// leader started).
	Published *PublishedCallout `json:"published,omitempty"`
	// AgeMS is how long ago the leader received it, by the leader's clock.
	AgeMS int64 `json:"age_ms,omitempty"`
}

// CalloutBoard is the leader's copy of the controller's latest read.
type CalloutBoard struct {
	Now func() time.Time

	mu  sync.Mutex
	cur *PublishedCallout
	at  time.Time
}

func (b *CalloutBoard) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Publish keeps in as the latest read. A read older than the one kept
// (a late retry) is dropped unless the kept one is stale. An unknown slot
// is stored as neither ours nor anyone's.
func (b *CalloutBoard) Publish(_ context.Context, in PublishedCallout) (struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.cur != nil && in.ReadAt.Before(b.cur.ReadAt) && now.Sub(b.at) < CalloutStaleAfter {
		return struct{}{}, nil
	}
	if !in.Known {
		in.Ours, in.Holder = false, ""
	}
	b.cur, b.at = &in, now
	return struct{}{}, nil
}

// Status answers the latest read and its age.
func (b *CalloutBoard) Status(context.Context, struct{}) (CalloutAnswer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur == nil {
		return CalloutAnswer{}, nil
	}
	cp := *b.cur
	age := b.now().Sub(b.at)
	if age < 0 {
		age = 0
	}
	return CalloutAnswer{Published: &cp, AgeMS: age.Milliseconds()}, nil
}

// ServeCallout registers the callout methods on the leader server. The
// leader's permissions let the controller publish and gateways read
// (substrateLeaderPermissions); the route is mTLS like every leader call.
func ServeCallout(srv *leader.Server, b *CalloutBoard) {
	srv.Handle(leader.MethodCalloutPublish, leader.Typed(b.Publish))
	srv.HandleRead(leader.MethodCalloutStatus, leader.Typed(b.Status))
}

// LeaderCalloutPublisher is the controller's CalloutPublisher.
type LeaderCalloutPublisher struct {
	Leader *leader.Client
}

// PublishCallout implements CalloutPublisher.
func (p *LeaderCalloutPublisher) PublishCallout(ctx context.Context, st CalloutStatus) error {
	if p == nil || p.Leader == nil {
		return errors.New("no leader client")
	}
	in := PublishedCallout{Known: st.Known, Err: st.Err, FailMode: st.FailMode, Since: st.Since, ReadAt: st.At}
	if st.Known {
		in.Ours, in.Holder = st.Ours, st.Holder
	}
	return p.Leader.Call(ctx, leader.MethodCalloutPublish, leader.NewRequestID(), in, nil)
}

// calloutLeaderWait bounds one gateway read of the leader's report.
const calloutLeaderWait = 3 * time.Second

// LeaderCallout is the gateway's CalloutReader: the controller's latest
// report through the leader. No report, a report older than StaleAfter, or
// a report of a slot the controller could not read is an error (the slot
// is unknown, never the DefenseClaw callout). The controller that uses it
// reads at most every calloutCheckEvery.
type LeaderCallout struct {
	Leader *leader.Client
	// StaleAfter 0 is CalloutStaleAfter.
	StaleAfter time.Duration
}

// ReadCalloutSlot implements CalloutReader.
func (l *LeaderCallout) ReadCalloutSlot(ctx context.Context) (setup.CalloutSlot, error) {
	if l == nil || l.Leader == nil {
		return setup.CalloutSlot{}, errors.New("no leader client")
	}
	cctx, cancel := context.WithTimeout(ctx, calloutLeaderWait)
	defer cancel()
	var ans CalloutAnswer
	if err := l.Leader.Call(cctx, leader.MethodCalloutStatus, leader.NewRequestID(), struct{}{}, &ans); err != nil {
		return setup.CalloutSlot{}, fmt.Errorf("ask the leader for the controller's egress callout report: %w", err)
	}
	stale := l.StaleAfter
	if stale <= 0 {
		stale = CalloutStaleAfter
	}
	p := ans.Published
	switch age := time.Duration(ans.AgeMS) * time.Millisecond; {
	case p == nil:
		return setup.CalloutSlot{}, errors.New("the controller has not reported which egress callout Substrate uses")
	case age > stale:
		return setup.CalloutSlot{}, fmt.Errorf("the controller's last egress callout report is %s old (more than %s)", age.Round(time.Second), stale)
	case !p.Known:
		why := p.Err
		if why == "" {
			why = "it has not read the slot yet"
		}
		return setup.CalloutSlot{}, errors.New("the controller cannot read it: " + why)
	}
	return setup.CalloutSlot{Holder: p.Holder, Ours: p.Ours}, nil
}
