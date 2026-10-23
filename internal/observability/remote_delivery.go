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

package observability

import (
	"context"
	"sync"
)

type remoteDeliveryKey struct{}

// RemoteDelivery follows the optional-destination deliveries of one
// occurrence that its producer keeps in a durable spool under a stable id
// (a trust anchor or credential change event) and offers, through one
// sender, until every destination has it. The sender keeps one
// RemoteDelivery per occurrence across offers: each offer is an attempt, a
// destination that acknowledged an earlier attempt or still has one in
// flight is not sent the occurrence again, and the occurrence is delivered
// once an attempt ends with nothing in flight and no destination left that
// failed. The state is in memory only: after a restart the spooled
// occurrence is offered to every destination again under the same record
// id.
type RemoteDelivery struct {
	mu   sync.Mutex
	open bool
	// inFlight counts, per destination, the deliveries handed to its queue
	// that have not ended.
	inFlight map[string]int
	// failed is set when a destination did not get the occurrence since the
	// current attempt began.
	failed    bool
	delivered map[string]bool
}

// NewRemoteDelivery returns the delivery state of one occurrence.
func NewRemoteDelivery() *RemoteDelivery {
	return &RemoteDelivery{inFlight: make(map[string]int), delivered: make(map[string]bool)}
}

// WithRemoteDelivery attaches delivery to ctx, so the runtime reports every
// optional-destination outcome of the occurrence emitted with ctx to it.
func WithRemoteDelivery(ctx context.Context, delivery *RemoteDelivery) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if delivery == nil {
		return ctx
	}
	return context.WithValue(ctx, remoteDeliveryKey{}, delivery)
}

// RemoteDeliveryFrom returns the RemoteDelivery attached to ctx, or nil.
func RemoteDeliveryFrom(ctx context.Context) *RemoteDelivery {
	if ctx == nil {
		return nil
	}
	delivery, _ := ctx.Value(remoteDeliveryKey{}).(*RemoteDelivery)
	return delivery
}

// BeginAttempt starts an offer: failures of an earlier attempt are
// forgotten, destinations that acknowledged are kept.
func (delivery *RemoteDelivery) BeginAttempt() {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	delivery.open, delivery.failed = true, false
}

// EndAttempt ends the emission of an offer. Deliveries it handed to
// destinations may still be in flight.
func (delivery *RemoteDelivery) EndAttempt() {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	delivery.open = false
	delivery.mu.Unlock()
}

// Pending reports whether destination needs the occurrence: it has not
// acknowledged it and has no delivery of it in flight. A nil RemoteDelivery
// follows nothing, so every destination needs it.
func (delivery *RemoteDelivery) Pending(destination string) bool {
	if delivery == nil {
		return true
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	return !delivery.delivered[destination] && delivery.inFlight[destination] == 0
}

// Acknowledged reports whether destination acknowledged an earlier attempt.
func (delivery *RemoteDelivery) Acknowledged(destination string) bool {
	if delivery == nil {
		return false
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	return delivery.delivered[destination]
}

// Fail records that destination did not get the occurrence in this attempt
// (it could not be projected or queued).
func (delivery *RemoteDelivery) Fail(destination string) {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	if !delivery.delivered[destination] {
		delivery.failed = true
	}
}

// Track records one delivery handed to destination and returns the function
// its queue calls once with the terminal outcome: delivered when the
// destination acknowledged it, false when it was refused, dropped or
// abandoned. A failure fails the current attempt even when an earlier one
// handed the delivery over: no later attempt sends the destination another
// copy while it is in flight. Later calls are ignored.
func (delivery *RemoteDelivery) Track(destination string) func(delivered bool) {
	if delivery == nil {
		return func(bool) {}
	}
	delivery.mu.Lock()
	delivery.inFlight[destination]++
	delivery.mu.Unlock()
	var once sync.Once
	return func(delivered bool) {
		once.Do(func() {
			delivery.mu.Lock()
			defer delivery.mu.Unlock()
			if delivery.inFlight[destination]--; delivery.inFlight[destination] <= 0 {
				delete(delivery.inFlight, destination)
			}
			if delivered {
				delivery.delivered[destination] = true
			} else if !delivery.delivered[destination] {
				delivery.failed = true
			}
		})
	}
}

// Settled reports whether the last attempt has ended with nothing in
// flight, and if so whether every destination of it has the occurrence.
// Nothing to deliver (a nil RemoteDelivery, an occurrence no destination
// takes) is delivered.
func (delivery *RemoteDelivery) Settled() (settled, delivered bool) {
	if delivery == nil {
		return true, true
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	if delivery.open || len(delivery.inFlight) > 0 {
		return false, false
	}
	return true, !delivery.failed
}
