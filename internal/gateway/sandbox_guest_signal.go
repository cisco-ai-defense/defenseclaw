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
	"context"
	"errors"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

const (
	// A guest's first lifecycle or egress record can be delayed while it
	// starts or while the daemon retries its telemetry queue. The live lease
	// is the existing five-minute bound for that start and reporting window.
	sandboxGuestGrace         = sandboxreg.LiveLease
	sandboxGuestSignalEvery   = time.Hour
	sandboxGuestSignalRetry   = time.Minute
	sandboxGuestRecordTimeout = 3 * time.Second
	sandboxGuestRecordMax     = 8
	sandboxGuestSignalMax     = 4096
)

type sandboxGuestSignalKey struct {
	uid    int
	id     string
	reason string
}

type sandboxGuestSignals struct {
	mu       sync.Mutex
	last     map[sandboxGuestSignalKey]sandboxGuestRate
	inFlight int
	wg       sync.WaitGroup
	// record is a test seam for the alert recorder.
	record func(context.Context, audit.SandboxRegistrationWithoutGuestEvent) error
}

type sandboxGuestRate struct {
	next    time.Time
	pending bool
}

// sandboxGuestSignal observes one admitted route without changing its answer.
// A watched registration alerts only until its first accepted guest record
// after bind; a later guest disappearance is outside this signal's scope.
func (a *APIServer) sandboxGuestSignal(ctx context.Context, auth *sandboxAuthority, reg sandboxreg.Registration, reason string) {
	if !reg.GuestWatch || !reg.GuestSeenAt.IsZero() || reg.BoundAt.IsZero() || reg.SandboxName == "" ||
		reg.State == sandboxreg.StatePending || reg.State == sandboxreg.StateRevoked {
		return
	}
	now := auth.clock()
	if now.Before(reg.BoundAt.Add(sandboxGuestGrace)) {
		return
	}
	current, ok, err := auth.store.Get(reg.UID, reg.ID)
	if err != nil {
		sandboxRecordFailed("guest signal lookup", err)
		return
	}
	if !ok || !current.GuestWatch || !current.GuestSeenAt.IsZero() || current.State == sandboxreg.StateRevoked {
		return
	}
	phase := audit.SandboxPhaseStopped
	if sandboxreg.EffectiveState(current, now) == sandboxreg.StateLive {
		phase = audit.SandboxPhaseReady
	}
	a.sandboxGuestEmit(ctx, auth, current, reason, phase)
}

// sandboxStoppedReportSignal records a running report the gateway refused
// for reg, a registration whose daemon reported its sandbox stopped
// (sandboxreg.ErrStopped): something of the account claimed a stopped
// sandbox runs again without starting it (GAP-0673). Rate-limited like the
// guest signal, per registration.
func (a *APIServer) sandboxStoppedReportSignal(ctx context.Context, auth *sandboxAuthority, reg sandboxreg.Registration) {
	if reg.BoundAt.IsZero() || reg.SandboxName == "" || reg.State != sandboxreg.StateStopped {
		return
	}
	a.sandboxGuestEmit(ctx, auth, reg, audit.SandboxGuestRunningAfterStop, audit.SandboxPhaseStopped)
}

// sandboxGuestEmit records one registration-without-guest alert for reg
// with reason, at most once per sandboxGuestSignalEvery per registration
// and reason, off the request path.
func (a *APIServer) sandboxGuestEmit(ctx context.Context, auth *sandboxAuthority, reg sandboxreg.Registration, reason string, phase audit.SandboxPhase) {
	now := auth.clock()
	key := sandboxGuestSignalKey{uid: reg.UID, id: reg.ID, reason: reason}
	signals := &auth.guestSignals
	identity := sandboxRecordIdentity(reg)
	identity.Phase = phase
	event := audit.SandboxRegistrationWithoutGuestEvent{
		Sandbox: identity, Subject: sandboxRecordSubject(reg), Reason: reason, Timestamp: now,
	}
	signals.mu.Lock()
	if signals.last == nil {
		signals.last = make(map[sandboxGuestSignalKey]sandboxGuestRate)
	}
	if last, ok := signals.last[key]; ok && (last.pending || now.Before(last.next)) {
		signals.mu.Unlock()
		return
	}
	for candidate, last := range signals.last {
		if !last.pending && !now.Before(last.next) {
			delete(signals.last, candidate)
		}
	}
	if len(signals.last) >= sandboxGuestSignalMax {
		var oldest sandboxGuestSignalKey
		var at time.Time
		for candidate, seen := range signals.last {
			if !seen.pending && (at.IsZero() || seen.next.Before(at)) {
				oldest, at = candidate, seen.next
			}
		}
		delete(signals.last, oldest)
	}
	if signals.inFlight >= sandboxGuestRecordMax {
		signals.last[key] = sandboxGuestRate{next: now.Add(sandboxGuestSignalRetry)}
		signals.mu.Unlock()
		sandboxRecordFailed("registration without guest", errors.New("alert recorder capacity reached"))
		return
	}
	signals.last[key] = sandboxGuestRate{pending: true}
	signals.inFlight++
	signals.wg.Add(1)
	record := signals.record
	signals.mu.Unlock()
	go func() {
		defer signals.wg.Done()
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxGuestRecordTimeout)
		defer cancel()
		if record == nil {
			record = a.managedSandboxRecorder().RecordSandboxRegistrationWithoutGuest
		}
		err := record(bounded, event)
		signals.mu.Lock()
		signals.inFlight--
		// Revocation or a sighting can remove this rate key during the call.
		if current, ok := signals.last[key]; ok && current.pending {
			delay := sandboxGuestSignalEvery
			if err != nil {
				delay = sandboxGuestSignalRetry
			}
			signals.last[key] = sandboxGuestRate{next: auth.clock().Add(delay)}
		}
		signals.mu.Unlock()
		sandboxRecordFailed("registration without guest", err)
	}()
}

// sandboxGuestSignalForget removes a registration's rate keys when it has
// been sighted, revoked, removed or evicted.
func (a *APIServer) sandboxGuestSignalForget(reg sandboxreg.Registration) {
	if a == nil {
		return
	}
	auth := a.sandboxAuthority.ready.Load()
	if auth == nil {
		return
	}
	signals := &auth.guestSignals
	signals.mu.Lock()
	defer signals.mu.Unlock()
	for key := range signals.last {
		if key.uid == reg.UID && key.id == reg.ID {
			delete(signals.last, key)
		}
	}
}

// sandboxMarkGuestSeen persists the first accepted guest record at gateway
// receipt. A queued record can carry an event time before the bind.
// Sighting failure never changes the events route's response.
func (a *APIServer) sandboxMarkGuestSeen(reg sandboxreg.Registration) {
	if !reg.GuestWatch || !reg.GuestSeenAt.IsZero() || reg.BoundAt.IsZero() {
		return
	}
	auth, err := a.sandboxAuth()
	if err == nil {
		err = auth.store.MarkGuestSeen(reg.UID, reg.ID, auth.clock())
		if err == nil {
			a.sandboxGuestSignalForget(reg)
		}
	}
	sandboxRecordFailed("guest sighting", err)
}
