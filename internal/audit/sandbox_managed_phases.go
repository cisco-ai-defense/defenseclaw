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

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The managed gateway's one recorder tracks the phase of every account's
// managed sandboxes by registration (sandboxPhaseKey). The gateway, not the
// sandbox's daemon, decides when such a sandbox stops being tracked: it
// forgets the phase whenever the registration is revoked, removed or
// evicted (ForgetManagedSandbox), a revoked registration's records never
// start tracking it again (SandboxLifecycleEvent.TrackedOnly), and one
// account tracks at most as many sandboxes as it may hold registrations
// (LimitManagedPhases).

// sandboxManagedPhasePrefix starts the tracked-phase key of a managed
// sandbox. A sandbox name holds no NUL, so it never meets a name key.
const sandboxManagedPhasePrefix = "\x00registration\x00"

// ErrSandboxPhaseLimit is the error of a lifecycle record that would track
// one more managed sandbox for an account already at LimitManagedPhases.
// The record is not emitted.
var ErrSandboxPhaseLimit = errors.New("audit: the account tracks as many managed sandboxes as it may register")

func sandboxManagedPhaseKey(registrationID string) string {
	return sandboxManagedPhasePrefix + registrationID
}

// LimitManagedPhases bounds the managed sandboxes the recorder tracks for
// one account (SandboxLifecycleEvent.UserID) to n; 0 is no bound. A
// lifecycle record that would track one more fails with
// ErrSandboxPhaseLimit and is not emitted.
func (recorder *SandboxRecorder) LimitManagedPhases(n int) {
	if recorder == nil {
		return
	}
	recorder.lifecycle.Lock()
	defer recorder.lifecycle.Unlock()
	recorder.managedLimit = max(n, 0)
}

// managedPhaseRoomLocked refuses a lifecycle record that would start
// tracking a managed sandbox for an account that already tracks
// LimitManagedPhases of them. The caller holds recorder.lifecycle.
func (recorder *SandboxRecorder) managedPhaseRoomLocked(key string, input SandboxLifecycleEvent) error {
	if recorder.managedLimit <= 0 || input.TrackedOnly || input.Sandbox.Phase == SandboxPhaseDeleted ||
		!strings.HasPrefix(key, sandboxManagedPhasePrefix) {
		return nil
	}
	if _, known := recorder.phases[key]; known {
		return nil
	}
	held := 0
	for other, tracked := range recorder.phases {
		if tracked.owner == input.UserID && strings.HasPrefix(other, sandboxManagedPhasePrefix) {
			held++
		}
	}
	if held >= recorder.managedLimit {
		return fmt.Errorf("%w (account %q, %d tracked)", ErrSandboxPhaseLimit, input.UserID, held)
	}
	return nil
}

// ForgetManagedSandbox stops tracking the phase of the managed sandbox of
// registration registrationID and, when it counted as active, republishes
// its connector's metric.defenseclaw.sandbox.active gauge. It reports
// whether a phase was tracked.
func (recorder *SandboxRecorder) ForgetManagedSandbox(ctx context.Context, registrationID string) bool {
	if recorder == nil || registrationID == "" {
		return false
	}
	recorder.lifecycle.Lock()
	defer recorder.lifecycle.Unlock()
	key := sandboxManagedPhaseKey(registrationID)
	tracked, known := recorder.phases[key]
	if !known {
		return false
	}
	delete(recorder.phases, key)
	if !tracked.phase.Active() || recorder.logger == nil {
		return true
	}
	binding := recorder.logger.runtimeV8BindingSnapshot()
	if binding.metricBatch == nil {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event := recorder.newEvent(ctx, ActionSandboxLifecycle, SandboxIdentity{Connector: tracked.connector}, "", "", time.Now())
	_ = recorder.logger.recordRuntimeV8GeneratedMetricBatch(ctx, binding,
		[]RuntimeV8GeneratedMetric{newSandboxActiveMetric(event, tracked.connector, recorder.activeLocked(tracked.connector))})
	return true
}

// TrackedSandboxes is the number of sandboxes whose phase the recorder
// tracks.
func (recorder *SandboxRecorder) TrackedSandboxes() int {
	if recorder == nil {
		return 0
	}
	recorder.lifecycle.Lock()
	defer recorder.lifecycle.Unlock()
	return len(recorder.phases)
}

// activeLocked counts the tracked sandboxes of connector in an active
// phase. The caller holds recorder.lifecycle.
func (recorder *SandboxRecorder) activeLocked(connector string) int64 {
	var active int64
	for _, tracked := range recorder.phases {
		if tracked.connector == connector && tracked.phase.Active() {
			active++
		}
	}
	return active
}
