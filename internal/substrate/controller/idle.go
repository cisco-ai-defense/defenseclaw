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
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// idle suspends a running actor that has been idle for IdleSuspendAfter
// (E4): no hook, model, relay or egress activity and low CPU, never with a
// pending ask, never for a --task run unless its profile allows it, and
// never without a fresh CPU sample (no sample means not idle).
func (c *Controller) idle(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, base Event) error {
	after := c.o.IdleSuspendAfter
	if after <= 0 || a.GetStatus().GetState() != ateapi.ActorStateRunning || st.conflict {
		return nil
	}
	if reg.Task && !reg.IdleSuspendTask {
		return nil
	}
	uid := a.GetMetadata().GetUid()
	if c.o.Activity.PendingAsk(uid) {
		return nil
	}
	now := c.o.Now()
	last := st.runningAt
	if t, ok := c.o.Activity.LastActivity(uid); ok && t.After(last) {
		last = t
	}
	if last.IsZero() || now.Sub(last) < after {
		return nil
	}
	if c.o.CPU == nil {
		return nil
	}
	cores, at, ok := c.o.CPU.CPU(uid)
	if !ok || now.Sub(at) > c.o.CPUSampleMaxAge || cores >= c.o.IdleCPU {
		return nil
	}
	if _, err := c.o.Client.SuspendActor(ctx, ateapi.RefOf(a.GetMetadata())); err != nil {
		return fmt.Errorf("%s: idle suspend: %w", st.key, err)
	}
	st.lastState = ateapi.ActorStateSuspended
	ev := base
	ev.Type, ev.Severity, ev.Message = EventIdleSuspend, SeverityInfo, "suspended after "+after.String()+" without activity"
	ev.Detail = map[string]any{"idle_for": now.Sub(last).Round(1e9).String(), "cpu_cores": cores, "task": reg.Task}
	c.emit(ev)
	return nil
}
