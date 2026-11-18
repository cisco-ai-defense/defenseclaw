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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// idle suspends a running actor that has been idle for after (the profile's
// idle_suspend_after, else IdleSuspendAfter; E4): no hook, model, relay or
// egress activity, never with a pending ask and never for a --task run
// unless its profile allows it. With a CPU source the actor also needs a
// fresh low CPU sample (no sample means not idle). Without one (the chart
// wires no usage receiver, so this is the usual case) a busy actor shows
// nothing, so only positive evidence counts (GAP-0534): the activity feed
// has heard of the actor (GAP-0465) and reports attachments, no terminal
// is attached, and the window runs from the last attachment too. A
// detached actor running a silent job is then suspended: the known limit.
// IdleSuspendWithoutCPU makes silence alone enough, an attached actor's
// too. Without an activity feed (nil or NoActivity, the create path's
// controller) nothing is idle.
//
// A --task actor whose task ended is suspended TaskEndGrace after the end
// (taskEnded), so a batch larger than the pool drains through it
// (GAP-0274). Once it reached the gateway after the end (pull, logs,
// connect), or was woken again later, it is idle like any other actor
// (GAP-0288). The end counts when it came after the actor was last seen
// stopped, not after the controller first saw it running: a short task
// ends before a slow pass sees it run, and a restarted controller sees
// every finished task already running (GAP-0411).
// The task-end suspend does not depend on idle suspend: with no idle timeout
// (idle_suspend_after: 0) a finished task still gives its worker back
// (GAP-0518).
func (c *Controller) idle(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, base Event, after time.Duration) error {
	if c.o.Activity == nil || a.GetStatus().GetState() != ateapi.ActorStateRunning || st.conflict {
		return nil
	}
	if _, none := c.o.Activity.(NoActivity); none {
		return nil
	}
	uid := a.GetMetadata().GetUid()
	if c.o.Activity.PendingAsk(uid) {
		return nil
	}
	now := c.o.Now()
	if reg.Task && !reg.IdleSuspendTask {
		src, ok := c.o.Activity.(TaskEndSource)
		if !ok {
			return nil
		}
		ended, ok := src.TaskEnded(uid)
		if !ok {
			return nil // the task runs
		}
		if ended.After(st.stoppedAt) {
			if t, ok := c.o.Activity.LastActivity(uid); !ok || !t.After(ended.Add(taskEndSlack)) {
				return c.taskEnded(ctx, a, st, reg, base, ended, now)
			}
		}
	}
	if after <= 0 {
		return nil // idle suspend is off
	}
	last := st.runningAt
	seen, heard := c.o.Activity.LastActivity(uid)
	if heard && seen.After(last) {
		last = seen
	}
	if c.o.CPU == nil && !c.live().IdleSuspendWithoutCPU {
		src, ok := c.o.Activity.(AttachSource)
		if !heard || !ok {
			return nil // unknown activity or attachments: not idle
		}
		if at, ok := src.Attached(uid); ok {
			if now.Sub(at) <= c.o.AttachMaxAge {
				return nil // a terminal is attached
			}
			if at.After(last) {
				last = at
			}
		}
	}
	if last.IsZero() || now.Sub(last) < after {
		return nil
	}
	detail := map[string]any{"task": reg.Task}
	if c.o.CPU != nil {
		cores, at, ok := c.o.CPU.CPU(uid)
		if !ok || now.Sub(at) > c.o.CPUSampleMaxAge || cores >= c.o.IdleCPU {
			return nil
		}
		detail["cpu_cores"] = cores
	} else if !heard {
		return nil
	}
	if _, err := c.o.Client.SuspendActor(ctx, ateapi.RefOf(a.GetMetadata())); err != nil {
		return fmt.Errorf("%s: idle suspend: %w", st.key, err)
	}
	st.lastState, st.stoppedAt = ateapi.ActorStateSuspended, now
	ev := base
	ev.Type, ev.Severity, ev.Message = EventIdleSuspend, SeverityInfo, "suspended after "+after.String()+" without activity"
	detail["idle_for"] = now.Sub(last).Round(1e9).String()
	ev.Detail = detail
	c.emit(ev)
	return nil
}

// taskEndSlack is how close to the end report other activity may be (the
// report itself is relay traffic).
const taskEndSlack = 10 * time.Second

// taskEnded suspends a --task actor TaskEndGrace after its task ended; the
// caller checked that nothing reached the gateway since.
func (c *Controller) taskEnded(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, base Event, ended, now time.Time) error {
	if now.Sub(ended) < c.o.TaskEndGrace {
		return nil
	}
	if _, err := c.o.Client.SuspendActor(ctx, ateapi.RefOf(a.GetMetadata())); err != nil {
		return fmt.Errorf("%s: task-end suspend: %w", st.key, err)
	}
	st.lastState, st.stoppedAt = ateapi.ActorStateSuspended, now
	ev := base
	ev.Type, ev.Severity = EventTaskEndSuspend, SeverityInfo
	ev.Message = "suspended: its task ended " + now.Sub(ended).Round(time.Second).String() + " ago, so its worker is free; pull, logs and connect wake it"
	ev.Detail = map[string]any{"task": true, "batch": reg.BatchID}
	c.emit(ev)
	return nil
}
