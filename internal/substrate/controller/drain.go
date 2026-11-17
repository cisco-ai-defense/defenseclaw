// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// A worker pool roll (a new worker image, a node drain) replaces each
// worker: Substrate marks the old one DRAINING when its pod starts to
// terminate, places no new actor on it and, by design, leaves the actors it
// hosts alone (DrainWorker). An actor still RUNNING there when the pod's
// termination grace ends is CRASHED, and its unsaved work is lost. Substrate
// suspends nothing for you (substrate-1:GAP-0449). So the controller moves a
// managed actor off a draining worker: it suspends it (a snapshot, as idle
// suspend takes) and, unless its --task already ended, resumes it, which
// places it on an ACTIVE worker. The agent and a running task go on where
// they were; an attached session reconnects.

// EventWorkerDrainSuspend and EventWorkerDrainResume record the move.
const (
	EventWorkerDrainSuspend = "sandbox.worker_drain.suspend"
	EventWorkerDrainResume  = "sandbox.worker_drain.resume"
)

// drainingWorkers lists the workers once per pass. A client without the
// call, or a principal that may not list workers, gets one warning: the
// controller then cannot move actors before a pool roll.
func (c *Controller) drainingWorkers(ctx context.Context) ateapi.Draining {
	wl, ok := c.o.Client.(ateapi.WorkerLister)
	if !ok {
		return ateapi.Draining{}
	}
	d, err := ateapi.DrainingWorkers(ctx, wl)
	if err != nil {
		if !c.workersWarned {
			c.workersWarned = true
			c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
				Message: "cannot list Substrate workers (" + status.Code(err).String() + "): an actor running on a draining worker is not suspended before the worker stops, so a worker pool roll crashes it; suspend running actors before you roll the pool, or grant DefenseClaw global viewer (the chart bootstrap)"})
		}
		return ateapi.Draining{}
	}
	c.workersWarned = false
	return d
}

// drain moves a managed actor off a draining worker; done is true when it
// acted (the pass for that actor ends there). A suspended actor this
// controller moved is resumed on a later pass, once Substrate reports it
// SUSPENDED.
func (c *Controller) drain(ctx context.Context, a *ateapi.Actor, st *actorState, reg Registration, base Event) (bool, error) {
	ref := ateapi.RefOf(a.GetMetadata())
	switch a.GetStatus().GetState() {
	case ateapi.ActorStateRunning:
		pod, draining := c.currentDrain().Hosts(a)
		if !draining {
			st.drainResume = false
			return false, nil
		}
		if _, err := c.o.Client.SuspendActor(ctx, ref); err != nil {
			return true, fmt.Errorf("%s: suspend off draining worker %s: %w", st.key, pod, err)
		}
		st.lastState = ateapi.ActorStateSuspended
		st.drainResume = !c.taskDone(a, st, reg)
		st.drainFrom, st.drainResumeWarned = pod, false
		ev := base
		ev.Type, ev.Severity = EventWorkerDrainSuspend, SeverityWarn
		ev.Message = "suspended: its worker " + pod + " is draining (a worker pool roll), and an actor still running there when the worker stops crashes and loses its work"
		if st.drainResume {
			ev.Message += "; DefenseClaw resumes it on another worker"
		} else {
			ev.Message += "; its task had ended, so it stays suspended"
		}
		ev.Detail = map[string]any{"worker_pod": pod, "task": reg.Task, "resume": st.drainResume}
		c.emit(ev)
		return true, nil
	case ateapi.ActorStateSuspending:
		return st.drainResume, nil
	case ateapi.ActorStateSuspended:
		if !st.drainResume {
			return false, nil
		}
		if _, _, err := c.o.Client.ResumeActor(ctx, ref); err != nil {
			// No room yet (the new workers are still starting) or a
			// transient error: the actor is safe, suspended; try again on
			// the next pass and say so once.
			if !st.drainResumeWarned {
				st.drainResumeWarned = true
				ev := base
				ev.Type, ev.Severity = EventWarning, SeverityWarn
				ev.Message = "moved off draining worker " + st.drainFrom + " and suspended, but not resumed yet (" + status.Code(err).String() + "): DefenseClaw tries again on each pass; connect also resumes it"
				c.emit(ev)
			}
			return true, nil
		}
		st.drainResume = false
		st.lastState = ateapi.ActorStateResuming
		ev := base
		ev.Type, ev.Severity = EventWorkerDrainResume, SeverityInfo
		ev.Message = "resumed on another worker after its worker " + st.drainFrom + " began draining"
		ev.Detail = map[string]any{"worker_pod": st.drainFrom}
		c.emit(ev)
		return true, nil
	}
	st.drainResume = false
	return false, nil
}

// taskDone says whether a --task actor's task has already ended: such an
// actor is only suspended, as its task-end suspend would.
func (c *Controller) taskDone(a *ateapi.Actor, st *actorState, reg Registration) bool {
	if !reg.Task {
		return false
	}
	src, ok := c.o.Activity.(TaskEndSource)
	if !ok {
		return false
	}
	ended, ok := src.TaskEnded(a.GetMetadata().GetUid())
	return ok && ended.After(st.runningAt)
}

// currentDrain is the draining workers of the pass in progress.
func (c *Controller) currentDrain() ateapi.Draining {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.draining
}
