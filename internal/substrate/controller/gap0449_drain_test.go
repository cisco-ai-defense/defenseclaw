// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// substrate-1:GAP-0449: a worker pool roll (rc.3 to v1.0.0 on E1) marked the
// old workers DRAINING; Substrate leaves the actors they host alone, and both
// running actors crashed when the 30-minute termination grace ended. The
// controller now suspends a managed actor on a draining worker and resumes it
// on another worker.

// workerCluster is the fake control API with a worker list (ListWorkers).
type workerCluster struct {
	*ateapifake.Fake
	mu      sync.Mutex
	workers []*pb.Worker
	err     error
}

func (w *workerCluster) ListWorkers(_ context.Context, _ ateapi.ListOptions) (ateapi.Page[*pb.Worker], error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return ateapi.Page[*pb.Worker]{}, w.err
	}
	return ateapi.Page[*pb.Worker]{Items: append([]*pb.Worker(nil), w.workers...)}, nil
}

// drain marks the worker pod that hosts a DRAINING, as Substrate does when
// the pool replaces it.
func (w *workerCluster) drain(t *testing.T, a *ateapi.Actor) string {
	t.Helper()
	got, err := w.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
	if err != nil {
		t.Fatal(err)
	}
	asg := got.GetStatus().GetWorkerAssignment()
	if asg.GetWorkerPod() == "" {
		t.Fatalf("actor %s has no worker", got.GetMetadata().GetName())
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.workers = append(w.workers, &pb.Worker{Metadata: &pb.ResourceMetadata{Name: "w-" + asg.GetWorkerPod()},
		WorkerNamespace: asg.GetWorkerNamespace(), WorkerPod: asg.GetWorkerPod(),
		Status: &pb.WorkerStatus{State: pb.WorkerState_WORKER_STATE_DRAINING}})
	return asg.GetWorkerPod()
}

func drainRig(t *testing.T) (*rig, *workerCluster) {
	t.Helper()
	var wc *workerCluster
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		wc = &workerCluster{Fake: o.Client.(*ateapifake.Fake)}
		o.Client = wc
	})
	return r, wc
}

func TestGAP0449RunningActorIsMovedOffADrainingWorker(t *testing.T) {
	r, wc := drainRig(t)
	moved := running(t, r, "alice-g449", "sub-alice")
	stays := running(t, r, "bob-g449", "sub-bob")
	ref := ateapi.RefOf(moved.GetMetadata())
	r.pass()
	oldPod := wc.drain(t, moved)
	suspends := r.api.Calls("SuspendActor")
	r.pass()
	if got := r.api.Calls("SuspendActor") - suspends; got != 1 {
		t.Fatalf("SuspendActor calls after the drain = %d, want 1 (only the actor on the draining worker): it would crash when the worker stops", got)
	}
	a, _ := r.api.GetActor(context.Background(), ref)
	if a.GetStatus().GetState() != ateapi.ActorStateSuspended {
		t.Fatalf("actor on the draining worker is %s, want SUSPENDED", a.GetStatus().GetState())
	}
	if evs := r.sink.Events("sandbox.worker_drain.suspend"); len(evs) != 1 || evs[0].Actor != "alice-g449" {
		t.Fatalf("drain suspend events = %+v, want one for alice-g449", evs)
	}
	// The next pass resumes it, on another worker.
	r.pass()
	a, _ = r.api.GetActor(context.Background(), ref)
	if a.GetStatus().GetState() != ateapi.ActorStateRunning || a.GetStatus().GetWorkerAssignment().GetWorkerPod() == oldPod {
		t.Fatalf("after the move: %s on %q, want RUNNING on a worker other than %q", a.GetStatus().GetState(),
			a.GetStatus().GetWorkerAssignment().GetWorkerPod(), oldPod)
	}
	if len(r.sink.Events("sandbox.worker_drain.resume")) != 1 {
		t.Fatal("no drain resume event")
	}
	// It is not moved again, and the other actor was never touched.
	suspends = r.api.Calls("SuspendActor")
	r.pass()
	if got := r.api.Calls("SuspendActor") - suspends; got != 0 {
		t.Fatalf("SuspendActor calls once moved = %d, want 0", got)
	}
	b, _ := r.api.GetActor(context.Background(), ateapi.RefOf(stays.GetMetadata()))
	if b.GetStatus().GetState() != ateapi.ActorStateRunning {
		t.Fatalf("the actor on an active worker is %s, want RUNNING", b.GetStatus().GetState())
	}
}

// running places a new actor of person on a worker.
func running(t *testing.T, r *rig, name, person string) *ateapi.Actor {
	t.Helper()
	a := r.actor("eng-web", name, ateapi.ActorStateRunning, person)
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	return a
}

// A --task actor whose task already ended is only suspended, as its task-end
// suspend would be: resuming it would hold a worker for nothing.
func TestGAP0449EndedTaskIsSuspendedNotResumed(t *testing.T) {
	r, wc := drainRig(t)
	a := running(t, r, "ci-g449", "")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "ci-g449", UID: a.GetMetadata().GetUid(),
		Person: "sub-ci", Profile: "eng", Source: controller.SourceLauncher, Task: true}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	r.act.EndTask(a.GetMetadata().GetUid(), r.clk.Now())
	wc.drain(t, a)
	r.pass()
	r.pass()
	got, _ := r.api.GetActor(context.Background(), ref)
	if got.GetStatus().GetState() != ateapi.ActorStateSuspended || r.api.Calls("ResumeActor") != 0 {
		t.Fatalf("ended task on a draining worker: %s with %d resumes, want SUSPENDED and none", got.GetStatus().GetState(), r.api.Calls("ResumeActor"))
	}
}

// A task that ended before this controller first saw its actor run (a
// controller restart, or a short run) has ended too: the drain compares the
// end with the actor's last stop, as the task-end suspend does (GAP-0411).
// Compared with when the controller first saw it run, the drain resumed the
// finished task on a new worker, which then held that worker until an idle
// suspend.
func TestGAP0449TaskEndedBeforeTheControllerSawItIsNotResumed(t *testing.T) {
	r, wc := drainRig(t)
	a := running(t, r, "ci2-g449", "")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "ci2-g449", UID: a.GetMetadata().GetUid(),
		Person: "sub-ci", Profile: "eng", Source: controller.SourceLauncher, Task: true}); err != nil {
		t.Fatal(err)
	}
	r.act.EndTask(a.GetMetadata().GetUid(), r.clk.Now())
	r.clk.Add(time.Second)
	wc.drain(t, a)
	r.pass()
	r.pass()
	got, _ := r.api.GetActor(context.Background(), ref)
	if got.GetStatus().GetState() != ateapi.ActorStateSuspended || r.api.Calls("ResumeActor") != 0 {
		t.Fatalf("task that ended before the first pass, on a draining worker: %s with %d resumes, want SUSPENDED and none",
			got.GetStatus().GetState(), r.api.Calls("ResumeActor"))
	}
	if evs := r.sink.Events("sandbox.worker_drain.suspend"); len(evs) != 1 || evs[0].Detail["resume"] != false {
		t.Fatalf("drain suspend events = %+v, want one with resume false", evs)
	}
}

// A principal that may not list workers is told once what that costs.
func TestGAP0449WorkerListRefusedWarnsOnce(t *testing.T) {
	r, wc := drainRig(t)
	wc.err = status.Error(codes.PermissionDenied, "no global viewer")
	running(t, r, "alice-g449w", "sub-alice")
	r.pass()
	r.pass()
	n := 0
	for _, ev := range r.sink.Events(controller.EventWarning) {
		if strings.Contains(ev.Message, "cannot list Substrate workers") && strings.Contains(ev.Message, "worker pool roll") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("worker-list refusal warnings = %d, want 1", n)
	}
}
