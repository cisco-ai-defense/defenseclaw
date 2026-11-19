// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// substrate-1:GAP-0449: verify warns while a worker pool roll still has
// actors running on the draining workers.
func TestGAP0449WorkerDrainCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		w      *WorkerDrain
		status string
		want   string
	}{
		{"not read", nil, Skip, "not read"},
		{"read failed", &WorkerDrain{Note: "no global viewer"}, Skip, "no global viewer"},
		{"no roll", &WorkerDrain{}, Pass, "no worker is draining"},
		{"roll, nothing left", &WorkerDrain{Draining: 2}, Pass, "no actor runs on them"},
		{"roll with actors", &WorkerDrain{Draining: 2, RunningOn: 3}, Warn, "still run 3 actor(s)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := CheckWorkerDrainRunning(Observed{WorkerDrain: tc.w})
			if c.ID != CheckWorkerDrain || c.Status != tc.status || !strings.Contains(c.Message, tc.want) {
				t.Fatalf("check = %+v, want %s with %q", c, tc.status, tc.want)
			}
		})
	}
}

type workerPages []*pb.Worker

func (w workerPages) ListWorkers(_ context.Context, o ateapi.ListOptions) (ateapi.Page[*pb.Worker], error) {
	if o.PageToken == "" {
		return ateapi.Page[*pb.Worker]{Items: w[:1], NextPageToken: "p2"}, nil
	}
	return ateapi.Page[*pb.Worker]{Items: w[1:]}, nil
}

// The draining set matches an actor by its Worker name or by its worker pod,
// across pages, and leaves active workers out.
func TestGAP0449DrainingWorkersMatchesNameOrPod(t *testing.T) {
	ws := workerPages{
		{Metadata: &pb.ResourceMetadata{Name: "old-1"}, WorkerNamespace: "dc-workers", WorkerPod: "gv-old-1",
			Status: &pb.WorkerStatus{State: pb.WorkerState_WORKER_STATE_DRAINING}},
		{Metadata: &pb.ResourceMetadata{Name: "new-1"}, WorkerNamespace: "dc-workers", WorkerPod: "gv-new-1",
			Status: &pb.WorkerStatus{State: pb.WorkerState_WORKER_STATE_ACTIVE}},
		{Metadata: &pb.ResourceMetadata{Name: "old-2"}, WorkerNamespace: "dc-workers", WorkerPod: "gv-old-2",
			Status: &pb.WorkerStatus{State: pb.WorkerState_WORKER_STATE_DRAINING}},
	}
	d, err := ateapi.DrainingWorkers(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	on := func(name, ns, pod string) *ateapi.Actor {
		asg := &pb.WorkerAssignment{WorkerNamespace: ns, WorkerPod: pod}
		if name != "" {
			asg.Worker = &pb.ObjectRef{Name: name}
		}
		return &ateapi.Actor{Status: &pb.ActorStatus{State: pb.ActorState_ACTOR_STATE_RUNNING, WorkerAssignment: asg}}
	}
	for _, tc := range []struct {
		a    *ateapi.Actor
		want bool
	}{
		{on("old-1", "dc-workers", "gv-old-1"), true},
		{on("", "dc-workers", "gv-old-2"), true},
		{on("new-1", "dc-workers", "gv-new-1"), false},
		{on("", "other", "gv-old-1"), false},
		{&ateapi.Actor{Status: &pb.ActorStatus{State: pb.ActorState_ACTOR_STATE_SUSPENDED}}, false},
	} {
		if _, got := d.Hosts(tc.a); got != tc.want {
			t.Errorf("Hosts(%v) = %v, want %v", tc.a.GetStatus().GetWorkerAssignment(), got, tc.want)
		}
	}
}
