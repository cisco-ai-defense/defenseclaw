// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// runRec is a lifecycle sink that also takes running reports.
type runRec struct {
	lifeRec
	rmu     sync.Mutex
	reports [][]string
	fail    bool
}

func (r *runRec) Running(_ context.Context, actors []chainstate.Actor) error {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	if r.fail {
		return errors.New("leader unreachable")
	}
	var uids []string
	for _, a := range actors {
		uids = append(uids, a.UID)
	}
	slices.Sort(uids)
	r.reports = append(r.reports, uids)
	return nil
}

func (r *runRec) got() [][]string {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	return slices.Clone(r.reports)
}

// substrate-1 GAP-0539: the controller tells the leader which actors it sees
// running, about once a minute, so a quiet running actor's chain window runs
// on wall time. Only RUNNING actors are named; a failed report warns once.
func TestGAP0539ControllerReportsRunningActors(t *testing.T) {
	life := &runRec{}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Lifecycle = life })
	run := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	r.actor("eng-web", "alice-2", ateapi.ActorStateSuspended, "sub-alice")
	r.pass()
	want := []string{run.GetMetadata().GetUid()}
	if got := life.got(); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("first pass reports %v, want one report of %v", got, want)
	}
	r.clk.Add(10 * time.Second)
	r.pass()
	if got := life.got(); len(got) != 1 {
		t.Fatalf("a report every pass: %v", got)
	}
	r.clk.Add(time.Minute)
	r.pass()
	if got := life.got(); len(got) != 2 || !slices.Equal(got[1], want) {
		t.Fatalf("after a minute: %v", got)
	}
	// The running actor suspends: it is no longer reported.
	if err := r.api.SetState(ateapi.RefOf(run.GetMetadata()), ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(time.Minute)
	r.pass()
	if got := life.got(); len(got) != 2 {
		t.Fatalf("a report with no running actor: %v", got)
	}
	// A failed report warns once.
	if err := r.api.SetState(ateapi.RefOf(run.GetMetadata()), ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	life.rmu.Lock()
	life.fail = true
	life.rmu.Unlock()
	before := len(r.sink.Events())
	for i := 0; i < 3; i++ {
		r.clk.Add(time.Minute)
		r.pass()
	}
	warned := 0
	for _, ev := range r.sink.Events()[before:] {
		if ev.Type == controller.EventWarning && ev.Severity == controller.SeverityWarn && strings.HasPrefix(ev.Message, "the leader did not take the report of running actors") {
			warned++
		}
	}
	if warned != 1 {
		t.Fatalf("%d running-report warnings for 3 failed reports, want 1", warned)
	}
}
