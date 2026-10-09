// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	oursObserve  = "defenseclaw-observe-aaaaaaaa"
	oursControls = "defenseclaw-controls-bbbbbbbb"
	lookalike    = "defenseclaw-controls-cccccccc" // shaped like ours, never recorded
)

func cleanupFixture(t *testing.T) (*fakeTetragon, Dirs) {
	t.Helper()
	tg := newFakeTetragon(t)
	dirs := Dirs{State: t.TempDir(), Run: t.TempDir()}
	for _, name := range []string{oursObserve, oursControls, lookalike, "customer-tcp-policy", "defenseclaw-observe-ZZZZZZZZ"} {
		tg.addForeign(name)
	}
	// The record holds two real names and two lines no helper would write.
	if err := os.WriteFile(dirs.Loaded(), []byte(oursObserve+"\n"+oursControls+"\ncustomer-tcp-policy\n../../etc/passwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return tg, dirs
}

func TestCleanupDeletesOnlyRecordedPatternNames(t *testing.T) {
	tg, dirs := cleanupFixture(t)
	tg.allowed = map[string]bool{RPCList: true, RPCDelete: true}
	result, err := Cleanup(context.Background(), tg, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Removed, []string{oursControls, oursObserve}) {
		t.Fatalf("removed = %v", result.Removed)
	}
	if !reflect.DeepEqual(result.Foreign, []string{lookalike}) {
		t.Fatalf("foreign = %v; a name with the shape and no record is reported, never deleted", result.Foreign)
	}
	if got := strings.Join(tg.names(), ","); got != "customer-tcp-policy,"+lookalike+",defenseclaw-observe-ZZZZZZZZ" {
		t.Fatalf("remaining = %s", got)
	}
	deletes := 0
	for _, call := range tg.take() {
		if strings.HasPrefix(call, "delete:") {
			deletes++
		}
	}
	if deletes != 2 {
		t.Fatalf("%d deletes", deletes)
	}
	if names, _ := readLoaded(dirs); len(names) != 0 {
		t.Fatalf("record after cleanup = %v", names)
	}
}

func TestCleanupKeepsWhatItCouldNotDelete(t *testing.T) {
	tg, dirs := cleanupFixture(t)
	wrapped := &failingDelete{Client: tg, fail: oursControls}
	result, err := Cleanup(context.Background(), wrapped, dirs)
	if err == nil || !reflect.DeepEqual(result.Kept, []string{oursControls}) || !reflect.DeepEqual(result.Removed, []string{oursObserve}) {
		t.Fatalf("result %+v err %v", result, err)
	}
	if names, _ := readLoaded(dirs); !reflect.DeepEqual(names, []string{oursControls}) {
		t.Fatalf("the name that could not be deleted must stay recorded: %v", names)
	}
}

type failingDelete struct {
	Client
	fail string
}

func (f *failingDelete) DeleteTracingPolicy(ctx context.Context, name string) error {
	if name == f.fail {
		return errors.New("injected delete failure")
	}
	return f.Client.DeleteTracingPolicy(ctx, name)
}

func TestCleanupTreatsAGoneNameAsRetired(t *testing.T) {
	tg, dirs := cleanupFixture(t)
	tg.remove(oursControls) // Tetragon restarted and dropped it
	result, err := Cleanup(context.Background(), tg, dirs)
	if err != nil || !reflect.DeepEqual(result.Missing, []string{oursControls}) || !reflect.DeepEqual(result.Removed, []string{oursObserve}) {
		t.Fatalf("result %+v err %v", result, err)
	}
	if names, _ := readLoaded(dirs); len(names) != 0 {
		t.Fatalf("record = %v", names)
	}
}

func TestCleanupWithTetragonDownKeepsTheRecord(t *testing.T) {
	_, dirs := cleanupFixture(t)
	down := &downClient{}
	if _, err := Cleanup(context.Background(), down, dirs); err == nil {
		t.Fatal("expected an error")
	}
	if names, _ := readLoaded(dirs); len(names) != 2 {
		t.Fatalf("record = %v; it must survive a failed cleanup", names)
	}
}

type downClient struct{}

func (downClient) Agent(context.Context) (Agent, error) { return Agent{}, errors.New("down") }
func (downClient) ListTracingPolicies(context.Context) ([]LoadedPolicy, error) {
	return nil, errors.New("down")
}
func (downClient) AddTracingPolicy(context.Context, []byte) error    { return errors.New("down") }
func (downClient) DeleteTracingPolicy(context.Context, string) error { return errors.New("down") }
func (downClient) ConfigureTracingPolicy(context.Context, string, PolicyMode) error {
	return errors.New("down")
}

func TestCleanupPublishesTheRetirement(t *testing.T) {
	h := enforcing(t)
	if _, err := Cleanup(context.Background(), h.tg, h.dirs); err != nil {
		t.Fatal(err)
	}
	state, err := ReadState(h.dirs)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Loaded) != 0 || len(state.Policies) != 0 || len(state.Applied) != 0 {
		t.Fatalf("state after cleanup: loaded %v policies %v applied %v", state.Loaded, state.Policies, state.Applied)
	}
	if len(h.tg.names()) != 0 {
		t.Fatalf("still loaded: %v", h.tg.names())
	}
}

func TestAllowedRPCsPerMode(t *testing.T) {
	want := map[Mode][]string{
		ModeOff:     {RPCList, RPCDelete},
		ModeConsume: {RPCAgent, RPCList, RPCDelete},
		ModeObserve: {RPCAgent, RPCList, RPCAdd, RPCDelete, RPCConfigure},
		ModeEnforce: {RPCAgent, RPCList, RPCAdd, RPCDelete, RPCConfigure},
	}
	for mode, rpcs := range want {
		if got := AllowedRPCs(mode); !reflect.DeepEqual(got, rpcs) {
			t.Errorf("AllowedRPCs(%s) = %v, want %v", mode, got, rpcs)
		}
	}
	if AllowedRPCs("bogus") != nil {
		t.Error("an unknown mode may call nothing")
	}
}

func TestGuardRefusesCallsOutsideTheModeAndUnrecordedNames(t *testing.T) {
	tg := newFakeTetragon(t)
	recorded := func(name string) bool { return name == oursObserve }
	ctx := context.Background()
	for _, mode := range []Mode{ModeOff, ModeConsume} {
		g := guard(tg, mode, recorded)
		if err := g.AddTracingPolicy(ctx, []byte("x")); !errors.Is(err, ErrRPCNotAllowed) {
			t.Errorf("%s: add: %v", mode, err)
		}
		if err := g.ConfigureTracingPolicy(ctx, oursObserve, PolicyEnforce); !errors.Is(err, ErrRPCNotAllowed) {
			t.Errorf("%s: configure: %v", mode, err)
		}
	}
	if _, err := guard(tg, ModeOff, recorded).Agent(ctx); !errors.Is(err, ErrRPCNotAllowed) {
		t.Errorf("off must not even ask for the version: %v", err)
	}
	if _, err := guard(tg, ModeConsume, recorded).Agent(ctx); err != nil {
		t.Errorf("consume may ask for the version: %v", err)
	}
	g := guard(tg, ModeEnforce, recorded)
	tg.addForeign(oursObserve)
	tg.addForeign(lookalike)
	tg.addForeign("customer-policy")
	for _, name := range []string{lookalike, "customer-policy", "../x"} {
		if err := g.DeleteTracingPolicy(ctx, name); !errors.Is(err, ErrRPCNotAllowed) {
			t.Errorf("delete %q: %v", name, err)
		}
		if err := g.ConfigureTracingPolicy(ctx, name, PolicyMonitor); !errors.Is(err, ErrRPCNotAllowed) {
			t.Errorf("configure %q: %v", name, err)
		}
	}
	if err := g.DeleteTracingPolicy(ctx, oursObserve); err != nil {
		t.Errorf("a recorded name may be deleted: %v", err)
	}
}

// retireHarness has recorded policies and then starts in a mode that loads none.
func retireHarness(t *testing.T, mode Mode) *harness {
	t.Helper()
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	h.tg.addForeign("customer-tcp-policy")
	h.tg.addForeign(lookalike)
	h.tg.allowed = map[string]bool{RPCList: true, RPCDelete: true}
	if mode == ModeConsume {
		h.tg.allowed[RPCAgent] = true
	}
	h.start(Intent{Mode: mode, BurnIn: DefaultBurnIn})
	return h
}

func TestOffAndConsumeOnlyRetireRecordedNames(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModeConsume} {
		t.Run(string(mode), func(t *testing.T) {
			h := retireHarness(t, mode)
			h.tg.take()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.ctl.Run(ctx) }()
			if mode == ModeConsume {
				// Consume keeps publishing the stream's view after the retire.
				waitUntil(t, "the retire", func() bool { return len(h.loadedFile()) == 0 })
				cancel()
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(h.tg.names(), ","); got != "customer-tcp-policy,"+lookalike {
				t.Fatalf("remaining = %s", got)
			}
			if names := h.loadedFile(); len(names) != 0 {
				t.Fatalf("record = %v", names)
			}
			for _, call := range h.tg.take() {
				if !strings.HasPrefix(call, "list") && !strings.HasPrefix(call, "delete:") {
					t.Fatalf("mode %s made call %s", mode, call)
				}
			}
			if h.status().Effective != string(mode) {
				t.Fatalf("effective = %q", h.status().Effective)
			}
		})
	}
}

func TestRetireWaitsForTetragonThenNeverConnectsAgain(t *testing.T) {
	h := retireHarness(t, ModeOff)
	var down atomic.Bool
	down.Store(true)
	h.ctl.cfg.Dial = func(context.Context) (Client, func(), error) {
		if down.Load() {
			return nil, nil, errors.New("connection refused")
		}
		return h.tg, func() {}, nil
	}
	h.ctl.cfg.Intervals.Reconcile = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- h.ctl.Run(context.Background()) }()
	// A helper that cannot retire its policies must say so, and keep trying.
	// Wait for it rather than for a fixed time: a loaded host runs the first
	// attempt late.
	waitUntil(t, "the orphaned change and the tetragon_unavailable warning", func() bool {
		select {
		case err := <-done:
			t.Fatalf("Run returned %v with the record still holding names", err)
		default:
		}
		for _, ch := range h.status().Changes {
			if ch.Event == EventOrphaned {
				return h.has(WarnTetragonUnavailable)
			}
		}
		return false
	})
	down.Store(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the retire never completed")
	}
	if names := h.loadedFile(); len(names) != 0 {
		t.Fatalf("record = %v", names)
	}
	h.tg.take()
	// With the record empty a restarted helper in off mode makes no call at all.
	h.start(Intent{Mode: ModeOff})
	if err := h.ctl.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls := h.tg.take(); len(calls) != 0 {
		t.Fatalf("calls = %v; off never connects again", calls)
	}
}

// In consume the event stream is the helper's only session with Tetragon:
// the published state says what it says (reachable, version and pid, or the
// refused endpoint), and nothing a previous mode published survives.
func TestConsumePublishesWhatTheStreamSaysAboutTetragon(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	h.pass()
	h.ctl.warn(WarnReconcileFailed)
	h.ctl.persist()
	h.start(Intent{Mode: ModeConsume, BurnIn: DefaultBurnIn})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.ctl.Run(ctx) }()
	waitUntil(t, "the retire", func() bool { return len(h.loadedFile()) == 0 })
	if st := h.status(); h.has(WarnReconcileFailed) || st.Tetragon.Reachable || len(st.Policies) != 0 || len(st.UIDs) != 0 {
		t.Fatalf("observe's state survived the switch to consume: %+v", st.FileState)
	}

	h.ctl.NoteStream(StreamStatus{Reason: "tetragon_untrusted_endpoint: /var/run/tetragon is world-writable"})
	waitUntil(t, "the refused endpoint", func() bool { return h.has(WarnTetragonUnavailable) })
	if st := h.status().Tetragon; st.Reachable || !strings.HasPrefix(st.Reason, "tetragon_untrusted_endpoint:") {
		t.Fatalf("tetragon = %+v", st)
	}
	h.ctl.NoteStream(StreamStatus{Connected: true, Version: "v1.7.1", PID: 4242})
	waitUntil(t, "the stream", func() bool { return h.status().Tetragon.Reachable })
	file, err := ReadState(h.dirs)
	if err != nil {
		t.Fatal(err)
	}
	if file.Tetragon.Version != "v1.7.1" || file.Tetragon.PID != 4242 || !file.Tetragon.Reachable || h.has(WarnTetragonUnavailable) {
		t.Fatalf("the state file the root CLI reads: %+v %v", file.Tetragon, file.Warnings)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A retire that failed while Tetragon was down runs again as soon as the
// event stream connects, not a reconcile interval later.
func TestConsumeRetiresAsSoonAsTetragonIsBack(t *testing.T) {
	h := retireHarness(t, ModeConsume)
	h.ctl.cfg.Intervals.Reconcile = time.Hour
	var down atomic.Bool
	down.Store(true)
	h.ctl.cfg.Dial = func(context.Context) (Client, func(), error) {
		if down.Load() {
			return nil, nil, errors.New("connection refused")
		}
		return h.tg, func() {}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.ctl.Run(ctx) }()
	waitUntil(t, "the orphaned warning", func() bool { return h.has(WarnTetragonUnavailable) })
	down.Store(false)
	h.ctl.NoteStream(StreamStatus{Connected: true, Version: "v1.7.1"})
	waitUntil(t, "the retire", func() bool { return len(h.loadedFile()) == 0 })
	if h.has(WarnTetragonUnavailable) {
		t.Fatalf("warnings = %v", h.status().Warnings)
	}
	cancel()
	<-done
}
