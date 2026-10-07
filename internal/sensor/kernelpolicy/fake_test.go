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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	// The suite does not run as root; a pause is normally accepted from root
	// alone. One test puts the real check back.
	pauseFileTrusted = func(fs.FileInfo) bool { return true }
}

// fakeTetragon behaves like the FineGuidanceSensors calls the controller
// uses: a duplicate name is refused, the mode comes from the policy YAML,
// and a restart drops every policy added over gRPC.
type fakeTetragon struct {
	mu       sync.Mutex
	agent    Agent
	policies map[string]*LoadedPolicy
	calls    []string
	failAdd  map[string]bool
	failAll  bool
	// onList runs at the start of ListTracingPolicies.
	onList func()
	// allowed, when set, makes any other call a test failure.
	allowed map[string]bool
	t       *testing.T
}

func newFakeTetragon(t *testing.T) *fakeTetragon {
	return &fakeTetragon{
		t: t, policies: map[string]*LoadedPolicy{}, failAdd: map[string]bool{},
		agent: Agent{Version: "1.7.1", PID: 4242, LSMKnown: true, LSM: true,
			KeepSensorsOnExitKnown: true, KeepSensorsOnExit: false},
	}
}

func (f *fakeTetragon) record(call, rpc string) error {
	f.calls = append(f.calls, call)
	if f.allowed != nil && !f.allowed[rpc] {
		f.t.Errorf("call %s is outside the allowlist", call)
		return fmt.Errorf("call %s not allowed", call)
	}
	return nil
}

func (f *fakeTetragon) Agent(context.Context) (Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("agent", RPCAgent); err != nil {
		return Agent{}, err
	}
	return f.agent, nil
}

func (f *fakeTetragon) ListTracingPolicies(context.Context) ([]LoadedPolicy, error) {
	if f.onList != nil {
		f.onList()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("list", RPCList); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.policies))
	for name := range f.policies {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]LoadedPolicy, 0, len(names))
	for _, name := range names {
		out = append(out, *f.policies[name])
	}
	return out, nil
}

func (f *fakeTetragon) AddTracingPolicy(_ context.Context, yaml []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	tp, err := decodePolicy(stripComments(yaml))
	if err != nil {
		return err
	}
	name := tp.Metadata.Name
	if err := f.record("add:"+name, RPCAdd); err != nil {
		return err
	}
	if f.failAll || f.failAdd[name] {
		return errors.New("injected add failure")
	}
	if _, dup := f.policies[name]; dup {
		return fmt.Errorf("tracing policy %s already exists", name)
	}
	mode := LoadedEnforce // Tetragon's default when the policy says nothing
	for _, option := range tp.Spec.Options {
		if option.Name == modeOption && option.Value == "monitor" {
			mode = LoadedMonitor
		}
	}
	f.policies[name] = &LoadedPolicy{Name: name, Mode: mode, State: StateEnabled}
	f.calls[len(f.calls)-1] += ":" + string(mode)
	return nil
}

func (f *fakeTetragon) DeleteTracingPolicy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("delete:"+name, RPCDelete); err != nil {
		return err
	}
	if _, ok := f.policies[name]; !ok {
		return fmt.Errorf("tracing policy %s does not exist", name)
	}
	delete(f.policies, name)
	return nil
}

func (f *fakeTetragon) ConfigureTracingPolicy(_ context.Context, name string, mode PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("configure:"+name+":"+string(mode), RPCConfigure); err != nil {
		return err
	}
	p, ok := f.policies[name]
	if !ok {
		return fmt.Errorf("tracing policy %s does not exist", name)
	}
	p.Mode = LoadedMonitor
	if mode == PolicyEnforce {
		p.Mode = LoadedEnforce
	}
	return nil
}

// restart drops every policy and gives Tetragon a new pid.
func (f *fakeTetragon) restart() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies = map[string]*LoadedPolicy{}
	f.agent.PID++
}

func (f *fakeTetragon) setMode(name string, mode LoadedMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[name].Mode = mode
}

func (f *fakeTetragon) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, name)
}

func (f *fakeTetragon) addForeign(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[name] = &LoadedPolicy{Name: name, Mode: LoadedEnforce, State: StateEnabled}
}

func (f *fakeTetragon) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.calls
	f.calls = nil
	return out
}

func (f *fakeTetragon) find(family Family) (LoadedPolicy, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, p := range f.policies {
		if got, _ := FamilyOfName(name); got == family {
			return *p, true
		}
	}
	return LoadedPolicy{}, false
}

func (f *fakeTetragon) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for name := range f.policies {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// harness is a Controller over a fake Tetragon, an in-memory world and a
// clock the test moves.
type harness struct {
	t      *testing.T
	dirs   Dirs
	tg     *fakeTetragon
	w      *world
	ctl    *Controller
	now    time.Time
	procs  []Proc
	intent Intent
}

func newHarness(t *testing.T, intent Intent, targets string) *harness {
	t.Helper()
	base := t.TempDir()
	h := &harness{
		t:    t,
		dirs: Dirs{State: filepath.Join(base, "state"), Run: filepath.Join(base, "run")},
		tg:   newFakeTetragon(t),
		w:    newWorld(t, targets),
		now:  time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
	}
	h.start(intent)
	return h
}

// start creates (or re-creates, as after a helper restart) the controller
// from whatever is on disk.
func (h *harness) start(intent Intent) {
	if h.ctl != nil {
		// A graceful stop writes the burn-in evidence and the state.
		h.ctl.flush()
		h.ctl.persist()
	}
	h.intent = intent
	h.ctl = New(Config{
		Intent:        intent,
		Dirs:          h.dirs,
		Dial:          func(context.Context) (Client, func(), error) { return h.tg, func() {}, nil },
		Enrollment:    func() (Enrollment, error) { return h.w.enroll, nil },
		FS:            h.w.fs,
		Procs:         func(func(int) bool) ([]Proc, error) { return h.procs, nil },
		ExtraPrefixes: []string{"/opt/agents"},
		Now:           func() time.Time { return h.now },
		Intervals:     Intervals{Call: 5 * time.Second, Reconcile: 20 * time.Millisecond, Lock: 5 * time.Millisecond},
	})
}

func (h *harness) pass() {
	h.t.Helper()
	h.ctl.pass(context.Background(), "test")
}

func (h *harness) status() State { return h.ctl.Status() }

func (h *harness) has(warning string) bool {
	for _, w := range h.status().Warnings {
		if w == warning || strings.HasPrefix(w, warning+":") {
			return true
		}
	}
	return false
}

// burnedIn gives uid the covered time it needs.
func (h *harness) burnedIn(uid int, d time.Duration) {
	h.ctl.tallyMu.Lock()
	h.ctl.burn.Sync(Digest(), h.w.enroll, h.now)
	h.ctl.burn.Accrue(uid, d)
	h.ctl.tallyMu.Unlock()
}

func (h *harness) accrueTick() {
	h.ctl.SetStream(true)
	h.ctl.accrue() // consumes the stream-change loss flag
	h.ctl.accrue()
}

func enforceIntent(ack string, connectors ...string) Intent {
	if len(connectors) == 0 {
		connectors = []string{"claudecode", "codex"}
	}
	return Intent{Mode: ModeEnforce, BurnIn: 24 * time.Hour, EnforceAck: ack, EnforceConnectors: connectors}
}

func observeIntent() Intent { return Intent{Mode: ModeObserve, BurnIn: 24 * time.Hour} }

func (h *harness) pause(d time.Duration) {
	h.t.Helper()
	p, err := NewPause(h.now, d, false, 0, "test")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := WritePause(h.dirs, p); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) resume() {
	h.t.Helper()
	if err := ClearPause(h.dirs); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) loadedFile() []string {
	names, err := readLoaded(h.dirs)
	if err != nil {
		h.t.Fatal(err)
	}
	return names
}

func (h *harness) writeRaw(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func indexOf(calls []string, prefix string) int {
	for i, call := range calls {
		if strings.HasPrefix(call, prefix) {
			return i
		}
	}
	return -1
}

func countCalls(calls []string, prefix string) int {
	n := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			n++
		}
	}
	return n
}
