// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

// streamSource is a source whose stream the test ends, the way a restart of
// the sensor helper ends the broker stream.
type streamSource struct {
	buffer   *plane.Buffer
	startErr error
	script   []plane.Event
	closed   atomic.Int32
}

func newStream(script ...plane.Event) *streamSource {
	return &streamSource{buffer: plane.NewBuffer(), script: script}
}

func (s *streamSource) Start(context.Context) error {
	if s.startErr != nil {
		return s.startErr
	}
	for _, event := range s.script {
		s.buffer.Push(event)
	}
	return nil
}
func (s *streamSource) Events() <-chan plane.Event { return s.buffer.Events() }
func (s *streamSource) Coverage() plane.Coverage   { return fullCoverage() }
func (s *streamSource) Close() error               { s.closed.Add(1); return nil }

func unreachableHelper() *streamSource {
	source := newStream()
	source.startErr = fmt.Errorf("%w at /run/defenseclaw-sensor/helper.sock: connect: connection refused", acquire.ErrHelperUnreachable)
	return source
}

// brokeredWith is a managed gateway whose sensor helper hands out the given
// sources, one per subscription, in order; the last one repeats.
func brokeredWith(t *testing.T, sources ...*streamSource) (*Service, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	now := time.Unix(1_760_000_000, 0)
	service, err := New(Options{
		Config:    config.AIRuntimeConfig{Enabled: true, EnableHostPlane: true},
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  StaticResolver{Names: map[string]string{}},
		Acquirer:  &kernelAcquirer{source: sources[0]},
		NewPlaneSource: func([]string) plane.Source {
			n := int(calls.Add(1)) - 1
			if n >= len(sources) {
				n = len(sources) - 1
			}
			return sources[n]
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	service.hostPlane.reattachDelay = time.Millisecond
	return service, &calls
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !done() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func planeC(service *Service) (bool, string) {
	running, _, reason := service.hostPlaneHealth(platform.Capability{})
	return running, reason
}

// GAP-0051: a restart of the sensor helper (a crash under Restart=always,
// or the printed fix) ended the broker stream, and the gateway never
// subscribed again: Plane C stayed down until the gateway restarted too.
func TestBrokeredPlaneReattachesAfterTheHelperRestarts(t *testing.T) {
	t.Parallel()
	first := newStream(plane.Event{Kind: plane.KindExec, PID: 10, PPID: 1, Name: "bash"})
	second := newStream(plane.Event{Kind: plane.KindExec, PID: 11, PPID: 1, Name: "bash"})
	service, calls := brokeredWith(t, first, unreachableHelper(), second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.startHostPlane(ctx)
	waitFor(t, "the first stream's event", func() bool { return service.hostPlane.handled.Load() >= 1 })

	first.buffer.Close() // the helper restarts
	waitFor(t, "the second stream's event", func() bool { return service.hostPlane.handled.Load() >= 2 })
	if running, reason := planeC(service); !running || reason != "" {
		t.Fatalf("after re-attaching: running=%v reason=%q", running, reason)
	}
	// One subscription at New, one the helper refused while it restarted,
	// one that worked.
	if got := calls.Load(); got != 3 {
		t.Fatalf("%d subscriptions, want 3", got)
	}
	if first.closed.Load() == 0 {
		t.Fatal("the ended stream's source was not closed")
	}
	_ = service.hostPlane.close()
	if second.closed.Load() == 0 {
		t.Fatal("close did not reach the re-attached source")
	}
}

// While the helper does not answer, health says Plane C is down, that the
// gateway is re-attaching and why the last try failed.
func TestPlaneCDownWhileTheHelperDoesNotAnswer(t *testing.T) {
	t.Parallel()
	first := newStream()
	service, calls := brokeredWith(t, first, unreachableHelper())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.startHostPlane(ctx)
	waitFor(t, "the plane to run", func() bool { running, _ := planeC(service); return running })
	first.buffer.Close()
	waitFor(t, "a failed re-attach", func() bool { return calls.Load() >= 3 })
	running, reason := planeC(service)
	if running || !strings.Contains(reason, "stopped delivering") ||
		!strings.Contains(reason, "re-attaching to the sensor helper (last try: acquire: dial helper") {
		t.Fatalf("while the helper is down: running=%v reason=%q", running, reason)
	}
	cancel()
	_ = service.hostPlane.close()
}

// A local source has nothing that restarts it: its end stays reported.
func TestLocalPlaneDoesNotReattach(t *testing.T) {
	t.Parallel()
	source := newStream()
	host := newHost(source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	source.buffer.Close()
	service := &Service{hostPlane: host}
	waitFor(t, "the plane to stop", func() bool { running, _ := planeC(service); return !running })
	if _, reason := planeC(service); reason != "the kernel event source stopped delivering" {
		t.Fatalf("reason = %q", reason)
	}
}
