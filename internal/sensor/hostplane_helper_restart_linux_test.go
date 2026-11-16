// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sensor

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

// restartFeed is a Tetragon session the test drives: Recv returns the
// batches sent to it, and recvs counts the calls, so the test knows a batch
// was handled once the next call began.
type restartFeed struct {
	batches chan plane.KernelBatch
	done    chan struct{}
	once    sync.Once
	recvs   atomic.Int64
}

func newRestartFeed() *restartFeed {
	return &restartFeed{batches: make(chan plane.KernelBatch, 8), done: make(chan struct{})}
}

func (f *restartFeed) Recv() (plane.KernelBatch, error) {
	f.recvs.Add(1)
	select {
	case batch := <-f.batches:
		return batch, nil
	case <-f.done:
		return plane.KernelBatch{}, errors.New("closed")
	}
}

func (f *restartFeed) Backend() plane.Backend {
	return plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1"}
}

func (f *restartFeed) Close() error { f.once.Do(func() { close(f.done) }); return nil }

// send hands the feed a batch and waits until the source handled it.
func (f *restartFeed) send(t *testing.T, batch plane.KernelBatch) {
	t.Helper()
	before := f.recvs.Load()
	f.batches <- batch
	deadline := time.Now().Add(10 * time.Second)
	for f.recvs.Load() <= before {
		if time.Now().After(deadline) {
			t.Fatal("the Tetragon source did not take the batch")
		}
		time.Sleep(time.Millisecond)
	}
}

// startHelperOn serves the real sensor helper on socket: a Tetragon source
// over feed, and status as its kernel_status. It returns the helper's stop.
func startHelperOn(t *testing.T, socket string, feed *restartFeed, status acquire.KernelStatus) (stop func()) {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	server := acquire.NewServer(acquire.ServerConfig{Tetragon: &acquire.TetragonConfig{
		Mode:         "consume",
		Dial:         func(context.Context) (plane.KernelFeed, error) { return feed, nil },
		KernelStatus: func(context.Context) (acquire.KernelStatus, error) { return status, nil },
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(ctx, listener) }()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the sensor helper did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

// cowork-1-0-8 GAP-0080, end to end: the real sensor helper streams a real
// Tetragon source (over a fake Tetragon session) to the real gateway client
// and Service, then restarts, as a package upgrade or a config push restarts
// it: a new helper on the same socket, with a new source and counters that
// begin again. What the gateway reports does not go back. events_lost keeps
// the first helper's losses, those it counted after its last coverage frame
// included, and adds the second's; the kernel controls' hour count takes
// the second helper's total from zero, although it already passed the
// first's.
func TestHostSensorCountsSurviveAHelperRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "g080")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	kernelStatus := func(blocked, since int64) acquire.KernelStatus {
		return acquire.KernelStatus{Available: true, Mode: "observe",
			Counters: map[string]int64{"blocked_total": blocked}, CountersEpoch: since}
	}
	firstFeed := newRestartFeed()
	stopFirst := startHelperOn(t, socket, firstFeed, kernelStatus(5, 100))

	helper := acquire.NewHelper(socket)
	service, err := New(Options{
		Config: config.AIRuntimeConfig{
			Enabled: true, Planes: []string{"a", "b", "c"}, EnableHostPlane: true, PollIntervalSec: 3600,
		},
		Providers:      testCatalog(),
		Platform:       allPlanesAvailable(),
		Resolver:       StaticResolver{Names: map[string]string{}},
		Acquirer:       helper,
		NewPlaneSource: helper.PlaneSource,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	defer func() { cancel(); <-done }()

	eventsLost := func() int64 {
		if backend := service.hostPlaneBackend(); backend != nil {
			return backend.EventsLost
		}
		return -1
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("%s; events lost %d", what, eventsLost())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("plane c never ran on the first helper", func() bool { return eventsLost() == 0 })
	service.refreshKernelState(ctx) // the first helper's counters: the baseline

	firstFeed.send(t, plane.KernelBatch{Dropped: 2})
	waitFor("the first helper's 2 losses never arrived", func() bool { return eventsLost() == 2 })
	// 3 more, and the helper stops before its next coverage frame.
	firstFeed.send(t, plane.KernelBatch{Dropped: 3})
	stopFirst()
	// The gateway reads the end of the stream on its own time: until then it
	// still shows the first helper's source.
	waitFor("the gateway did not see the first helper go", func() bool { return eventsLost() == -1 })

	secondFeed := newRestartFeed()
	startHelperOn(t, socket, secondFeed, kernelStatus(9, 200))
	waitFor("plane c did not come back on the second helper", func() bool { return eventsLost() >= 0 })
	if got := eventsLost(); got != 5 {
		t.Fatalf("events lost after the helper restart = %d, want the first helper's 5", got)
	}
	secondFeed.send(t, plane.KernelBatch{Dropped: 1})
	waitFor("the second helper's loss did not add to the first's", func() bool { return eventsLost() == 6 })

	service.refreshKernelState(ctx)
	service.mu.RLock()
	blocked := service.kernel.BlockedLastHour
	service.mu.RUnlock()
	if blocked != 9 {
		t.Fatalf("denials in the hour after the helper restart = %d, want the second helper's 9 counted from zero", blocked)
	}

	// The snapshot, which the plane_health telemetry is built from, says the same.
	service.Poll(ctx)
	for _, health := range service.Snapshot().Planes {
		if health.Plane == platform.PlaneC && (health.Backend == nil || health.Backend.EventsLost != 6) {
			t.Fatalf("plane c in the snapshot = %+v, want events lost 6", health)
		}
	}
}
