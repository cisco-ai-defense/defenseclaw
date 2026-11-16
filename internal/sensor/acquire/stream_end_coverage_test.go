// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// cowork-1-0-8 GAP-0080: an event stream ends with its coverage. The
// losses the helper's source counted after the last coverage frame (sent
// every coverageRefresh, and only when it changed) went with a helper that
// stopped (a package upgrade, a config push) or a source that ended; the
// gateway carries only the losses it was told. Now the last frame names
// them, before the source closes.
func TestAnEndingEventStreamSendsItsLastCoverage(t *testing.T) {
	for _, end := range []string{"the helper stops", "the source ends"} {
		t.Run(end, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "acq")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "s")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Skipf("unix sockets unavailable here: %v", err)
			}
			stub := newStubSource(tetragonCoverage())
			server := NewServer(ServerConfig{})
			server.acquirer = stubAcquirer{stub}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = server.Serve(ctx, listener) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("helper did not stop")
				}
			})

			source := NewHelper(socket).PlaneSource(nil)
			if err := source.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			// Counted after the stream's first coverage frame, with no change
			// notice, as the buffers and the Tetragon session count them.
			counted := plane.WithBufferDrops(plane.WithKernelOverflows(tetragonCoverage(), 2), 3, plane.SensorEventBuffer)
			counted.Backend.EventsLost = 7
			stub.mu.Lock()
			stub.cov = counted
			stub.mu.Unlock()
			if end == "the helper stops" {
				cancel()
			} else {
				_ = stub.Close()
			}
			deadline := time.After(10 * time.Second)
			for open := true; open; {
				select {
				case _, open = <-source.Events():
				case <-deadline:
					t.Fatal("the event stream did not end")
				}
			}
			if got := source.Coverage().Losses(); got != (plane.Losses{BufferDropped: 3, KernelOverflows: 2, BackendLost: 7}) {
				t.Fatalf("losses the gateway was told = %+v, want the helper's last 3 drops, 2 overflows and 7 lost", got)
			}
		})
	}
}

// writeFailingConn takes the first ok writes and fails every one after
// them, as a stream whose gateway stopped reading does at its deadline.
type writeFailingConn struct {
	net.Conn
	mu     sync.Mutex
	ok     int
	writes int
}

func (c *writeFailingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes > c.ok {
		return 0, errors.New("write: broken pipe")
	}
	return len(p), nil
}

func (c *writeFailingConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// cowork-1-0-8 GAP-0080 review L1: a stream whose frame write failed still
// tried its last coverage frame, after the part of the failed frame that
// went out; the gateway failed the decode and the teardown waited up to the
// final frame's deadline. A broken stream is not written to again.
func TestABrokenEventStreamSendsNoLastCoverage(t *testing.T) {
	helperEnd, gatewayEnd := net.Pipe()
	defer gatewayEnd.Close()
	conn := &writeFailingConn{Conn: helperEnd, ok: 2} // the coverage header frame: length, then payload
	stub := newStubSource(tetragonCoverage())
	server := NewServer(ServerConfig{})
	server.acquirer = stubAcquirer{stub}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serveEvents(context.Background(), conn, Request{Version: protocolVersion, Op: OpEvents})
	}()
	waitUntil := time.Now().Add(5 * time.Second)
	for conn.count() < 2 {
		if time.Now().After(waitUntil) {
			t.Fatal("the stream sent no coverage header")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A changed coverage, so a last frame would go out; then an event whose
	// frame write fails.
	counted := plane.WithBufferDrops(tetragonCoverage(), 3, plane.SensorEventBuffer)
	stub.mu.Lock()
	stub.cov = counted
	stub.mu.Unlock()
	stub.events <- plane.Event{Kind: plane.KindExec, PID: 42}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stream did not end after a failed write")
	}
	if got := conn.count(); got != 3 {
		t.Fatalf("writes on the stream = %d, want 3: the header frame's two and the failed one, no last frame after it", got)
	}
}
