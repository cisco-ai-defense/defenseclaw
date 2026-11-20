// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-1591. The gateway's read-loop log drainer (readloop_log.go) is one
// goroutine for the whole process and reads os.Stderr for every line. A test
// that swaps os.Stderr while that goroutine is alive writes a variable it
// reads, which the race detector reports as a DATA RACE (and it did, in
// TestOfflineBundleDigestDoesNotReadTargetPolicyDir, under load).
//
// So no test swaps os.Stderr. TestMain points it once, before any goroutine
// starts, at a pipe whose reader copies to the real stderr; captureStderr
// only switches where that reader sends the bytes, under a mutex. A flush
// marker written to the pipe tells the capture that every byte written
// before it has been delivered.
type stderrTee struct {
	mu     sync.Mutex // guards sink, marker, marked and the writes to real
	capMu  sync.Mutex // one capture at a time
	sink   *bytes.Buffer
	marker []byte
	marked chan struct{}
	real   *os.File
	w      *os.File
	seq    atomic.Int64
}

var stderrTeeForTests *stderrTee

// installStderrTee must run first in TestMain, before the tests start any
// goroutine that reads os.Stderr.
func installStderrTee() error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	c := &stderrTee{real: os.Stderr, w: w}
	os.Stderr = w
	stderrTeeForTests = c
	go c.pump(r)
	return nil
}

func (c *stderrTee) deliverLocked(b []byte) {
	if len(b) == 0 {
		return
	}
	if c.sink != nil {
		c.sink.Write(b)
		return
	}
	_, _ = c.real.Write(b)
}

func (c *stderrTee) pump(r *os.File) {
	buf := make([]byte, 32<<10)
	var acc []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			c.mu.Lock()
			acc = append(acc, buf[:n]...)
			for len(acc) > 0 {
				if c.marker == nil {
					c.deliverLocked(acc)
					acc = acc[:0]
					break
				}
				if i := bytes.Index(acc, c.marker); i >= 0 {
					c.deliverLocked(acc[:i])
					acc = acc[i+len(c.marker):]
					close(c.marked)
					c.marker, c.marked = nil, nil
					continue
				}
				// Hold back what could be the start of the marker.
				keep := min(len(c.marker)-1, len(acc))
				c.deliverLocked(acc[:len(acc)-keep])
				acc = append(acc[:0], acc[len(acc)-keep:]...)
				break
			}
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// flush returns once every byte written to os.Stderr before the call has been
// delivered (to the capture, or to the real stderr).
func (c *stderrTee) flush() error {
	marker := []byte(fmt.Sprintf("\x00dc-stderr-flush-%d\x00", c.seq.Add(1)))
	marked := make(chan struct{})
	c.mu.Lock()
	c.marker, c.marked = marker, marked
	c.mu.Unlock()
	if _, err := c.w.Write(marker); err != nil {
		return err
	}
	select {
	case <-marked:
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("stderr tee: flush marker not seen in 30 s")
	}
}

// captureStderr returns what the process wrote to os.Stderr while fn ran: its
// own writes and those of any goroutine still logging (the read-loop drainer).
// Used to assert on the operator-facing log lines emitted by proxy helpers.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	c := stderrTeeForTests
	if c == nil {
		t.Fatal("captureStderr: TestMain did not install the stderr tee")
	}
	c.capMu.Lock()
	defer c.capMu.Unlock()
	sink := &bytes.Buffer{}
	c.mu.Lock()
	c.sink = sink
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.sink = nil
		c.mu.Unlock()
	}()
	fn()
	if err := c.flush(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return sink.String()
}
