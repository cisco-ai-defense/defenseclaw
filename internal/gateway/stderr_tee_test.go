// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-1591, GAP-1602. The gateway's read-loop log drainer (readloop_log.go)
// is one goroutine for the whole process and reads os.Stderr for every line.
// A test that swaps os.Stderr while that goroutine is alive writes a variable
// it reads, which the race detector reports as a DATA RACE (and it did, in
// TestOfflineBundleDigestDoesNotReadTargetPolicyDir, under load).
//
// So no test swaps os.Stderr. TestMain points it once, before any goroutine
// starts, at a pipe whose reader copies to the real stream; captureStderr
// only switches where that reader sends the bytes, under a mutex. A flush
// marker written to the pipe tells the capture that every byte written
// before it has been delivered.
//
// Under -test.v=test2json (go test -json: the CI race and plain shards, and
// the native Windows harness) testing.M.Run sets os.Stderr = os.Stdout after
// TestMain (go.dev/issue/33419), so a tee on os.Stderr would never see a
// byte (GAP-1612). There TestMain points os.Stdout at the tee instead, and
// M.Run's own assignment makes os.Stderr the tee too, still before any test
// runs. Test2json's events then pass through the tee as well: a capture
// copies them on to the real stdout, so test2json reads every event in
// order, and leaves the framed (^V) event lines out of what it returns.
type stderrTee struct {
	mu     sync.Mutex // guards sink, marker, marked and the writes to real
	capMu  sync.Mutex // one capture at a time
	sink   *bytes.Buffer
	marker []byte
	marked chan struct{}
	real   *os.File
	w      *os.File
	seq    atomic.Int64
	// stdout: the tee is os.Stdout (and, from M.Run on, os.Stderr); what a
	// capture takes still goes on to real, the stream test2json reads.
	stdout bool
}

var stderrTeeForTests *stderrTee

// test2jsonFrame starts the lines testing writes for test2json (=== RUN,
// --- PASS, ...) under -test.v=test2json.
const test2jsonFrame = byte(0x16)

// stderrTestingRedirects reports whether testing.M.Run will point os.Stderr
// at os.Stdout (-test.v=test2json). The flags must be parsed.
func stderrTestingRedirects() bool {
	f := flag.Lookup("test.v")
	return f != nil && f.Value.String() == "test2json"
}

// setUpStderrCapture must run first in TestMain, before the tests start any
// goroutine that reads os.Stderr. It parses the flags.
func setUpStderrCapture() error {
	if !flag.Parsed() {
		flag.Parse()
	}
	return installStderrTee(stderrTestingRedirects())
}

// flushStderrCapture delivers what the tee still holds.
func flushStderrCapture() {
	if stderrTeeForTests != nil {
		_ = stderrTeeForTests.flush()
	}
}

// installStderrTee points os.Stderr (or, when M.Run will copy os.Stdout to
// os.Stderr, os.Stdout) at the tee's pipe.
func installStderrTee(stdout bool) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	c := &stderrTee{real: os.Stderr, w: w, stdout: stdout}
	if stdout {
		c.real = os.Stdout
		os.Stdout = w
	} else {
		os.Stderr = w
	}
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
		if !c.stdout {
			return
		}
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
	if os.Stderr != c.w {
		// Something replaced os.Stderr after TestMain: the capture would
		// read "" and every log assertion would fail for the wrong reason.
		t.Fatal("captureStderr: os.Stderr is no longer the stderr tee")
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
	out := sink.String()
	c.mu.Unlock()
	if !c.stdout {
		return out
	}
	// The capture holds test2json's events of the tests running meanwhile.
	var kept strings.Builder
	for line := range strings.SplitAfterSeq(out, "\n") {
		if line != "" && line[0] != test2jsonFrame {
			kept.WriteString(line)
		}
	}
	return kept.String()
}

// GAP-1602. A capture must not write os.Stderr while the read-loop drainer
// reads it, in any output mode: CI runs the gateway race shards with
// go test -json -race (-test.v=test2json), and the native Windows harness
// runs the binary the same way. Under -race a swap of os.Stderr during the
// drainer's writes is a DATA RACE and fails this test.
func TestCaptureStderrDoesNotRaceTheReadLoopDrainer(t *testing.T) {
	for i := range 20 {
		want := fmt.Sprintf("gap1602 capture %d", i)
		got := captureStderr(t, func() {
			// The drainer goroutine reads os.Stderr for each queued line
			// while this capture runs.
			for j := range 50 {
				readLoopLogf("gap1602 drainer line %d.%d", i, j)
			}
			fmt.Fprintln(os.Stderr, want)
			time.Sleep(2 * time.Millisecond)
		})
		if !strings.Contains(got, want) {
			t.Fatalf("capture %d = %q, want it to hold %q", i, got, want)
		}
	}
}
