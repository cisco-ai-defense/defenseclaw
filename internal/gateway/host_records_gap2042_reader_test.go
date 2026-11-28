// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestGAP2042HelperProcess is the host log reader the reader tests run: it
// does nothing unless GAP2042_HELPER names a mode.
func TestGAP2042HelperProcess(t *testing.T) {
	switch os.Getenv("GAP2042_HELPER") {
	case "flood":
		// A reader that never stops writing.
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				os.Exit(0)
			}
		}
	case "hold":
		// A reader whose child keeps the output pipe open after the reader
		// is killed.
		child := exec.Command(os.Args[0], "-test.run=^TestGAP2042HelperProcess$")
		child.Env = append(os.Environ(), "GAP2042_HELPER=sleep")
		child.Stdout = os.Stdout
		_ = child.Start()
		time.Sleep(20 * time.Second)
		os.Exit(0)
	case "sleep":
		time.Sleep(20 * time.Second)
		os.Exit(0)
	}
}

func gap2042Helper(t *testing.T, mode string) (string, []string) {
	t.Helper()
	t.Setenv("GAP2042_HELPER", mode)
	return os.Args[0], []string{"-test.run=^TestGAP2042HelperProcess$"}
}

// TestGAP2042ReaderStopsAtTheOutputCap: a reader still writing at the
// output bound is stopped there and the read keeps the bytes before it,
// instead of draining it until the read time runs out and losing the whole
// read (rel-1-0-10:GAP-2042, CHK-RFGW2 N2).
func TestGAP2042ReaderStopsAtTheOutputCap(t *testing.T) {
	path, args := gap2042Helper(t, "flood")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	out, capped, err := hostRecordCommand(ctx, path, args...)
	if err != nil || !capped || len(out) != hostRecordOutputMax {
		t.Fatalf("err=%v capped=%v len=%d after %v, want the first %d bytes kept", err, capped, len(out), time.Since(start), hostRecordOutputMax)
	}
}

// TestGAP2042ReaderDoesNotWaitForAHeldOutput: a reader killed at its read
// time whose child still holds the output pipe returns within the wait
// bound, so the reader is not busy for good (CHK-RFGW2 N3).
func TestGAP2042ReaderDoesNotWaitForAHeldOutput(t *testing.T) {
	path, args := gap2042Helper(t, "hold")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := hostRecordCommand(ctx, path, args...)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a reader killed at its read time gave no error")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("the read still waits for the output a child holds open")
	}
}
