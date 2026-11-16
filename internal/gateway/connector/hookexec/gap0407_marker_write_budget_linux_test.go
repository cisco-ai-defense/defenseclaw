// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A saturated local append must not keep the hook past its answer budget.
func TestGAP0407MarkerWriteDoesNotHoldAnswerPastBudget(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{'x'}, 4096)
	for {
		_, err := syscall.Write(fd, chunk)
		if errors.Is(err, syscall.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := openHookFailureLog
	var openedMarker atomic.Bool
	openHookFailureLog = func(path string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasSuffix(path, "hook-failures.dropped") {
			openedMarker.Store(true)
			return writer, nil
		}
		return previous(path, flag, perm)
	}
	defer func() { openHookFailureLog = previous }()
	var output bytes.Buffer
	exited := make(chan time.Duration, 1)
	started := time.Now()
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "closed",
		Stdout: &output, Stderr: io.Discard,
		Exit: func(int) { exited <- time.Since(started) },
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"write-stall"}`)
	startAnswerWatchdog(&opts, specs["claudecode"], "closed", started.Add(450*time.Millisecond), started.Add(450*time.Millisecond))
	select {
	case elapsed := <-exited:
		if elapsed > 650*time.Millisecond {
			t.Fatalf("hook exit delayed by local append: %v", elapsed)
		}
	case <-time.After(700 * time.Millisecond):
		// Release a blocked writer before failing so the test process can exit.
		buffer := make([]byte, 1<<20)
		if _, err := reader.Read(buffer); err != nil {
			t.Fatal(err)
		}
		select {
		case elapsed := <-exited:
			t.Fatalf("hook exit waited for local append: %v (marker opened=%t)", elapsed, openedMarker.Load())
		case <-time.After(time.Second):
			t.Fatalf("hook exit still blocked after local append released (marker opened=%t)", openedMarker.Load())
		}
	}
}
