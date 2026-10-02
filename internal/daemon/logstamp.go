// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bufio"
	"io"
	"os"
	"sync"
	"time"
)

// EnvLogTimestamps turns the gateway.log line stamps off when set to "0".
const EnvLogTimestamps = "DEFENSECLAW_LOG_TIMESTAMPS"

var (
	rawStderrMu sync.Mutex
	rawStderr   *os.File
)

// RawStderr is the log file itself while StampChildLog is active, and
// os.Stderr otherwise. A child that may outlive the gateway (the
// config-restart helper) must inherit this file, not the stamping pipe: once
// the gateway exits, writes to the pipe would fail with EPIPE.
func RawStderr() *os.File {
	rawStderrMu.Lock()
	defer rawStderrMu.Unlock()
	if rawStderr != nil {
		return rawStderr
	}
	return os.Stderr
}

// StampChildLog prefixes every line the detached gateway writes to
// gateway.log with an RFC 3339 UTC time (GAP-1319). The daemon child's
// stdout and stderr are the log file; this routes os.Stdout and os.Stderr
// through an in-process pipe whose reader stamps each line and appends it to
// that file. The reader lives in the gateway itself, so nothing depends on
// the CLI that spawned it. fd 2 stays the file, so Go runtime crash output
// still reaches it directly.
//
// It does nothing outside a daemon child or when DEFENSECLAW_LOG_TIMESTAMPS=0.
// The returned func puts the file back and drains the pipe; call it before
// the process prints its exit error.
func StampChildLog() (restore func()) {
	if !IsDaemonChild() || os.Getenv(EnvLogTimestamps) == "0" {
		return func() {}
	}
	return stampLog(os.Stderr, os.Stdout, time.Now)
}

// EnvStampLog marks a detached helper (the background watchdog) whose
// stdout and stderr are its log file, so it stamps its lines like the
// gateway does.
const EnvStampLog = "DEFENSECLAW_STAMP_LOG"

// StampDetachedLog prefixes every line a detached helper started with
// EnvStampLog=1 writes with an RFC 3339 UTC time (GAP-1578), the same way
// StampChildLog stamps gateway.log. The marker is cleared so the helper's own
// children do not inherit it. It does nothing without the marker or when
// DEFENSECLAW_LOG_TIMESTAMPS=0.
func StampDetachedLog() (restore func()) {
	marked := os.Getenv(EnvStampLog) == "1"
	_ = os.Unsetenv(EnvStampLog)
	if !marked || os.Getenv(EnvLogTimestamps) == "0" {
		return func() {}
	}
	return stampLog(os.Stderr, os.Stdout, time.Now)
}

func stampLog(file, stdout *os.File, now func() time.Time) func() {
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyStamped(file, r, now)
		_ = r.Close()
	}()
	sameStdout := sameFile(file, stdout)
	rawStderrMu.Lock()
	rawStderr = file
	rawStderrMu.Unlock()
	os.Stderr = w
	if sameStdout {
		os.Stdout = w
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			os.Stderr = file
			if sameStdout {
				os.Stdout = stdout
			}
			_ = w.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			rawStderrMu.Lock()
			rawStderr = nil
			rawStderrMu.Unlock()
		})
	}
}

// copyStamped writes each line from r to dst with a time prefix. A final
// line without a newline is written as is.
func copyStamped(dst io.Writer, r io.Reader, now func() time.Time) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			_, _ = io.WriteString(dst, now().UTC().Format(time.RFC3339)+" "+line)
		}
		if err != nil {
			return
		}
	}
}

func sameFile(a, b *os.File) bool {
	if a == nil || b == nil {
		return false
	}
	ai, errA := a.Stat()
	bi, errB := b.Stat()
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}
