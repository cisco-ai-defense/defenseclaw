// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type fakeServiceEvents struct {
	mu       sync.Mutex
	info     []string
	warnings []string
	closed   bool
}

func (f *fakeServiceEvents) Info(_ uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info = append(f.info, msg)
	return nil
}

func (f *fakeServiceEvents) Warning(_ uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.warnings = append(f.warnings, msg)
	return nil
}

func (f *fakeServiceEvents) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestServiceLogFailureFallsBackToEventLog(t *testing.T) {
	events := &fakeServiceEvents{}
	previousOpen := openWindowsServiceEventLog
	openWindowsServiceEventLog = func(string) (windowsServiceEventSink, error) { return events, nil }
	previousOutput := log.Writer()
	t.Cleanup(func() {
		openWindowsServiceEventLog = previousOpen
		log.SetOutput(previousOutput)
	})

	closeLog := redirectWindowsServiceOutputToEventLog("DefenseClawGateway", errors.New("access is denied"))
	if closeLog == nil {
		t.Fatal("no closer returned")
	}
	log.Print("after fallback")
	closeLog()

	if len(events.warnings) != 1 || !strings.HasPrefix(events.warnings[0], managed.MarkerDegraded) ||
		!strings.Contains(events.warnings[0], "service-log") {
		t.Fatalf("warnings = %v, want one degraded service-log line", events.warnings)
	}
	if len(events.info) != 1 || !strings.Contains(events.info[0], "after fallback") {
		t.Fatalf("info = %v, want the forwarded log line", events.info)
	}
	if !events.closed {
		t.Fatal("event log not closed")
	}
}

func TestDefaultOwnerFailureIsReportedNotFatal(t *testing.T) {
	events := &fakeServiceEvents{}
	previousOpen := openWindowsServiceEventLog
	openWindowsServiceEventLog = func(string) (windowsServiceEventSink, error) { return events, nil }
	t.Cleanup(func() { openWindowsServiceEventLog = previousOpen })

	reportWindowsServiceDegraded("DefenseClawGateway", "default-owner", errors.New("set token owner"))
	if len(events.warnings) != 1 || !strings.Contains(events.warnings[0], "default-owner") {
		t.Fatalf("warnings = %v", events.warnings)
	}
}
