// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/defenseclaw/defenseclaw/internal/winsession"
)

func TestWindowsServiceSessionEventsOnlyForStandaloneGuardianAndEnumerator(t *testing.T) {
	guardian := []string{"enterprise", "hooks", "watch", "--manifest", `C:\x\targets.yaml`, "--interval", "1m"}
	enumerator := []string{"enterprise", "windows", "enumerate", "--manifest", `C:\x\targets.yaml`, "--interval", "5m"}
	for _, tc := range []struct {
		args    []string
		profile string
		want    bool
	}{
		{guardian, "standalone", true},
		{enumerator, "standalone", true},
		{guardian, "", false},
		{enumerator, "secure_client", false},
		{nil, "standalone", false}, // the gateway service has no arguments
		{[]string{"enterprise", "hooks", "reconcile"}, "standalone", false},
	} {
		if got := windowsServiceSessionEvents(tc.args, tc.profile); got != tc.want {
			t.Errorf("windowsServiceSessionEvents(%v, %q) = %t, want %t", tc.args, tc.profile, got, tc.want)
		}
	}
}

func drainWinsession() {
	for {
		select {
		case <-winsession.Logons():
		default:
			return
		}
	}
}

func runSessionTestService(t *testing.T, sessionEvents bool, event uint32) (svc.Accepted, bool) {
	t.Helper()
	drainWinsession()
	requests := make(chan svc.ChangeRequest, 4)
	changes := make(chan svc.Status, 16)
	handler := &defenseClawWindowsService{
		execute: func(ctx context.Context) int {
			<-ctx.Done()
			return 0
		},
		sessionEvents: sessionEvents,
	}
	done := make(chan struct{})
	go func() {
		handler.Execute(nil, requests, changes)
		close(done)
	}()
	var accepted svc.Accepted
	deadline := time.After(2 * time.Second)
	for accepted == 0 {
		select {
		case status := <-changes:
			if status.State == svc.Running {
				accepted = status.Accepts
			}
		case <-deadline:
			t.Fatal("service did not report running")
		}
	}
	requests <- svc.ChangeRequest{Cmd: svc.SessionChange, EventType: event}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	<-done
	select {
	case <-winsession.Logons():
		return accepted, true
	default:
		return accepted, false
	}
}

func TestWindowsServiceForwardsSignInOnlyWhenSubscribed(t *testing.T) {
	accepted, notified := runSessionTestService(t, true, windows.WTS_SESSION_LOGON)
	if accepted&svc.AcceptSessionChange == 0 || !notified {
		t.Fatalf("subscribed service: accepts=%#x notified=%t, want session changes accepted and forwarded", accepted, notified)
	}
	if _, notified := runSessionTestService(t, true, windows.WTS_SESSION_LOCK); notified {
		t.Fatal("a session lock must not trigger enrollment")
	}
	accepted, notified = runSessionTestService(t, false, windows.WTS_SESSION_LOGON)
	if accepted != svc.AcceptStop|svc.AcceptShutdown|svc.AcceptPreShutdown || notified {
		t.Fatalf("unsubscribed service: accepts=%#x notified=%t, want the historical controls only", accepted, notified)
	}
}
