// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWaitForStopOrSubsystemFailureReturnsFatalError(t *testing.T) {
	fatal := make(chan error, 1)
	fatal <- subsystemFailure("api", errors.New("bind failed"))
	err := waitForStopOrSubsystemFailure(context.Background(), fatal)
	if err == nil || !strings.Contains(err.Error(), "api subsystem stopped") {
		t.Fatalf("err = %v, want the api subsystem failure", err)
	}
}

func TestWaitForStopOrSubsystemFailureReturnsNilOnStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForStopOrSubsystemFailure(ctx, make(chan error)); err != nil {
		t.Fatalf("err = %v, want nil on a requested stop", err)
	}
}

func TestBindConflictClassification(t *testing.T) {
	if !isBindConflict(syscall.Errno(10013)) {
		t.Fatal("WSAEACCES should be a retryable bind conflict")
	}
	if !isBindConflict(errors.New("bind: An attempt was made to access a socket in a way forbidden by its access permissions.")) {
		t.Fatal("WSAEACCES text should be a retryable bind conflict")
	}
	if isBindConflict(errors.New("no such host")) {
		t.Fatal("unrelated error classified as a bind conflict")
	}
	err := describeBindConflict("127.0.0.1:18970", syscall.Errno(10013))
	if !strings.Contains(err.Error(), "excluded port range") {
		t.Fatalf("describeBindConflict = %v, want the excluded range remedy", err)
	}
}

func TestManagedInspectorRetryBackoff(t *testing.T) {
	got := []time.Duration{}
	delay := managedInspectorRetryInitial
	for i := 0; i < 8; i++ {
		got = append(got, delay)
		delay = nextManagedInspectorRetry(delay)
	}
	if got[0] != managedInspectorRetryInitial || got[len(got)-1] != managedInspectorRetryMax {
		t.Fatalf("backoff = %v", got)
	}
}
