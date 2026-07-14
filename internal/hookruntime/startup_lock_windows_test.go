// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayStartLockSerializesConcurrentHookProcesses(t *testing.T) {
	const callers = 8
	var active atomic.Int32
	var maximum atomic.Int32
	var wg sync.WaitGroup
	errorsByCaller := make(chan error, callers)
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errorsByCaller <- WithGatewayStartLock(context.Background(), func() error {
				current := active.Add(1)
				defer active.Add(-1)
				for {
					seen := maximum.Load()
					if current <= seen || maximum.CompareAndSwap(seen, current) {
						break
					}
				}
				time.Sleep(15 * time.Millisecond)
				return nil
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent gateway starts = %d, want 1", got)
	}
}

func TestGatewayStartLockHonorsWaitingHookDeadline(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- WithGatewayStartLock(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	err := WithGatewayStartLock(ctx, func() error {
		t.Fatal("deadline-expired hook entered gateway start critical section")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting hook error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}
