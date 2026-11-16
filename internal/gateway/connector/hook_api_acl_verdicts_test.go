// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A clean ACL verdict is reused while the directory keeps its identity, and
// inspected again once the identity changes (rel-1-0-6 GAP-0129).
func TestHookAPIACLVerdictReusedUntilIdentityChanges(t *testing.T) {
	var v hookAPIACLVerdicts
	var inspections atomic.Int64
	inspect := func() error { inspections.Add(1); return nil }
	for range 3 {
		if err := v.check("/d", "id-1", inspect); err != nil {
			t.Fatal(err)
		}
	}
	if inspections.Load() != 1 {
		t.Fatalf("inspections for one identity = %d, want 1", inspections.Load())
	}
	if err := v.check("/d", "id-2", inspect); err != nil || inspections.Load() != 2 {
		t.Fatalf("changed identity: err %v, inspections %d, want a new inspection", err, inspections.Load())
	}
}

// A refusing verdict and a failed inspection are never kept: the next check
// inspects again, so a fixed directory is accepted and a broken one refused
// every time.
func TestHookAPIACLRefusalIsNotKept(t *testing.T) {
	var v hookAPIACLVerdicts
	refusal := errors.New("write-capable ACL")
	var inspections atomic.Int64
	for range 2 {
		if err := v.check("/d", "id", func() error { inspections.Add(1); return refusal }); !errors.Is(err, refusal) {
			t.Fatalf("err = %v, want the refusal", err)
		}
	}
	if inspections.Load() != 2 {
		t.Fatalf("a refusing verdict was reused: %d inspections", inspections.Load())
	}
	if err := v.check("/d", "id", func() error { return nil }); err != nil {
		t.Fatalf("fixed directory = %v", err)
	}
}

// A clean verdict expires after hookAPIACLCleanFor even with the same identity.
func TestHookAPIACLCleanVerdictExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	v := hookAPIACLVerdicts{now: func() time.Time { return now }}
	var inspections atomic.Int64
	inspect := func() error { inspections.Add(1); return nil }
	_ = v.check("/d", "id", inspect)
	now = now.Add(hookAPIACLCleanFor - time.Second)
	_ = v.check("/d", "id", inspect)
	now = now.Add(2 * time.Second)
	_ = v.check("/d", "id", inspect)
	if inspections.Load() != 2 {
		t.Fatalf("inspections = %d, want 2 (one reuse, one after expiry)", inspections.Load())
	}
}

// A directory whose identity cannot be read is inspected every time.
func TestHookAPIACLUnknownIdentityIsAlwaysInspected(t *testing.T) {
	var v hookAPIACLVerdicts
	var inspections atomic.Int64
	for range 3 {
		_ = v.check("/d", "", func() error { inspections.Add(1); return nil })
	}
	if inspections.Load() != 3 {
		t.Fatalf("inspections = %d, want 3", inspections.Load())
	}
}

// A 32-way burst of checks of one directory shares one inspection and gets
// its verdict.
func TestHookAPIACLBurstSharesOneInspection(t *testing.T) {
	var v hookAPIACLVerdicts
	var inspections atomic.Int64
	release := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- v.check("/d", "id", func() error { inspections.Add(1); <-release; return nil })
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if inspections.Load() != 1 {
		t.Fatalf("32 concurrent checks ran %d inspections, want 1", inspections.Load())
	}
}

// An inspection that panics leaves no clean verdict and fails its waiters.
func TestHookAPIACLPanickedInspectionIsNotClean(t *testing.T) {
	var v hookAPIACLVerdicts
	func() {
		defer func() { _ = recover() }()
		_ = v.check("/d", "id", func() error { panic("boom") })
	}()
	var inspections atomic.Int64
	if err := v.check("/d", "id", func() error { inspections.Add(1); return nil }); err != nil || inspections.Load() != 1 {
		t.Fatalf("after a panicked inspection: err %v, inspections %d; want a new inspection", err, inspections.Load())
	}
}
