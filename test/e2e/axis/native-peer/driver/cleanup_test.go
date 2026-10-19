// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
)

type fakeCustody struct {
	closeErr, retryErr error
	closes, retries    int
}

func (f *fakeCustody) Close(ctx context.Context) error       { f.closes++; return f.closeErr }
func (f *fakeCustody) StopAndWait(ctx context.Context) error { f.retries++; return f.retryErr }

func TestCleanupFailureRemainsFailureAfterSuccessfulRetry(t *testing.T) {
	failed := errors.New("fixed first cleanup failed")
	fake := &fakeCustody{closeErr: failed}
	owner := &cleanupOwner{}
	if !errors.Is(owner.close(fake), failed) || len(owner.pending) != 0 || fake.closes != 1 || fake.retries != 1 {
		t.Fatal("successful retry hid original cleanup failure")
	}
}

func TestCleanupRetainsExactOwnerWhenRetryAlsoFails(t *testing.T) {
	fake := &fakeCustody{closeErr: errors.New("fixed close"), retryErr: errors.New("fixed retry")}
	owner := &cleanupOwner{}
	if owner.close(fake) == nil || len(owner.pending) != 1 || owner.pending[0] != fake {
		t.Fatal("failed cleanup lost native owner")
	}
	fake.retryErr = nil
	if owner.retry() != nil || len(owner.pending) != 0 || fake.retries != 2 {
		t.Fatal("retained owner could not discharge")
	}
}
