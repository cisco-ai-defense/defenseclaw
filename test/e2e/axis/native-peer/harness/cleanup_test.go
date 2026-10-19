// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSession struct {
	closeErr, retryErr error
	closes, retries    int
	contexts           []context.Context
}

func (s *fakeSession) Close(ctx context.Context) error {
	s.closes++
	s.contexts = append(s.contexts, ctx)
	return s.closeErr
}

func (s *fakeSession) StopAndWait(ctx context.Context) error {
	s.retries++
	s.contexts = append(s.contexts, ctx)
	return s.retryErr
}

func TestCleanupOwnerRetainsExactSessionAndOriginalFailure(t *testing.T) {
	first, pending := errors.New("first cleanup failure"), errors.New("still pending")
	s := &fakeSession{closeErr: first, retryErr: pending}
	owner := &cleanupOwner{}
	if err := owner.close(s); !errors.Is(err, first) || !errors.Is(err, pending) || len(owner.pending) != 1 || owner.pending[0] != s {
		t.Fatal("pending exact custody was discarded")
	}
	if s.closes != 1 || s.retries != 1 || s.contexts[0] == s.contexts[1] {
		t.Fatal("cleanup retry did not get a fresh context")
	}
	for _, ctx := range s.contexts {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("cleanup context was unbounded or not released")
		}
	}
	s.retryErr = nil
	if err := owner.retry(); err != nil || len(owner.pending) != 0 {
		t.Fatal("observed native wait did not discharge exact custody")
	}
	// Even an immediately successful retry must not erase the first error.
	s = &fakeSession{closeErr: first}
	if err := owner.close(s); !errors.Is(err, first) || len(owner.pending) != 0 {
		t.Fatal("eventual cleanup converted original failure to success")
	}
}
