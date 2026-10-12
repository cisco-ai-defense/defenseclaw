//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"testing"
)

// GAP-0680, GAP-0517: after a directory outage a bound Mac kept answering
// from Open Directory's caches for about 11 minutes, so accounts stayed on the
// default profile. The guardian flushes those caches at the first pass that
// resolves accounts after one that resolved none, and only then.
func TestIdentityPassFlushesDirectoryCachesWhenTheDirectoryReturns(t *testing.T) {
	flushes := 0
	previous := enterpriseHookFlushDirectoryCaches
	enterpriseHookFlushDirectoryCaches = func(context.Context) error { flushes++; return nil }
	t.Cleanup(func() { enterpriseHookFlushDirectoryCaches = previous })
	var stderr bytes.Buffer
	unreachable := false
	for i, pass := range []struct{ resolved, flushes int }{
		{3, 0}, // healthy
		{0, 0}, // the outage begins
		{0, 0}, // still down: never flush during the outage
		{2, 1}, // back: flush once
		{3, 1}, // healthy again
	} {
		unreachable = enterpriseHookIdentityPassDone(context.Background(), &stderr, unreachable, 3, pass.resolved)
		if flushes != pass.flushes {
			t.Fatalf("pass %d: %d flushes, want %d", i, flushes, pass.flushes)
		}
	}
	if enterpriseHookIdentityPassDone(context.Background(), &stderr, false, 0, 0) {
		t.Fatal("a pass that lists no accounts says nothing about the directory")
	}
}
