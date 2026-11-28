// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"testing"
	"time"
)

// BenchmarkLeaderSinkEmit is what a model call pays for the cluster usage
// push: one lock and one map update, no network, no disk.
func BenchmarkLeaderSinkEmit(b *testing.B) {
	s := NewLeaderSink("epoch-bench")
	r := actorRec("p:aaaa", "act-1", "", "ns1", "m1", 0.01, time.Now())
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Emit(ctx, r)
		}
	})
}
