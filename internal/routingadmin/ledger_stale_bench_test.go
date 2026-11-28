// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"testing"
	"time"
)

// BenchmarkLedgerSpendStaleCheck is the budget read of a model call on a
// cluster replica: in memory only, with the stale window on.
func BenchmarkLedgerSpendStaleCheck(b *testing.B) {
	now := time.Now()
	l := NewLedger()
	l.SetStaleAfter(15 * time.Second)
	l.ApplyRemote([]string{"day"}, []SeedRow{{Day: now.UTC().Format(time.DateOnly), Key: "user:day:p:1", USD: 1}}, now)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Spend("user:day:p:1", "day", now)
		}
	})
}
