// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"testing"
)

func TestManagedManifestGuardDisabledAllocatesNothing(t *testing.T) {
	ctx := context.Background()
	if allocations := testing.AllocsPerRun(100, func() {
		if !managedManifestGenerationMatches(ctx, 1) || !managedManifestProjectionMatches(ctx, pipeline.LocalLogOutcome{}) {
			t.Fatal("disabled guard rejected ordinary event")
		}
	}); allocations != 0 {
		t.Fatalf("disabled guard allocations=%v", allocations)
	}
}

func BenchmarkManagedManifestGuardDisabled(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for range b.N {
		managedManifestGenerationMatches(ctx, 1)
		managedManifestProjectionMatches(ctx, pipeline.LocalLogOutcome{})
	}
}
