// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestProjectManagedLogIsPureAndMatchesDelivery(t *testing.T) {
	for _, collect := range []bool{false, true} {
		t.Run(fmt.Sprint(collect), func(t *testing.T) {
			deps := newRuntimeTestDependencies(t)
			plan := managedFallbackRuntimePlan(t, deps, collect, "https://preview.example.test", true)
			adapters := newManagedFallbackAdapters()
			runtime := newManagedFallbackRuntime(t, deps, plan, adapters)
			const id = "preview-managed-record"
			const content = "preview-person@example.test"
			builder := runtimeContentRecordBuilder(id, content)
			preview, err := runtime.ProjectManagedLog(t.Context(), diagnosticMetadata(t), builder)
			if err != nil {
				t.Fatal(err)
			}
			work := preview.OptionalWork()
			if preview.LocalPersisted() || len(work) != 1 || work[0].Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
				t.Fatalf("preview persisted=%t work=%d; want one managed projection only", preview.LocalPersisted(), len(work))
			}
			encoded, err := work[0].Projection().Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(content)) {
				t.Fatal("preview retained sensitive source content")
			}
			if n := countRuntimeRecord(t, deps, id); n != 0 {
				t.Fatalf("preview wrote %d records", n)
			}
			managed := adapters.named(t, config.ObservabilityV8ManagedAIDDestinationName)
			operator := adapters.named(t, "operator-console")
			select {
			case <-managed.delivered:
				t.Fatal("preview dispatched managed work")
			default:
			}
			select {
			case <-operator.delivered:
				t.Fatal("preview dispatched operator work")
			default:
			}
			outcome, err := runtime.Emit(t.Context(), diagnosticMetadata(t), builder)
			if err != nil {
				t.Fatal(err)
			}
			for _, actual := range outcome.OptionalWork() {
				if actual.Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
					continue
				}
				body, err := actual.Projection().Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(encoded, body) {
					t.Fatal("preview differs from actual managed projection")
				}
				return
			}
			t.Fatal("ordinary emit did not produce the managed projection")
		})
	}
}
