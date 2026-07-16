// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

func TestRegisteredTraceProjectionContractCoversEveryGeneratedSpanAndIsDetached(t *testing.T) {
	t.Parallel()
	traces := 0
	for _, family := range generatedFamilyIdentityDescriptors() {
		if family.Identity.Signal != SignalTraces {
			continue
		}
		traces++
		contract, ok := RegisteredTraceProjectionContract(family.Identity)
		if !ok || len(contract.AttributeKeys) == 0 || contract.EventAttributeKeys == nil ||
			len(contract.LinkRelations) == 0 || len(contract.LinkAttributeKeys) == 0 ||
			len(contract.ResourceAttributeKeys) == 0 || len(contract.ScopeAttributeKeys) == 0 {
			t.Fatalf("trace contract %s = %+v ok=%v", family.FamilyID, contract, ok)
		}
		contract.AttributeKeys[0] = "mutated"
		contract.LinkRelations[0] = "mutated"
		contract.LinkAttributeKeys[0] = "mutated"
		contract.ResourceAttributeKeys[0] = "mutated"
		contract.ScopeAttributeKeys[0] = "mutated"
		for name, keys := range contract.EventAttributeKeys {
			if len(keys) > 0 {
				keys[0] = "mutated"
				contract.EventAttributeKeys[name] = keys
				break
			}
		}
		fresh, ok := RegisteredTraceProjectionContract(family.Identity)
		if !ok || fresh.AttributeKeys[0] == "mutated" || fresh.LinkRelations[0] == "mutated" ||
			fresh.LinkAttributeKeys[0] == "mutated" || fresh.ResourceAttributeKeys[0] == "mutated" ||
			fresh.ScopeAttributeKeys[0] == "mutated" {
			t.Fatalf("caller mutated generated trace contract %s: %+v", family.FamilyID, fresh)
		}
		for _, keys := range fresh.EventAttributeKeys {
			if len(keys) > 0 && keys[0] == "mutated" {
				t.Fatalf("caller mutated event contract %s", family.FamilyID)
			}
		}
	}
	if traces != 25 {
		t.Fatalf("generated trace family count = %d, want 25", traces)
	}
	if _, ok := RegisteredTraceProjectionContract(EventIdentity{
		Bucket: BucketModelIO, Signal: SignalMetrics, Name: "gen_ai.client.operation.duration",
	}); ok {
		t.Fatal("metric identity exposed a trace projection contract")
	}
}
