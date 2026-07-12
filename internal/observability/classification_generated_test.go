// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"reflect"
	"sort"
	"testing"
)

func TestGeneratedProducerGroupsAreExactPublicClassificationAuthority(t *testing.T) {
	t.Parallel()

	if got, want := len(generatedProducerGroups), 203; got != want {
		t.Fatalf("generated producer groups = %d, want %d", got, want)
	}
	if got, want := len(gatewayEventClassifications), 15; got != want {
		t.Fatalf("gateway classifications = %d, want %d", got, want)
	}
	if got, want := len(auditActionClassifications), 188; got != want {
		t.Fatalf("audit classifications = %d, want %d", got, want)
	}

	generatedKeys := map[ProducerKind][]ProducerKey{
		ProducerGatewayEvent: nil,
		ProducerAuditAction:  nil,
	}
	seen := make(map[generatedProducerLookupKey]struct{}, len(generatedProducerGroups))
	for _, group := range generatedProducerGroups {
		lookupKey := generatedProducerLookupKey{Kind: group.Kind, Key: group.Key}
		if _, duplicate := seen[lookupKey]; duplicate {
			t.Fatalf("duplicate generated producer group %s/%s", group.Kind, group.Key)
		}
		seen[lookupKey] = struct{}{}
		generatedKeys[group.Kind] = append(generatedKeys[group.Kind], group.Key)

		got, found := publicClassificationForTest(group.Kind, group.Key)
		if !found {
			t.Fatalf("generated producer %s/%s is absent from public classification", group.Kind, group.Key)
		}
		want := expectedGeneratedClassificationForTest(t, group)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("classification %s/%s\n got: %#v\nwant: %#v", group.Kind, group.Key, got, want)
		}
	}

	for _, kind := range []ProducerKind{ProducerGatewayEvent, ProducerAuditAction} {
		sort.Slice(generatedKeys[kind], func(left, right int) bool {
			return generatedKeys[kind][left] < generatedKeys[kind][right]
		})
		if got := ClassificationKeys(kind); !reflect.DeepEqual(got, generatedKeys[kind]) {
			t.Fatalf("classification keys for %s = %v, want %v", kind, got, generatedKeys[kind])
		}
	}
	if keys := ClassificationKeys(ProducerKind("unknown")); keys != nil {
		t.Fatalf("unknown producer kind keys = %v, want nil", keys)
	}
}

func TestGeneratedPublicClassificationCopiesAreIsolated(t *testing.T) {
	t.Parallel()

	first, found := AuditActionClassification("block")
	if !found || len(first.AllowedContextBuckets) == 0 || len(first.MandatoryRules) == 0 ||
		len(first.CompanionRules) == 0 {
		t.Fatalf("block classification lacks clone fixtures: %#v", first)
	}
	want := cloneClassification(first)
	first.AllowedContextBuckets[0] = BucketDiagnostic
	first.MandatoryRules[0] = MandatoryAlways
	first.CompanionRules[0] = CompanionFindingPerObservation

	second, found := AuditActionClassification("block")
	if !found || !reflect.DeepEqual(second, want) {
		t.Fatalf("caller mutated public classification: got %#v, want %#v", second, want)
	}
	keys := ClassificationKeys(ProducerGatewayEvent)
	wantKeys := append([]ProducerKey(nil), keys...)
	keys[0] = "caller-mutation"
	if got := ClassificationKeys(ProducerGatewayEvent); !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("caller mutated classification keys: got %v, want %v", got, wantKeys)
	}
	if classification, ok := GatewayEventClassification("unknown"); ok ||
		!reflect.DeepEqual(classification, Classification{}) {
		t.Fatalf("unknown gateway lookup = %#v, %t", classification, ok)
	}
	if classification, ok := AuditActionClassification("unknown"); ok ||
		!reflect.DeepEqual(classification, Classification{}) {
		t.Fatalf("unknown audit lookup = %#v, %t", classification, ok)
	}
}

func TestGeneratedClassificationDefaultIdentityBehaviorIsExhaustive(t *testing.T) {
	t.Parallel()

	for _, group := range generatedProducerGroups {
		classification, found := publicClassificationForTest(group.Kind, group.Key)
		if !found {
			t.Fatalf("missing public classification %s/%s", group.Kind, group.Key)
		}
		resolved, err := classification.Resolve(ClassificationContext{RawSeverity: "HIGH"})
		if !group.HasDefaultIdentity {
			if err == nil {
				t.Fatalf("context-required producer %s/%s resolved without identity: %+v", group.Kind, group.Key, resolved)
			}
			continue
		}
		if err != nil {
			t.Fatalf("default producer %s/%s failed: %v", group.Kind, group.Key, err)
		}
		identity, ok := generatedProducerIdentities[group.DefaultIdentityKey]
		if !ok {
			t.Fatalf("default producer %s/%s references an unknown identity", group.Kind, group.Key)
		}
		want := EventIdentity{Bucket: identity.Bucket, Signal: SignalLogs, Name: identity.EventName}
		if resolved.Identity != want {
			t.Fatalf("default producer %s/%s identity = %+v, want %+v", group.Kind, group.Key, resolved.Identity, want)
		}
	}
}

func TestGeneratedClassificationRuleUnionDoesNotBroadenExactRuntimeRule(t *testing.T) {
	t.Parallel()

	classification, found := AuditActionClassification("sink-failure")
	if !found || !containsMandatoryRuleForTest(
		classification.MandatoryRules,
		MandatoryProtectedBoundaryAuthFailure,
	) {
		t.Fatalf("sink-failure compatibility union = %v", classification.MandatoryRules)
	}
	// Public classification metadata is compatibility-facing introspection. Even
	// a caller-mutated copy cannot replace the generated selected-row authority.
	classification.MandatoryRules = []MandatoryRule{MandatoryAlways}
	classification.CompanionRules = []CompanionRule{CompanionFindingPerObservation}
	legacy, err := classification.Resolve(ClassificationContext{
		RawSeverity: "HIGH", FindingCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Mandatory || len(legacy.RequiredCompanions) != 0 {
		t.Fatalf("public rule metadata replaced exact generated rules: %+v", legacy)
	}
	authentication, err := classification.Resolve(ClassificationContext{
		Bucket: BucketPlatformHealth, EventName: "destination.authentication.failed",
		RawSeverity:    "HIGH",
		MandatoryFacts: MandatoryFacts{ProtectedBoundaryAuthFailure: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authentication.Mandatory {
		t.Fatal("exact authentication identity did not select its generated mandatory rule")
	}
	export, err := classification.Resolve(ClassificationContext{
		Bucket: BucketPlatformHealth, EventName: "destination.export_failed",
		RawSeverity: "HIGH",
	})
	if err != nil {
		t.Fatal(err)
	}
	if export.Mandatory {
		t.Fatal("caller-mutated compatibility rule broadened the exact export-failure identity")
	}
}

func publicClassificationForTest(kind ProducerKind, key ProducerKey) (Classification, bool) {
	switch kind {
	case ProducerGatewayEvent:
		return GatewayEventClassification(key)
	case ProducerAuditAction:
		return AuditActionClassification(key)
	default:
		return Classification{}, false
	}
}

func expectedGeneratedClassificationForTest(
	t *testing.T,
	group generatedProducerGroup,
) Classification {
	t.Helper()
	want := Classification{
		Kind: group.Kind, Key: group.Key,
		EventNamePolicy: group.EventNamePolicy, SeverityPolicy: group.SeverityPolicy,
	}
	if group.HasDefaultIdentity {
		identity, ok := generatedProducerIdentities[group.DefaultIdentityKey]
		if !ok {
			t.Fatalf("producer %s/%s default identity is unknown", group.Kind, group.Key)
		}
		want.Bucket = identity.Bucket
		want.DefaultEventName = identity.EventName
	} else if group.EventNamePolicy != EventNameContextRequired {
		t.Fatalf("producer %s/%s has no default for %q", group.Kind, group.Key, group.EventNamePolicy)
	}

	buckets := make(map[Bucket]struct{})
	mandatory := make(map[MandatoryRule]struct{})
	companions := make(map[CompanionRule]struct{})
	if group.ContextIdentitySetID != "" {
		set, ok := generatedProducerContextIdentitySets[group.ContextIdentitySetID]
		if !ok {
			t.Fatalf("producer %s/%s context set is unknown", group.Kind, group.Key)
		}
		for _, key := range set.IdentityKeys {
			identity, exists := generatedProducerIdentities[key]
			if !exists {
				t.Fatalf("producer %s/%s context identity is unknown", group.Kind, group.Key)
			}
			buckets[identity.Bucket] = struct{}{}
		}
	}
	for _, rule := range group.LegacyMandatoryRules {
		mandatory[rule] = struct{}{}
	}
	for _, rule := range group.CompanionRules {
		companions[rule] = struct{}{}
	}
	want.AllowedContextBuckets = sortedBucketsForTest(buckets)
	want.MandatoryRules = sortedMandatoryRulesForTest(mandatory)
	want.CompanionRules = sortedCompanionRulesForTest(companions)
	return want
}

func sortedBucketsForTest(values map[Bucket]struct{}) []Bucket {
	if len(values) == 0 {
		return nil
	}
	result := make([]Bucket, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func sortedMandatoryRulesForTest(values map[MandatoryRule]struct{}) []MandatoryRule {
	if len(values) == 0 {
		return nil
	}
	result := make([]MandatoryRule, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func sortedCompanionRulesForTest(values map[CompanionRule]struct{}) []CompanionRule {
	if len(values) == 0 {
		return nil
	}
	result := make([]CompanionRule, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func containsMandatoryRuleForTest(rules []MandatoryRule, want MandatoryRule) bool {
	for _, rule := range rules {
		if rule == want {
			return true
		}
	}
	return false
}
