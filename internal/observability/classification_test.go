// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	observability "github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestGatewayEventClassificationsMatchSourceConstants(t *testing.T) {
	want := typedStringConstants(t, "internal/gatewaylog/events.go", "EventType")
	got := producerKeysAsStrings(observability.ClassificationKeys(observability.ProducerGatewayEvent))
	if len(want) != 16 {
		t.Fatalf("gateway EventType source constants = %d, want 16", len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway classifications = %v, source constants = %v", got, want)
	}
}

func TestAuditActionClassificationsMatchSourceConstantsAndRegistry(t *testing.T) {
	sourceConstants := typedStringConstants(t, "internal/audit/actions.go", "Action")
	registry := make([]string, 0, len(audit.AllActions()))
	for _, action := range audit.AllActions() {
		registry = append(registry, string(action))
	}
	sort.Strings(registry)
	got := producerKeysAsStrings(observability.ClassificationKeys(observability.ProducerAuditAction))
	if len(sourceConstants) != 188 {
		t.Fatalf("audit Action source constants = %d, want 188", len(sourceConstants))
	}
	if !reflect.DeepEqual(registry, sourceConstants) {
		t.Fatalf("audit.AllActions registry differs from typed source constants\nregistry: %v\nsource: %v", registry, sourceConstants)
	}
	if !reflect.DeepEqual(got, sourceConstants) {
		t.Fatalf("audit classifications differ from typed source constants\nclassifications: %v\nsource: %v", got, sourceConstants)
	}
}

func TestClassificationMetadataIsValid(t *testing.T) {
	tests := []struct {
		kind observability.ProducerKind
		get  func(observability.ProducerKey) (observability.Classification, bool)
	}{
		{kind: observability.ProducerGatewayEvent, get: observability.GatewayEventClassification},
		{kind: observability.ProducerAuditAction, get: observability.AuditActionClassification},
	}
	for _, test := range tests {
		for _, key := range observability.ClassificationKeys(test.kind) {
			classification, ok := test.get(key)
			if !ok {
				t.Fatalf("lookup failed for %s/%s", test.kind, key)
			}
			if classification.Kind != test.kind || classification.Key != key {
				t.Errorf("metadata identity for %s/%s = %s/%s", test.kind, key, classification.Kind, classification.Key)
			}
			if classification.Bucket == "" {
				if len(classification.AllowedContextBuckets) == 0 {
					t.Errorf("%s/%s has neither fixed nor allowed context buckets", test.kind, key)
				}
			} else if !observability.IsBucket(classification.Bucket) {
				t.Errorf("%s/%s has unknown bucket %q", test.kind, key, classification.Bucket)
			}
			for _, bucket := range classification.AllowedContextBuckets {
				if !observability.IsBucket(bucket) {
					t.Errorf("%s/%s has unknown context bucket %q", test.kind, key, bucket)
				}
			}
			if classification.DefaultEventName != "" {
				if err := classification.DefaultEventName.Validate(); err != nil {
					t.Errorf("%s/%s has invalid default event name: %v", test.kind, key, err)
				}
				if !observability.IsRegisteredEventNameForSignal(
					observability.SignalLogs,
					classification.DefaultEventName,
				) {
					t.Errorf(
						"%s/%s default event name %q is not registered for logs",
						test.kind,
						key,
						classification.DefaultEventName,
					)
				}
			}
			switch classification.EventNamePolicy {
			case observability.EventNameFixed, observability.EventNameContextOptional:
				if classification.DefaultEventName == "" {
					t.Errorf("%s/%s policy %q requires a default event name", test.kind, key, classification.EventNamePolicy)
				}
			case observability.EventNameContextRequired:
			default:
				t.Errorf("%s/%s has unknown event-name policy %q", test.kind, key, classification.EventNamePolicy)
			}
			switch classification.SeverityPolicy {
			case observability.SeverityCanonicalOrInfo,
				observability.SeverityFindingRequired,
				observability.SeverityEvaluation,
				observability.SeverityFailureOrSource,
				observability.SeverityMalformedOrSource:
			default:
				t.Errorf("%s/%s has unknown severity policy %q", test.kind, key, classification.SeverityPolicy)
			}
		}
	}
}

func TestClassificationResolution(t *testing.T) {
	t.Run("verdict emits enforcement companion only when enforced", func(t *testing.T) {
		classification := mustGatewayClassification(t, "verdict")
		observed, err := classification.Resolve(observability.ClassificationContext{RawSeverity: "NONE"})
		if err != nil {
			t.Fatal(err)
		}
		if !observed.Severity.CleanEvaluation || observed.Mandatory || len(observed.RequiredCompanions) != 0 {
			t.Fatalf("observe-mode clean verdict = %+v", observed)
		}
		enforced, err := classification.Resolve(observability.ClassificationContext{
			RawSeverity: "HIGH",
			Enforced:    true,
			MandatoryFacts: observability.MandatoryFacts{
				EnforcedOutcome: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if enforced.Mandatory {
			t.Fatal("guardrail evaluation inherited enforcement-floor status from its companion")
		}
		wantCompanions := []observability.CompanionRule{observability.CompanionEnforcementWhenEnforced}
		if !reflect.DeepEqual(enforced.RequiredCompanions, wantCompanions) {
			t.Fatalf("enforced verdict companions = %v, want %v", enforced.RequiredCompanions, wantCompanions)
		}
	})

	t.Run("generic lifecycle requires typed context", func(t *testing.T) {
		classification := mustGatewayClassification(t, "lifecycle")
		if _, err := classification.Resolve(observability.ClassificationContext{}); err == nil {
			t.Fatal("context-free lifecycle classification succeeded")
		}
		resolved, err := classification.Resolve(observability.ClassificationContext{
			Bucket:    observability.BucketAgentLifecycle,
			EventName: "session_start",
		})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Identity.Bucket != observability.BucketAgentLifecycle || resolved.Identity.Name != "session_start" {
			t.Fatalf("resolved lifecycle identity = %+v", resolved.Identity)
		}
	})

	t.Run("fixed event name cannot be replaced", func(t *testing.T) {
		classification := mustGatewayClassification(t, "hook_decision")
		resolved, err := classification.Resolve(observability.ClassificationContext{RawSeverity: "LOW"})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Identity.Name != "hook_decision" {
			t.Fatalf("hook decision event name = %q", resolved.Identity.Name)
		}
		if _, err := classification.Resolve(observability.ClassificationContext{EventName: "replacement"}); err == nil {
			t.Fatal("fixed event name replacement succeeded")
		}
	})

	t.Run("enforcement state change is mandatory and has lifecycle companion", func(t *testing.T) {
		classification := mustAuditClassification(t, "quarantine")
		resolved, err := classification.Resolve(observability.ClassificationContext{
			StateChanged: true,
			MandatoryFacts: observability.MandatoryFacts{
				EnforcementStateChange: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resolved.Mandatory {
			t.Fatal("enforcement state change was not mandatory")
		}
		want := []observability.CompanionRule{observability.CompanionAssetLifecycleOnChange}
		if !reflect.DeepEqual(resolved.RequiredCompanions, want) {
			t.Fatalf("state-change companions = %v, want %v", resolved.RequiredCompanions, want)
		}
		asset, err := classification.Resolve(observability.ClassificationContext{
			Bucket:       observability.BucketAssetLifecycle,
			EventName:    observability.EventName(observability.TelemetryEventAssetQuarantined),
			RawSeverity:  "HIGH",
			StateChanged: true,
			MandatoryFacts: observability.MandatoryFacts{
				EnforcementStateChange: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if asset.Identity.Bucket != observability.BucketAssetLifecycle ||
			asset.Identity.Name != observability.EventName(observability.TelemetryEventAssetQuarantined) ||
			!asset.Mandatory {
			t.Fatalf("asset quarantine classification = %+v", asset)
		}
	})

	t.Run("generic block requires typed decision context", func(t *testing.T) {
		classification := mustAuditClassification(t, "block")
		if _, err := classification.Resolve(observability.ClassificationContext{
			RawSeverity: "HIGH",
		}); err == nil {
			t.Fatal("context-free generic block classification succeeded")
		}
		resolved, err := classification.Resolve(observability.ClassificationContext{
			Bucket:      observability.BucketEnforcementAction,
			EventName:   "enforcement.block.applied",
			RawSeverity: "HIGH",
			Enforced:    true,
			MandatoryFacts: observability.MandatoryFacts{
				EnforcedOutcome: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resolved.Mandatory || len(resolved.RequiredCompanions) != 0 {
			t.Fatalf("enforcement block resolution = %+v", resolved)
		}
	})

	t.Run("contextual identity must be a registered log event", func(t *testing.T) {
		classification := mustGatewayClassification(t, "lifecycle")
		for _, name := range []observability.EventName{
			"plausible.but.unregistered",
			"span.agent.invoke",
			"defenseclaw.agent.lifecycle.transitions",
		} {
			if _, err := classification.Resolve(observability.ClassificationContext{
				Bucket:    observability.BucketAgentLifecycle,
				EventName: name,
			}); err == nil {
				t.Errorf("contextual lifecycle accepted non-log identity %q", name)
			}
		}
	})

	t.Run("scan companion follows observed finding count", func(t *testing.T) {
		classification := mustGatewayClassification(t, "scan")
		clean, err := classification.Resolve(observability.ClassificationContext{})
		if err != nil {
			t.Fatal(err)
		}
		if len(clean.RequiredCompanions) != 0 {
			t.Fatalf("clean scan companions = %v", clean.RequiredCompanions)
		}
		withFindings, err := classification.Resolve(observability.ClassificationContext{FindingCount: 2})
		if err != nil {
			t.Fatal(err)
		}
		want := []observability.CompanionRule{observability.CompanionFindingPerObservation}
		if !reflect.DeepEqual(withFindings.RequiredCompanions, want) {
			t.Fatalf("scan-with-findings companions = %v, want %v", withFindings.RequiredCompanions, want)
		}
	})

	t.Run("finding requires source severity", func(t *testing.T) {
		classification := mustGatewayClassification(t, "scan_finding")
		if _, err := classification.Resolve(observability.ClassificationContext{}); err == nil {
			t.Fatal("finding without severity succeeded")
		}
	})

	t.Run("legacy acknowledgement preserves compatibility semantics", func(t *testing.T) {
		acknowledgement := mustAuditClassification(t, "acknowledge-alerts")
		resolved, err := acknowledgement.Resolve(observability.ClassificationContext{RawSeverity: "ACK"})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Severity.Severity != observability.SeverityInfo || !resolved.Severity.LegacyAcknowledged {
			t.Fatalf("acknowledgement severity = %+v", resolved.Severity)
		}
		overwritten := mustAuditClassification(t, "scan")
		if _, err = overwritten.Resolve(observability.ClassificationContext{RawSeverity: "ACK"}); err == nil {
			t.Fatal("overwritten legacy severity was synthesized as a canonical record")
		}
	})
}

func TestEveryClassificationResolvesOnlyRegisteredLogIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind observability.ProducerKind
		get  func(observability.ProducerKey) (observability.Classification, bool)
	}{
		{kind: observability.ProducerGatewayEvent, get: observability.GatewayEventClassification},
		{kind: observability.ProducerAuditAction, get: observability.AuditActionClassification},
	}
	for _, test := range tests {
		for _, key := range observability.ClassificationKeys(test.kind) {
			classification, ok := test.get(key)
			if !ok {
				t.Fatalf("lookup failed for %s/%s", test.kind, key)
			}
			bucket := classification.Bucket
			if bucket == "" {
				bucket = classification.AllowedContextBuckets[0]
			}
			if classification.EventNamePolicy == observability.EventNameContextRequired {
				// Every generated context-required identity is exercised by the
				// package-internal generated-row conformance test. This external
				// API test has no authority to invent a representative identity for
				// an exact generated producer context.
				if _, err := classification.Resolve(observability.ClassificationContext{
					Bucket: bucket, EventName: "plausible.but.unregistered", RawSeverity: "HIGH",
				}); err == nil {
					t.Errorf("%s/%s accepted an unregistered contextual event name", test.kind, key)
				}
				continue
			}
			eventName := classification.DefaultEventName
			resolved, err := classification.Resolve(observability.ClassificationContext{
				Bucket:      bucket,
				EventName:   eventName,
				RawSeverity: "HIGH",
			})
			if err != nil {
				t.Errorf("resolve %s/%s: %v", test.kind, key, err)
				continue
			}
			if err := resolved.Identity.Validate(); err != nil {
				t.Errorf("resolved identity for %s/%s is invalid: %v", test.kind, key, err)
			}

			if classification.EventNamePolicy == observability.EventNameFixed {
				continue
			}
			if _, err := classification.Resolve(observability.ClassificationContext{
				Bucket:      bucket,
				EventName:   "plausible.but.unregistered",
				RawSeverity: "HIGH",
			}); err == nil {
				t.Errorf("%s/%s accepted an unregistered contextual event name", test.kind, key)
			}
		}
	}
}

func mustGatewayClassification(t *testing.T, key observability.ProducerKey) observability.Classification {
	t.Helper()
	classification, ok := observability.GatewayEventClassification(key)
	if !ok {
		t.Fatalf("missing gateway classification %q", key)
	}
	return classification
}

func mustAuditClassification(t *testing.T, key observability.ProducerKey) observability.Classification {
	t.Helper()
	classification, ok := observability.AuditActionClassification(key)
	if !ok {
		t.Fatalf("missing audit classification %q", key)
	}
	return classification
}

func producerKeysAsStrings(keys []observability.ProducerKey) []string {
	result := make([]string, len(keys))
	for index, key := range keys {
		result[index] = string(key)
	}
	return result
}

func typedStringConstants(t *testing.T, relativePath, typeName string) []string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate classification test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	path := filepath.Join(repositoryRoot, relativePath)
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var result []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		declaration, ok := node.(*ast.GenDecl)
		if !ok || declaration.Tok != token.CONST {
			return true
		}
		for _, spec := range declaration.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			identifier, ok := valueSpec.Type.(*ast.Ident)
			if !ok || identifier.Name != typeName {
				continue
			}
			for _, expression := range valueSpec.Values {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s constant has non-literal value", typeName)
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s constant: %v", typeName, err)
				}
				result = append(result, value)
			}
		}
		return false
	})
	sort.Strings(result)
	return result
}
