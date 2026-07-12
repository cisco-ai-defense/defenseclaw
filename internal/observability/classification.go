// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"sort"
)

type ProducerKind string

const (
	ProducerGatewayEvent ProducerKind = "gateway_event"
	ProducerAuditAction  ProducerKind = "audit_action"
)

// ProducerKey is an observability-owned typed wire identity. Production metadata
// uses these keys without importing the producer packages that currently emit them.
type ProducerKey string

type EventNamePolicy string

const (
	EventNameFixed           EventNamePolicy = "fixed"
	EventNameContextOptional EventNamePolicy = "context_optional"
	EventNameContextRequired EventNamePolicy = "context_required"
)

type SeverityPolicy string

const (
	SeverityCanonicalOrInfo   SeverityPolicy = "canonical_or_info"
	SeverityFindingRequired   SeverityPolicy = "finding_required"
	SeverityEvaluation        SeverityPolicy = "evaluation"
	SeverityFailureOrSource   SeverityPolicy = "failure_or_source"
	SeverityMalformedOrSource SeverityPolicy = "malformed_or_source"
)

type MandatoryRule string

const (
	MandatoryAlways                        MandatoryRule = "always"
	MandatoryControlPlaneMutation          MandatoryRule = "control_plane_mutation"
	MandatoryApprovalResolution            MandatoryRule = "approval_resolution"
	MandatoryAlertMutation                 MandatoryRule = "alert_mutation"
	MandatoryProtectedBoundaryAuthFailure  MandatoryRule = "protected_boundary_auth_failure"
	MandatoryEnforcedOutcome               MandatoryRule = "enforced_outcome"
	MandatoryEnforcementStateChange        MandatoryRule = "enforcement_state_change"
	MandatorySchemaValidationFailure       MandatoryRule = "schema_validation_failure"
	MandatorySQLiteFailure                 MandatoryRule = "sqlite_failure"
	MandatoryExporterInitializationFailure MandatoryRule = "exporter_initialization_failure"
	MandatoryDurableHealthTransition       MandatoryRule = "durable_health_transition"
	MandatoryDestinationTestActivity       MandatoryRule = "destination_test_activity"
)

type CompanionRule string

const (
	CompanionEnforcementWhenEnforced CompanionRule = "enforcement_when_enforced"
	CompanionAssetLifecycleOnChange  CompanionRule = "asset_lifecycle_on_state_change"
	CompanionFindingPerObservation   CompanionRule = "finding_per_observation"
)

// MandatoryFacts are typed call-site facts. Free-form details never participate
// in floor qualification.
type MandatoryFacts struct {
	ControlPlaneMutation          bool
	ApprovalResolution            bool
	AlertMutation                 bool
	ProtectedBoundaryAuthFailure  bool
	EnforcedOutcome               bool
	EnforcementStateChange        bool
	SchemaValidationFailure       bool
	SQLiteFailure                 bool
	ExporterInitializationFailure bool
	DurableHealthTransition       bool
	DestinationTestActivity       bool
}

// Classification is immutable producer metadata. An empty Bucket means a typed
// call-site bucket is required and must belong to AllowedContextBuckets.
type Classification struct {
	Kind                  ProducerKind
	Key                   ProducerKey
	Bucket                Bucket
	DefaultEventName      EventName
	EventNamePolicy       EventNamePolicy
	SeverityPolicy        SeverityPolicy
	MandatoryRules        []MandatoryRule
	CompanionRules        []CompanionRule
	AllowedContextBuckets []Bucket
}

type ClassificationContext struct {
	Bucket         Bucket
	EventName      EventName
	RawSeverity    string
	MandatoryFacts MandatoryFacts
	Enforced       bool
	StateChanged   bool
	FindingCount   int
}

type ResolvedClassification struct {
	Identity           EventIdentity
	Severity           SeverityNormalization
	Mandatory          bool
	RequiredCompanions []CompanionRule
}

func (classification Classification) RequiresContext() bool {
	return classification.Bucket == "" || classification.EventNamePolicy == EventNameContextRequired
}

func (classification Classification) Resolve(context ClassificationContext) (ResolvedClassification, error) {
	if context.FindingCount < 0 {
		return ResolvedClassification{}, fmt.Errorf("finding count cannot be negative")
	}
	bucket := classification.Bucket
	// A context-optional producer can keep a compatibility default in one
	// bucket while explicitly allowing canonical context identities in another.
	// The generated allowed-bucket set is the authority for that override; an
	// arbitrary call-site bucket can never replace the registered default.
	if context.Bucket != "" && context.Bucket != bucket {
		if !bucketAllowed(context.Bucket, classification.AllowedContextBuckets) {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s does not allow context bucket %q",
				classification.Kind,
				classification.Key,
				context.Bucket,
			)
		}
		bucket = context.Bucket
	}
	if bucket == "" {
		if !bucketAllowed(context.Bucket, classification.AllowedContextBuckets) {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s requires one of context buckets %v, got %q",
				classification.Kind,
				classification.Key,
				classification.AllowedContextBuckets,
				context.Bucket,
			)
		}
		bucket = context.Bucket
	}

	eventName := classification.DefaultEventName
	switch classification.EventNamePolicy {
	case EventNameFixed:
		if context.EventName != "" && context.EventName != eventName {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s has fixed event name %q, got %q",
				classification.Kind,
				classification.Key,
				eventName,
				context.EventName,
			)
		}
	case EventNameContextOptional:
		if context.EventName != "" {
			eventName = context.EventName
		}
	case EventNameContextRequired:
		if context.EventName == "" {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s requires a typed event name",
				classification.Kind,
				classification.Key,
			)
		}
		eventName = context.EventName
	default:
		return ResolvedClassification{}, fmt.Errorf(
			"classification %s/%s has unknown event-name policy %q",
			classification.Kind,
			classification.Key,
			classification.EventNamePolicy,
		)
	}

	identity := EventIdentity{Bucket: bucket, Signal: SignalLogs, Name: eventName}
	if err := identity.Validate(); err != nil {
		return ResolvedClassification{}, err
	}
	// Classification exposes the generated group's compatibility-facing rule
	// unions. Runtime resolution deliberately narrows those unions to the exact
	// selected generated identity so one family cannot inherit another family's
	// mandatory or companion behavior.
	runtimeMandatoryRules := classification.MandatoryRules
	runtimeCompanionRules := classification.CompanionRules
	if group, found := lookupGeneratedProducerGroup(classification.Kind, classification.Key); found {
		if group.EventNamePolicy != classification.EventNamePolicy ||
			group.SeverityPolicy != classification.SeverityPolicy {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s disagrees with generated producer policy",
				classification.Kind,
				classification.Key,
			)
		}
		generatedIdentity, err := resolveGeneratedProducerIdentity(
			classification.Kind,
			classification.Key,
			ClassificationContext{Bucket: bucket, EventName: eventName},
		)
		if err != nil || generatedIdentity.Bucket != bucket ||
			generatedIdentity.EventName != eventName {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s identity disagrees with generated producer registry",
				classification.Kind,
				classification.Key,
			)
		}
		runtimeMandatoryRules = generatedIdentity.LegacyMandatoryRules
		runtimeCompanionRules = generatedIdentity.CompanionRules
	} else if classification.Kind == ProducerGatewayEvent || classification.Kind == ProducerAuditAction {
		return ResolvedClassification{}, fmt.Errorf(
			"classification %s/%s is absent from the generated producer registry",
			classification.Kind,
			classification.Key,
		)
	}
	severity, err := classification.resolveSeverity(context.RawSeverity)
	if err != nil {
		return ResolvedClassification{}, err
	}
	companions := make([]CompanionRule, 0, len(runtimeCompanionRules))
	for _, rule := range runtimeCompanionRules {
		switch rule {
		case CompanionEnforcementWhenEnforced:
			if context.Enforced && bucket != BucketEnforcementAction {
				companions = append(companions, rule)
			}
		case CompanionAssetLifecycleOnChange:
			if context.StateChanged {
				companions = append(companions, rule)
			}
		case CompanionFindingPerObservation:
			if context.FindingCount > 0 {
				companions = append(companions, rule)
			}
		}
	}
	return ResolvedClassification{
		Identity: identity,
		Severity: severity,
		Mandatory: Classification{
			MandatoryRules: runtimeMandatoryRules,
		}.isMandatory(context.MandatoryFacts),
		RequiredCompanions: companions,
	}, nil
}

func (classification Classification) resolveSeverity(raw string) (SeverityNormalization, error) {
	var normalized SeverityNormalization
	if classification.Kind == ProducerAuditAction {
		normalized = NormalizeLegacyAuditSeverity(classification.Key, raw)
	} else {
		normalized = NormalizeSeverity(raw)
	}
	if !normalized.Valid {
		return SeverityNormalization{}, fmt.Errorf("invalid severity %q", raw)
	}
	if normalized.LegacyAcknowledged && !normalized.Present {
		return SeverityNormalization{}, fmt.Errorf(
			"legacy ACK severity for %s/%s has no recoverable canonical severity; use the compatibility read model",
			classification.Kind,
			classification.Key,
		)
	}
	if normalized.Present {
		return normalized, nil
	}
	switch classification.SeverityPolicy {
	case SeverityFindingRequired:
		return SeverityNormalization{}, fmt.Errorf(
			"classification %s/%s requires finding severity",
			classification.Kind,
			classification.Key,
		)
	case SeverityFailureOrSource:
		return SeverityNormalization{Severity: SeverityHigh, Present: true, Valid: true}, nil
	case SeverityMalformedOrSource:
		return SeverityNormalization{Severity: SeverityMedium, Present: true, Valid: true}, nil
	default:
		return SeverityNormalization{Severity: SeverityInfo, Present: true, Valid: true}, nil
	}
}

func (classification Classification) isMandatory(facts MandatoryFacts) bool {
	for _, rule := range classification.MandatoryRules {
		switch rule {
		case MandatoryAlways:
			return true
		case MandatoryControlPlaneMutation:
			if facts.ControlPlaneMutation {
				return true
			}
		case MandatoryApprovalResolution:
			if facts.ApprovalResolution {
				return true
			}
		case MandatoryAlertMutation:
			if facts.AlertMutation {
				return true
			}
		case MandatoryProtectedBoundaryAuthFailure:
			if facts.ProtectedBoundaryAuthFailure {
				return true
			}
		case MandatoryEnforcedOutcome:
			if facts.EnforcedOutcome {
				return true
			}
		case MandatoryEnforcementStateChange:
			if facts.EnforcementStateChange {
				return true
			}
		case MandatorySchemaValidationFailure:
			if facts.SchemaValidationFailure {
				return true
			}
		case MandatorySQLiteFailure:
			if facts.SQLiteFailure {
				return true
			}
		case MandatoryExporterInitializationFailure:
			if facts.ExporterInitializationFailure {
				return true
			}
		case MandatoryDurableHealthTransition:
			if facts.DurableHealthTransition {
				return true
			}
		case MandatoryDestinationTestActivity:
			if facts.DestinationTestActivity {
				return true
			}
		}
	}
	return false
}

func bucketAllowed(bucket Bucket, allowed []Bucket) bool {
	for _, candidate := range allowed {
		if bucket == candidate {
			return true
		}
	}
	return false
}

var gatewayEventClassifications, auditActionClassifications = buildGeneratedProducerClassifications()

func GatewayEventClassification(key ProducerKey) (Classification, bool) {
	classification, ok := gatewayEventClassifications[key]
	return cloneClassification(classification), ok
}

func AuditActionClassification(key ProducerKey) (Classification, bool) {
	classification, ok := auditActionClassifications[key]
	return cloneClassification(classification), ok
}

func ClassificationKeys(kind ProducerKind) []ProducerKey {
	var source map[ProducerKey]Classification
	switch kind {
	case ProducerGatewayEvent:
		source = gatewayEventClassifications
	case ProducerAuditAction:
		source = auditActionClassifications
	default:
		return nil
	}
	keys := make([]ProducerKey, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	return keys
}

func cloneClassification(classification Classification) Classification {
	classification.MandatoryRules = append([]MandatoryRule(nil), classification.MandatoryRules...)
	classification.CompanionRules = append([]CompanionRule(nil), classification.CompanionRules...)
	classification.AllowedContextBuckets = append(
		[]Bucket(nil), classification.AllowedContextBuckets...,
	)
	return classification
}

func buildGeneratedProducerClassifications() (
	map[ProducerKey]Classification,
	map[ProducerKey]Classification,
) {
	gateway := make(map[ProducerKey]Classification)
	audit := make(map[ProducerKey]Classification)
	for index := range generatedProducerGroups {
		group := generatedProducerGroups[index]
		classification := classificationFromGeneratedProducerGroup(group)
		var target map[ProducerKey]Classification
		switch group.Kind {
		case ProducerGatewayEvent:
			target = gateway
		case ProducerAuditAction:
			target = audit
		default:
			panic(fmt.Sprintf("unknown generated producer kind %q", group.Kind))
		}
		if group.Key == "" {
			panic("generated observability classification has empty producer key")
		}
		if _, exists := target[group.Key]; exists {
			panic(fmt.Sprintf("duplicate generated observability classification %s/%s", group.Kind, group.Key))
		}
		target[group.Key] = classification
	}
	return gateway, audit
}

func classificationFromGeneratedProducerGroup(group generatedProducerGroup) Classification {
	classification := Classification{
		Kind:            group.Kind,
		Key:             group.Key,
		EventNamePolicy: group.EventNamePolicy,
		SeverityPolicy:  group.SeverityPolicy,
	}
	if group.HasDefaultIdentity {
		identity, ok := generatedProducerIdentities[group.DefaultIdentityKey]
		if !ok {
			panic(fmt.Sprintf("generated producer %s/%s has an unknown default identity", group.Kind, group.Key))
		}
		classification.Bucket = identity.Bucket
		classification.DefaultEventName = identity.EventName
	} else if group.EventNamePolicy != EventNameContextRequired {
		panic(fmt.Sprintf("generated producer %s/%s policy %q has no default identity", group.Kind, group.Key, group.EventNamePolicy))
	}

	buckets := make(map[Bucket]struct{})
	mandatoryRules := make(map[MandatoryRule]struct{})
	companionRules := make(map[CompanionRule]struct{})
	for _, rule := range group.LegacyMandatoryRules {
		mandatoryRules[rule] = struct{}{}
	}
	for _, rule := range group.CompanionRules {
		companionRules[rule] = struct{}{}
	}
	if group.ContextIdentitySetID != "" {
		set, ok := generatedProducerContextIdentitySets[group.ContextIdentitySetID]
		if !ok {
			panic(fmt.Sprintf("generated producer %s/%s has an unknown context identity set", group.Kind, group.Key))
		}
		for _, identityKey := range set.IdentityKeys {
			identity, exists := generatedProducerIdentities[identityKey]
			if !exists {
				panic(fmt.Sprintf("generated producer %s/%s context identity is unknown", group.Kind, group.Key))
			}
			buckets[identity.Bucket] = struct{}{}
		}
	}
	classification.AllowedContextBuckets = sortedGeneratedBuckets(buckets)
	classification.MandatoryRules = sortedGeneratedMandatoryRules(mandatoryRules)
	classification.CompanionRules = sortedGeneratedCompanionRules(companionRules)
	return classification
}

func sortedGeneratedBuckets(values map[Bucket]struct{}) []Bucket {
	result := make([]Bucket, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func sortedGeneratedMandatoryRules(values map[MandatoryRule]struct{}) []MandatoryRule {
	result := make([]MandatoryRule, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func sortedGeneratedCompanionRules(values map[CompanionRule]struct{}) []CompanionRule {
	result := make([]CompanionRule, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}
