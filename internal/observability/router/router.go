// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package router evaluates the immutable observability v8 collection and
// destination-routing plan. It deliberately owns no YAML parsing, redaction,
// persistence, export, or producer compatibility behavior.
package router

import (
	"fmt"
	"net/url"
	"reflect"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Admission is the result of the collection and mandatory-floor checks.
type Admission uint8

const (
	// AdmissionDrop means collection is disabled and no record may be built.
	AdmissionDrop Admission = iota
	// AdmissionOrdinary means the producer may build the ordinary canonical record.
	AdmissionOrdinary
	// AdmissionFloor means the producer may build only its minimal mandatory log.
	AdmissionFloor
)

func (admission Admission) String() string {
	switch admission {
	case AdmissionDrop:
		return "drop"
	case AdmissionOrdinary:
		return "ordinary"
	case AdmissionFloor:
		return "floor"
	default:
		return "unknown"
	}
}

// Metadata is the immutable, bounded, body-free portion of a prospective
// canonical record used by collection and selectors. Its fields are private so
// a floor-eligible classified value cannot be retargeted after construction.
type Metadata struct {
	identity    observability.EventIdentity
	severity    observability.Severity
	hasSeverity bool
	source      observability.Source
	connector   string
	action      observability.ProducerKey
	mandatory   bool
}

// NewMetadata constructs ordinary metadata. It cannot grant mandatory-floor
// eligibility; classified logs must use NewClassifiedLogMetadata.
func NewMetadata(
	identity observability.EventIdentity,
	severity *observability.Severity,
	source observability.Source,
	connector string,
	action observability.ProducerKey,
) (Metadata, error) {
	if identity.Signal == observability.SignalLogs {
		return Metadata{}, fmt.Errorf("ordinary log metadata is not supported; use registered classified-log metadata")
	}
	metadata := Metadata{
		identity:  identity,
		source:    source,
		connector: connector,
		action:    action,
	}
	if severity != nil {
		metadata.severity = *severity
		metadata.hasSeverity = true
	}
	if err := metadata.validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

// NewClassifiedLogMetadata resolves the immutable producer-classification
// registry before admission. Only its typed mandatory rules can grant the local
// floor; callers cannot set or retain that bit independently of the identity.
func NewClassifiedLogMetadata(
	kind observability.ProducerKind,
	key observability.ProducerKey,
	context observability.ClassificationContext,
	source observability.Source,
	connector string,
	action observability.ProducerKey,
) (Metadata, error) {
	classification, found := registeredClassification(kind, key)
	if !found {
		return Metadata{}, fmt.Errorf("unknown classified-log producer")
	}
	resolved, err := classification.Resolve(context)
	if err != nil {
		return Metadata{}, fmt.Errorf("classified-log metadata is invalid")
	}
	if resolved.Identity.Signal != observability.SignalLogs {
		return Metadata{}, fmt.Errorf("classified-log metadata requires a log identity")
	}
	metadata := Metadata{
		identity:  resolved.Identity,
		source:    source,
		connector: connector,
		action:    action,
		mandatory: resolved.Mandatory,
	}
	if resolved.Severity.Present {
		metadata.severity = resolved.Severity.Severity
		metadata.hasSeverity = true
	}
	if err := metadata.validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

// NewInboundImportedLogMetadata constructs ordinary-only metadata from the
// exact target/context capability pair returned by the validated inbound
// catalog. Imported logs can never acquire the local mandatory floor.
func NewInboundImportedLogMetadata(
	target observability.InboundTarget,
	context observability.InboundImportContext,
	severity *observability.Severity,
	authenticatedSource string,
) (Metadata, error) {
	expectedContext, ok := target.ImportContext()
	if !ok || expectedContext != context || target.Signal() != observability.SignalLogs ||
		target.Role() != observability.InboundTargetImport ||
		target.Bucket() != context.Bucket() || target.EventName() != context.EventName() ||
		target.DescriptorID() != context.FamilyDescriptorID() ||
		!target.AcceptsAuthenticatedSource(authenticatedSource) ||
		context.ConstructionMode() != "ordinary_import_only" ||
		!reflect.DeepEqual(context.Capabilities(), []string{"validate", "construct_ordinary"}) {
		return Metadata{}, fmt.Errorf("inbound imported-log metadata requires a validated target context")
	}
	metadata := Metadata{
		identity: observability.EventIdentity{
			Bucket: target.Bucket(), Signal: target.Signal(), Name: target.EventName(),
		},
		source: observability.SourceOTelReceiver, connector: authenticatedSource,
		mandatory: false,
	}
	if severity != nil {
		metadata.severity = *severity
		metadata.hasSeverity = true
	}
	if err := metadata.validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func registeredClassification(
	kind observability.ProducerKind,
	key observability.ProducerKey,
) (observability.Classification, bool) {
	switch kind {
	case observability.ProducerGatewayEvent:
		return observability.GatewayEventClassification(key)
	case observability.ProducerAuditAction:
		return observability.AuditActionClassification(key)
	default:
		return observability.Classification{}, false
	}
}

func (metadata Metadata) Identity() observability.EventIdentity { return metadata.identity }

func (metadata Metadata) Severity() (observability.Severity, bool) {
	return metadata.severity, metadata.hasSeverity
}

func (metadata Metadata) Source() observability.Source { return metadata.source }
func (metadata Metadata) Connector() string            { return metadata.connector }
func (metadata Metadata) Action() observability.ProducerKey {
	return metadata.action
}

// metadataFromRecord is deliberately private and used only after admission to
// verify a lazily built record. Eager records cannot be fed back into collection.
func metadataFromRecord(record observability.Record) Metadata {
	severity, hasSeverity := record.Severity()
	return Metadata{
		identity:    record.Identity(),
		severity:    severity,
		hasSeverity: hasSeverity,
		source:      record.Source(),
		connector:   record.Connector(),
		action:      observability.ProducerKey(record.Action()),
		mandatory:   record.Mandatory(),
	}
}

func (metadata Metadata) validate() error {
	if !observability.IsRegisteredEventIdentity(metadata.identity) {
		return fmt.Errorf("routing identity is not registered")
	}
	if metadata.hasSeverity {
		if _, ok := observability.SeverityRank(metadata.severity); !ok {
			return fmt.Errorf("routing severity is not canonical")
		}
	} else if metadata.severity != "" {
		return fmt.Errorf("routing severity is populated but marked absent")
	}
	if err := observability.ValidateStableToken("routing source", string(metadata.source)); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"routing connector": metadata.connector,
		"routing action":    string(metadata.action),
	} {
		if value == "" {
			continue
		}
		if err := observability.ValidateStableToken(field, value); err != nil {
			return err
		}
	}
	if metadata.mandatory && metadata.identity.Signal != observability.SignalLogs {
		return fmt.Errorf("mandatory floor is defined only for logs")
	}
	return nil
}

// RecordBuilder constructs either the ordinary record or, when requested by
// AdmissionFloor, the producer's minimal mandatory record. Evaluate never
// invokes it for AdmissionDrop. EvaluateManagedLogFallback is the sole narrow
// exception: after proving ordinary admission was AdmissionDrop and the plan
// contains the exact release-owned managed-enterprise destination, it invokes
// the builder once with AdmissionOrdinary for managed-only projection.
type RecordBuilder func(Admission) (observability.Record, error)

// Delivery identifies one selected destination route. Projection, redaction,
// and delivery are performed by later pipeline stages.
type Delivery struct {
	DestinationName  string
	DestinationKind  config.ObservabilityV8DestinationKind
	RouteName        string
	RouteIndex       int
	RedactionProfile string
	MandatoryFloor   bool
}

// Result is an immutable evaluation snapshot. Accessors return detached copies.
type Result struct {
	admission  Admission
	record     observability.Record
	hasRecord  bool
	deliveries []Delivery
}

func (result Result) Admission() Admission { return result.admission }

// Record returns a clone of the constructed record, if collection admitted it.
func (result Result) Record() (observability.Record, bool) {
	if !result.hasRecord {
		return observability.Record{}, false
	}
	return result.record.Clone(), true
}

// Deliveries returns a copy that callers may mutate safely.
func (result Result) Deliveries() []Delivery {
	return append([]Delivery(nil), result.deliveries...)
}

// ManagedLogFallbackResult is the release-owned, managed-only result for one
// ordinary collection drop. It deliberately has no Admission value: the
// ordinary verdict remains AdmissionDrop, local persistence remains disabled,
// and the enclosed canonical record is authorized only for the one generated
// managed-enterprise delivery.
type ManagedLogFallbackResult struct {
	record    observability.Record
	hasRecord bool
	delivery  Delivery
}

func (result ManagedLogFallbackResult) Record() (observability.Record, bool) {
	if !result.hasRecord {
		return observability.Record{}, false
	}
	return result.record.Clone(), true
}

func (result ManagedLogFallbackResult) Delivery() (Delivery, bool) {
	return result.delivery, result.hasRecord
}

type collectionKey struct {
	bucket observability.Bucket
	signal observability.Signal
}

type compiledSelector struct {
	buckets        map[observability.Bucket]struct{}
	bucketWildcard bool
	sources        map[observability.Source]struct{}
	connectors     map[string]struct{}
	actions        map[observability.ProducerKey]struct{}
	eventNames     map[observability.EventName]struct{}
	minSeverity    observability.Severity
}

type compiledRoute struct {
	index                    int
	name                     string
	generated                bool
	signals                  map[observability.Signal]struct{}
	selector                 compiledSelector
	action                   config.ObservabilityV8RouteAction
	redactionProfileByBucket map[observability.Bucket]string
	includesMandatoryFloor   bool
}

type compiledDestination struct {
	name         string
	kind         config.ObservabilityV8DestinationKind
	enabled      bool
	generated    bool
	firstMatch   bool
	capabilities map[observability.Signal]struct{}
	selected     map[observability.Signal]struct{}
	routes       []compiledRoute
}

// Evaluator is an immutable, race-safe runtime index derived from the v8 plan.
// It consumes the P1 compiler output and does not reinterpret source config.
type Evaluator struct {
	collection       map[collectionKey]bool
	destinations     []compiledDestination
	localDestination int
	managedFallback  int
	planDigest       string
}

// New snapshots and indexes an already compiled v8 plan. Structural checks here
// defend the runtime boundary; source validation remains the config compiler's
// responsibility.
func New(plan *config.ObservabilityV8Plan) (*Evaluator, error) {
	if plan == nil {
		return nil, fmt.Errorf("observability routing plan is required")
	}
	snapshot := plan.Snapshot()
	if snapshot.BucketCatalogVersion != observability.CurrentBucketCatalogVersion {
		return nil, fmt.Errorf("unsupported bucket catalog version %d", snapshot.BucketCatalogVersion)
	}

	evaluator := &Evaluator{
		collection:       make(map[collectionKey]bool, len(snapshot.Buckets)*len(observability.Signals())),
		destinations:     make([]compiledDestination, 0, len(snapshot.Destinations)),
		localDestination: -1,
		managedFallback:  -1,
		planDigest:       plan.Digest(),
	}
	seenBuckets := make(map[observability.Bucket]struct{}, len(snapshot.Buckets))
	for _, policy := range snapshot.Buckets {
		if !observability.IsBucket(policy.Bucket) {
			return nil, fmt.Errorf("compiled plan contains an unknown bucket")
		}
		if _, duplicate := seenBuckets[policy.Bucket]; duplicate {
			return nil, fmt.Errorf("compiled plan contains a duplicate bucket")
		}
		seenBuckets[policy.Bucket] = struct{}{}
		for _, signal := range observability.Signals() {
			evaluator.collection[collectionKey{bucket: policy.Bucket, signal: signal}] = policy.Collect.Enabled(signal)
		}
	}
	for _, bucket := range observability.Buckets() {
		if _, ok := seenBuckets[bucket]; !ok {
			return nil, fmt.Errorf("compiled plan omits a catalog bucket")
		}
	}

	seenDestinations := make(map[string]struct{}, len(snapshot.Destinations))
	for _, source := range snapshot.Destinations {
		if source.Name == "" {
			return nil, fmt.Errorf("compiled plan contains an unnamed destination")
		}
		if _, duplicate := seenDestinations[source.Name]; duplicate {
			return nil, fmt.Errorf("compiled plan contains a duplicate destination")
		}
		seenDestinations[source.Name] = struct{}{}
		destination := compileDestinationIndex(source)
		if err := validateDestinationIndex(destination); err != nil {
			return nil, err
		}
		if source.Name == config.ObservabilityV8ManagedAIDDestinationName {
			if evaluator.managedFallback >= 0 || !validManagedFallbackDestination(source, destination) {
				return nil, fmt.Errorf("compiled plan contains an invalid managed-enterprise destination")
			}
			evaluator.managedFallback = len(evaluator.destinations)
		}
		if source.Kind == config.ObservabilityV8DestinationLocalSQLite {
			if source.Name != config.ObservabilityV8LocalDestinationName || !source.Generated || !source.Enabled {
				return nil, fmt.Errorf("compiled plan contains an invalid local SQLite destination")
			}
			if evaluator.localDestination >= 0 {
				return nil, fmt.Errorf("compiled plan contains multiple local SQLite destinations")
			}
			if !validLocalDestination(destination) {
				return nil, fmt.Errorf("compiled plan contains an invalid local SQLite route")
			}
			evaluator.localDestination = len(evaluator.destinations)
		}
		evaluator.destinations = append(evaluator.destinations, destination)
	}
	if evaluator.localDestination < 0 {
		return nil, fmt.Errorf("compiled plan omits the required local SQLite destination")
	}
	return evaluator, nil
}

// validManagedFallbackDestination recognizes only the release-owned plan
// identity. Source-authored destinations cannot obtain the managed-only
// collection exception by imitating one field: the reserved name, generated
// identity, log-only capability, generated all-bucket sensitive route, and
// release-owned transport shape must all match.
func validManagedFallbackDestination(
	source config.ObservabilityV8EffectiveDestination,
	destination compiledDestination,
) bool {
	if source.Name != config.ObservabilityV8ManagedAIDDestinationName ||
		source.Kind != config.ObservabilityV8DestinationOTLP || !source.Enabled || !source.Generated ||
		source.PolicyForm != config.ObservabilityV8PolicyImplicitLocal || !source.FirstMatchPerSignal ||
		len(source.Capabilities.Signals) != 1 || source.Capabilities.Signals[0] != observability.SignalLogs ||
		len(source.SelectedSignals) != 1 || source.SelectedSignals[0] != observability.SignalLogs ||
		len(source.Routes) != 3 || len(destination.routes) != 3 ||
		source.Transport.Protocol != "http/json" || source.Transport.Method != "POST" ||
		source.Transport.LoggerName != "defenseclaw" ||
		source.ReloadApplicability.Policy != config.ObservabilityV8RestartRequired ||
		source.ReloadApplicability.Transport != config.ObservabilityV8LiveReloadable ||
		len(source.Transport.Headers) != 0 || source.Transport.TokenEnv != "" ||
		source.Transport.BearerEnv != "" || !validManagedFallbackEndpoint(source.Transport.Endpoint) ||
		source.Transport.Batch == nil || source.Transport.Batch.MaxQueueSize <= 0 ||
		source.Transport.Batch.MaxQueueBytes <= 0 || source.Transport.Batch.MaxExportBatchSize <= 0 ||
		source.Transport.Batch.MaxExportBatchBytes <= 0 || source.Transport.Batch.ScheduledDelayMS <= 0 {
		return false
	}
	diagnosticDrop := source.Routes[0]
	componentDrop := source.Routes[1]
	send := source.Routes[2]
	if !validGeneratedManagedDropRoute(
		diagnosticDrop,
		0,
		"drop-local-inventory-diagnostics",
		[]observability.ProducerKey{config.ObservabilityV8LocalInventoryDiagnosticAction},
		nil,
	) || !validGeneratedManagedDropRoute(
		componentDrop,
		1,
		"drop-managed-inventory-components",
		[]observability.ProducerKey{
			config.ObservabilityV8ManagedAgentInventoryAction,
			config.ObservabilityV8ManagedConnectorInventoryAction,
			config.ObservabilityV8ManagedMCPInventoryAction,
		},
		[]observability.EventName{"ai_component.observed"},
	) || send.Index != 2 || send.Name != "all-collected-logs" || !send.Generated ||
		len(send.Signals) != 1 || send.Signals[0] != observability.SignalLogs ||
		send.Action != config.ObservabilityV8RouteSend || send.IncludesMandatoryFloor ||
		!send.Selector.BucketWildcard || len(send.Selector.Buckets) != len(observability.Buckets()) ||
		len(send.Selector.Sources) != 0 || len(send.Selector.Connectors) != 0 ||
		len(send.Selector.Actions) != 0 || len(send.Selector.EventNames) != 0 ||
		send.Selector.MinSeverity != "" || !coversCatalog(destination.routes[2].selector.buckets) ||
		len(send.RedactionProfileByBucket) != len(observability.Buckets()) {
		return false
	}
	for _, bucket := range observability.Buckets() {
		if send.RedactionProfileByBucket[bucket] != "sensitive" {
			return false
		}
	}
	return true
}

func validGeneratedManagedDropRoute(
	route config.ObservabilityV8EffectiveRoute,
	index int,
	name string,
	actions []observability.ProducerKey,
	eventNames []observability.EventName,
) bool {
	return route.Index == index && route.Name == name && route.Generated &&
		len(route.Signals) == 1 && route.Signals[0] == observability.SignalLogs &&
		route.Action == config.ObservabilityV8RouteDrop && !route.IncludesMandatoryFloor &&
		!route.Selector.BucketWildcard &&
		reflect.DeepEqual(route.Selector.Buckets, []observability.Bucket{observability.BucketAIDiscovery}) &&
		len(route.Selector.Sources) == 0 && len(route.Selector.Connectors) == 0 &&
		reflect.DeepEqual(route.Selector.Actions, actions) &&
		reflect.DeepEqual(route.Selector.EventNames, eventNames) &&
		route.Selector.MinSeverity == "" && len(route.RedactionProfileByBucket) == 0
}

func validManagedFallbackEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Opaque == "" &&
		parsed.Host != "" && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.Path == config.ObservabilityV8ManagedAIDIngestPath &&
		parsed.EscapedPath() == config.ObservabilityV8ManagedAIDIngestPath &&
		parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery &&
		parsed.Fragment == "" && parsed.RawFragment == ""
}

// PlanDigest identifies the immutable compiled plan captured by this evaluator.
// Coordinators use it to reject dependencies assembled from different runtime
// graph generations without exposing any mutable routing state.
func (evaluator *Evaluator) PlanDigest() string {
	if evaluator == nil {
		return ""
	}
	return evaluator.planDigest
}

func validateDestinationIndex(destination compiledDestination) error {
	if len(destination.routes) > 0 && !destination.firstMatch {
		return fmt.Errorf("compiled destination does not declare first-match routing")
	}
	for position, route := range destination.routes {
		if route.index != position {
			return fmt.Errorf("compiled destination route order does not match its indexes")
		}
		if route.selector.bucketWildcard && !coversCatalog(route.selector.buckets) {
			return fmt.Errorf("compiled wildcard route does not pin the complete bucket catalog")
		}
	}
	return nil
}

func compileDestinationIndex(source config.ObservabilityV8EffectiveDestination) compiledDestination {
	destination := compiledDestination{
		name:         source.Name,
		kind:         source.Kind,
		enabled:      source.Enabled,
		generated:    source.Generated,
		firstMatch:   source.FirstMatchPerSignal,
		capabilities: signalSet(source.Capabilities.Signals),
		selected:     signalSet(source.SelectedSignals),
		routes:       make([]compiledRoute, 0, len(source.Routes)),
	}
	for _, sourceRoute := range source.Routes {
		route := compiledRoute{
			index:                    sourceRoute.Index,
			name:                     sourceRoute.Name,
			generated:                sourceRoute.Generated,
			signals:                  signalSet(sourceRoute.Signals),
			selector:                 compileSelector(sourceRoute.Selector),
			action:                   sourceRoute.Action,
			redactionProfileByBucket: cloneBucketProfiles(sourceRoute.RedactionProfileByBucket),
			includesMandatoryFloor:   sourceRoute.IncludesMandatoryFloor,
		}
		destination.routes = append(destination.routes, route)
	}
	return destination
}

func signalSet(values []observability.Signal) map[observability.Signal]struct{} {
	result := make(map[observability.Signal]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func compileSelector(source config.ObservabilityV8EffectiveSelector) compiledSelector {
	return compiledSelector{
		buckets:        setOf(source.Buckets),
		bucketWildcard: source.BucketWildcard,
		sources:        setOf(source.Sources),
		connectors:     setOf(source.Connectors),
		actions:        setOf(source.Actions),
		eventNames:     setOf(source.EventNames),
		minSeverity:    source.MinSeverity,
	}
}

func setOf[T comparable](values []T) map[T]struct{} {
	result := make(map[T]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func cloneBucketProfiles(source map[observability.Bucket]string) map[observability.Bucket]string {
	result := make(map[observability.Bucket]string, len(source))
	for bucket, profile := range source {
		result[bucket] = profile
	}
	return result
}

func validLocalDestination(destination compiledDestination) bool {
	if !destination.generated || !destination.firstMatch {
		return false
	}
	if _, ok := destination.capabilities[observability.SignalLogs]; !ok || len(destination.capabilities) != 1 {
		return false
	}
	if _, ok := destination.selected[observability.SignalLogs]; !ok || len(destination.selected) != 1 {
		return false
	}
	if len(destination.routes) != 1 {
		return false
	}
	route := destination.routes[0]
	_, logs := route.signals[observability.SignalLogs]
	if !route.generated || !logs || len(route.signals) != 1 || route.action != config.ObservabilityV8RouteSend ||
		!route.includesMandatoryFloor {
		return false
	}
	if !route.selector.bucketWildcard && len(route.selector.buckets) != len(observability.Buckets()) {
		return false
	}
	for _, bucket := range observability.Buckets() {
		if !route.selector.bucketWildcard {
			if _, ok := route.selector.buckets[bucket]; !ok {
				return false
			}
		}
		if route.redactionProfileByBucket[bucket] == "" {
			return false
		}
	}
	return true
}

func coversCatalog(buckets map[observability.Bucket]struct{}) bool {
	if len(buckets) != len(observability.Buckets()) {
		return false
	}
	for _, bucket := range observability.Buckets() {
		if _, ok := buckets[bucket]; !ok {
			return false
		}
	}
	return true
}

// Collected is the O(1) collection gate producers use before constructing body,
// attributes, events, or metric measurements. Unknown bucket/signal pairs return
// false.
func (evaluator *Evaluator) Collected(bucket observability.Bucket, signal observability.Signal) bool {
	if evaluator == nil {
		return false
	}
	return evaluator.collection[collectionKey{bucket: bucket, signal: signal}]
}

// Admit evaluates collection before any record construction. The mandatory
// exception applies only to disabled logs and selects only the local floor path.
func (evaluator *Evaluator) Admit(metadata Metadata) (Admission, error) {
	if evaluator == nil {
		return AdmissionDrop, fmt.Errorf("observability evaluator is nil")
	}
	if err := metadata.validate(); err != nil {
		return AdmissionDrop, err
	}
	if evaluator.Collected(metadata.identity.Bucket, metadata.identity.Signal) {
		return AdmissionOrdinary, nil
	}
	if metadata.identity.Signal == observability.SignalLogs && metadata.mandatory {
		return AdmissionFloor, nil
	}
	return AdmissionDrop, nil
}

// Evaluate applies admission lazily, verifies the constructed record matches the
// admitted metadata, and computes all independent destination selections.
func (evaluator *Evaluator) Evaluate(metadata Metadata, builder RecordBuilder) (Result, error) {
	admission, err := evaluator.Admit(metadata)
	if err != nil {
		return Result{}, err
	}
	result := Result{admission: admission}
	if admission == AdmissionDrop {
		return result, nil
	}
	if builder == nil {
		return Result{}, fmt.Errorf("record builder is required for %s admission", admission)
	}
	record, err := builder(admission)
	if err != nil {
		return Result{}, err
	}
	if err := verifyBuiltRecord(metadata, admission, record); err != nil {
		return Result{}, err
	}
	result.record = record.Clone()
	result.hasRecord = true
	result.deliveries = evaluator.route(metadata, admission)
	return result, nil
}

// EvaluateManagedLogFallback is the only release-owned exception to ordinary
// collection-before-construction. It first proves that ordinary evaluation is
// AdmissionDrop, then proves that the active immutable plan contains and
// selects the exact generated managed-enterprise log destination. Only then is
// the ordinary canonical record built once and validated. The result carries
// no local or operator-authored delivery and cannot apply to mandatory-floor,
// trace, or metric admission.
func (evaluator *Evaluator) EvaluateManagedLogFallback(
	metadata Metadata,
	builder RecordBuilder,
) (ManagedLogFallbackResult, error) {
	admission, err := evaluator.Admit(metadata)
	if err != nil {
		return ManagedLogFallbackResult{}, err
	}
	if admission != AdmissionDrop || metadata.identity.Signal != observability.SignalLogs ||
		metadata.source == observability.SourceOTelReceiver ||
		evaluator.managedFallback < 0 || evaluator.managedFallback >= len(evaluator.destinations) {
		return ManagedLogFallbackResult{}, nil
	}
	destination := evaluator.destinations[evaluator.managedFallback]
	deliveries := routeDestination(destination, metadata, false)
	if len(deliveries) != 1 ||
		deliveries[0].DestinationName != config.ObservabilityV8ManagedAIDDestinationName ||
		deliveries[0].DestinationKind != config.ObservabilityV8DestinationOTLP ||
		deliveries[0].MandatoryFloor || deliveries[0].RedactionProfile != "sensitive" {
		return ManagedLogFallbackResult{}, nil
	}
	if builder == nil {
		return ManagedLogFallbackResult{}, fmt.Errorf("record builder is required for managed-only fallback")
	}
	record, err := builder(AdmissionOrdinary)
	if err != nil {
		return ManagedLogFallbackResult{}, err
	}
	if err := verifyBuiltRecord(metadata, AdmissionOrdinary, record); err != nil {
		return ManagedLogFallbackResult{}, err
	}
	return ManagedLogFallbackResult{
		record: record.Clone(), hasRecord: true, delivery: deliveries[0],
	}, nil
}

func verifyBuiltRecord(metadata Metadata, admission Admission, record observability.Record) error {
	built := metadataFromRecord(record)
	if built != metadata {
		return fmt.Errorf("constructed record metadata does not match admitted metadata")
	}
	switch admission {
	case AdmissionFloor:
		if !record.Mandatory() || !record.IsFloorOnly() {
			return fmt.Errorf("floor admission requires an authenticated minimal floor record")
		}
	case AdmissionOrdinary:
		if record.IsFloorOnly() {
			return fmt.Errorf("ordinary admission rejects floor-only records")
		}
	default:
		return fmt.Errorf("constructed record has no admitted collection path")
	}
	return nil
}

func (evaluator *Evaluator) route(metadata Metadata, admission Admission) []Delivery {
	if admission == AdmissionFloor {
		destination := evaluator.destinations[evaluator.localDestination]
		return routeDestination(destination, metadata, true)
	}
	deliveries := make([]Delivery, 0, len(evaluator.destinations))
	for _, destination := range evaluator.destinations {
		deliveries = append(deliveries, routeDestination(destination, metadata, false)...)
	}
	return deliveries
}

func routeDestination(destination compiledDestination, metadata Metadata, floorOnly bool) []Delivery {
	if !destination.enabled {
		return nil
	}
	if _, ok := destination.capabilities[metadata.identity.Signal]; !ok {
		return nil
	}
	if _, ok := destination.selected[metadata.identity.Signal]; !ok {
		return nil
	}
	for _, route := range destination.routes {
		if floorOnly && !route.includesMandatoryFloor {
			continue
		}
		if _, ok := route.signals[metadata.identity.Signal]; !ok {
			continue
		}
		if !route.selector.matches(metadata) {
			continue
		}
		if route.action != config.ObservabilityV8RouteSend {
			return nil
		}
		profile := ""
		if metadata.identity.Signal != observability.SignalMetrics {
			profile = route.redactionProfileByBucket[metadata.identity.Bucket]
		}
		return []Delivery{{
			DestinationName:  destination.name,
			DestinationKind:  destination.kind,
			RouteName:        route.name,
			RouteIndex:       route.index,
			RedactionProfile: profile,
			MandatoryFloor:   floorOnly,
		}}
	}
	return nil
}

func (selector compiledSelector) matches(metadata Metadata) bool {
	if !selector.bucketWildcard &&
		!matchesValue(selector.buckets, metadata.identity.Bucket, observability.Bucket("*")) {
		return false
	}
	if !matchesValue(selector.sources, metadata.source, observability.Source("*")) {
		return false
	}
	if !matchesValue(selector.connectors, metadata.connector, "*") {
		return false
	}
	if !matchesValue(selector.actions, metadata.action, observability.ProducerKey("*")) {
		return false
	}
	if !matchesValue(selector.eventNames, metadata.identity.Name, observability.EventName("*")) {
		return false
	}
	if selector.minSeverity != "" {
		if !metadata.hasSeverity {
			return false
		}
		minimum, minimumOK := observability.SeverityRank(selector.minSeverity)
		actual, actualOK := observability.SeverityRank(metadata.severity)
		if !minimumOK || !actualOK || actual < minimum {
			return false
		}
	}
	return true
}

func matchesValue[T comparable](allowed map[T]struct{}, actual, wildcard T) bool {
	if len(allowed) == 0 {
		return true
	}
	var zero T
	if actual == zero {
		return false
	}
	if _, ok := allowed[wildcard]; ok {
		return true
	}
	_, ok := allowed[actual]
	return ok
}
