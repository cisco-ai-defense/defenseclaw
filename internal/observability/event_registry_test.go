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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

func TestEventNameRegistryRejectsArbitraryWellShapedNames(t *testing.T) {
	t.Parallel()

	for _, name := range []EventName{
		"plausible.but.unregistered",
		"arbitrary_snake_case",
		"span.unregistered.family",
		"defenseclaw.unregistered.metric",
		"",
	} {
		if IsRegisteredEventName(name) {
			t.Errorf("arbitrary event name %q is registered", name)
		}
	}
	for _, name := range []EventName{
		"finding.observed",
		"hook_decision",
		"session_start",
		"span.workflow.run",
		"defenseclaw.gateway.events.emitted",
		"gen_ai.client.token.usage",
	} {
		if !IsRegisteredEventName(name) {
			t.Errorf("declared event name %q is not registered", name)
		}
	}
}

func TestEventNamesAreSortedUniqueAndCopySafe(t *testing.T) {
	t.Parallel()

	first := EventNames()
	if len(first) == 0 {
		t.Fatal("event registry is empty")
	}
	if !sort.SliceIsSorted(first, func(left, right int) bool { return first[left] < first[right] }) {
		t.Fatal("EventNames is not sorted")
	}
	for i, name := range first {
		if !IsRegisteredEventName(name) {
			t.Errorf("EventNames returned unregistered name %q", name)
		}
		if i > 0 && first[i-1] == name {
			t.Errorf("EventNames contains duplicate %q", name)
		}
	}

	wantFirst := first[0]
	first[0] = "caller.mutation"
	second := EventNames()
	if second[0] != wantFirst {
		t.Fatalf("caller mutated event registry: got first name %q, want %q", second[0], wantFirst)
	}
}

func TestEventNameSignalMembershipIsExhaustiveAndDisjoint(t *testing.T) {
	t.Parallel()

	for _, family := range generatedFamilyIdentityDescriptors() {
		if !IsRegisteredEventNameForSignal(family.Identity.Signal, family.Identity.Name) {
			t.Errorf("%q is not registered for %q", family.Identity.Name, family.Identity.Signal)
		}
		for _, other := range Signals() {
			if other != family.Identity.Signal && IsRegisteredEventNameForSignal(other, family.Identity.Name) {
				t.Errorf("%q is unexpectedly registered for both %q and %q", family.Identity.Name, family.Identity.Signal, other)
			}
		}
	}

	for _, name := range classificationDefaultEventNames() {
		if !IsRegisteredEventNameForSignal(SignalLogs, name) {
			t.Errorf("classification default %q is not registered for logs", name)
		}
		if IsRegisteredEventNameForSignal(SignalTraces, name) ||
			IsRegisteredEventNameForSignal(SignalMetrics, name) {
			t.Errorf("classification default %q leaked into another signal", name)
		}
	}

	for _, signal := range []Signal{"", "profiles"} {
		if IsRegisteredEventNameForSignal(signal, "session_start") {
			t.Errorf("unknown signal %q accepted an event name", signal)
		}
	}
}

func TestRegisteredIdentityRequiresCatalogBucketAndMatchingSignal(t *testing.T) {
	t.Parallel()

	valid := []EventIdentity{
		{Bucket: BucketAgentLifecycle, Signal: SignalLogs, Name: "session_start"},
		{Bucket: BucketAgentLifecycle, Signal: SignalTraces, Name: "span.agent.invoke"},
		{Bucket: BucketAgentLifecycle, Signal: SignalMetrics, Name: "defenseclaw.agent.lifecycle.transitions"},
	}
	for _, identity := range valid {
		if !IsRegisteredEventIdentity(identity) {
			t.Errorf("registered identity predicate rejected %+v", identity)
		}
		if err := identity.Validate(); err != nil {
			t.Errorf("registered identity validation rejected %+v: %v", identity, err)
		}
	}

	invalid := []EventIdentity{
		{Bucket: "not-a-bucket", Signal: SignalLogs, Name: "session_start"},
		{Bucket: BucketAgentLifecycle, Signal: "profiles", Name: "session_start"},
		{Bucket: BucketModelIO, Signal: SignalLogs, Name: "session_start"},
		{Bucket: BucketAgentLifecycle, Signal: SignalLogs, Name: "span.agent.invoke"},
		{Bucket: BucketAgentLifecycle, Signal: SignalTraces, Name: "session_start"},
		{Bucket: BucketAgentLifecycle, Signal: SignalMetrics, Name: "plausible.metric"},
	}
	for _, identity := range invalid {
		if IsRegisteredEventIdentity(identity) {
			t.Errorf("registered identity predicate accepted %+v", identity)
		}
		if err := identity.Validate(); err == nil {
			t.Errorf("registered identity validation accepted %+v", identity)
		}
	}
}

func TestGeneratedFamilyIdentityAuthorityIsCompleteExactAndValid(t *testing.T) {
	t.Parallel()

	families := generatedFamilyIdentityDescriptors()
	if len(families) == 0 {
		t.Fatal("generated family identity inventory is empty")
	}
	wantSignals := map[Signal]bool{SignalLogs: false, SignalTraces: false, SignalMetrics: false}
	familyIDs := make(map[string]struct{}, len(families))
	identities := make(map[EventIdentity]struct{}, len(families))
	for _, family := range families {
		if family.FamilyID == "" || family.Descriptor == nil {
			t.Fatalf("incomplete generated family row: %+v", family)
		}
		if _, duplicate := familyIDs[family.FamilyID]; duplicate {
			t.Fatalf("duplicate generated family ID %q", family.FamilyID)
		}
		if _, duplicate := identities[family.Identity]; duplicate {
			t.Fatalf("duplicate generated family identity %+v", family.Identity)
		}
		familyIDs[family.FamilyID] = struct{}{}
		identities[family.Identity] = struct{}{}
		wantSignals[family.Identity.Signal] = true
		if !IsRegisteredEventIdentity(family.Identity) {
			t.Errorf("generated family identity is not registered: %+v", family.Identity)
		}
		contract := family.Descriptor.familyDescriptorContract()
		if contract.id != family.FamilyID || contract.identity != family.Identity {
			t.Errorf("generated row disagrees with descriptor: row=%+v contract=%+v", family, contract.identity)
		}
		if err := validateFamilyDescriptor(contract, familySignalForTest(t, family.Identity.Signal)); err != nil {
			t.Errorf("generated descriptor %q is invalid: %v", family.FamilyID, err)
		}
	}
	if !wantSignals[SignalLogs] || !wantSignals[SignalTraces] || !wantSignals[SignalMetrics] {
		t.Fatalf("generated family inventory omits a signal: %v", wantSignals)
	}

	wrongBucket := families[0].Descriptor.familyDescriptorContract()
	if wrongBucket.identity.Bucket == BucketModelIO {
		wrongBucket.identity.Bucket = BucketAgentLifecycle
	} else {
		wrongBucket.identity.Bucket = BucketModelIO
	}
	if err := validateFamilyDescriptor(wrongBucket, familySignalForTest(t, wrongBucket.identity.Signal)); !IsFamilyBuildError(err, FamilyBuildInvalidDescriptor) {
		t.Fatalf("wrong valid bucket descriptor error=%v, want %q", err, FamilyBuildInvalidDescriptor)
	}
}

func TestGeneratedProducerIdentitiesMatchFamilyAuthorityOrExplicitCompatibility(t *testing.T) {
	t.Parallel()

	families := make(map[string]EventIdentity, len(generatedFamilyIdentityDescriptors()))
	for _, family := range generatedFamilyIdentityDescriptors() {
		families[family.FamilyID] = family.Identity
	}
	compatibilityCount := 0
	for _, producer := range generatedProducerGroups {
		for _, row := range generatedProducerGroupIdentities(producer) {
			label := fmt.Sprintf("%s/%s:%s/%s", producer.Kind, producer.Key, row.Bucket, row.EventName)
			identity := EventIdentity{Bucket: row.Bucket, Signal: SignalLogs, Name: row.EventName}
			if row.CompatibilityOnly {
				compatibilityCount++
				if row.FamilyRefs.FamilyDescriptorID != "" || row.FamilyRefs.SelectedFamilyFloorID != "" {
					t.Errorf("compatibility identity %q references a canonical family", label)
				}
				if !IsRegisteredEventIdentity(identity) {
					t.Errorf("compatibility identity %q is not registered exactly: %+v", label, identity)
				}
				continue
			}
			if canonical, ok := families[row.FamilyRefs.FamilyDescriptorID]; !ok || canonical != identity {
				t.Errorf("producer identity %q identity=%+v, canonical=%+v present=%v", label, identity, canonical, ok)
			}
		}
	}
	if compatibilityCount == 0 {
		t.Fatal("generated producer catalog has no compatibility-only identity coverage")
	}
}

func TestClassificationsResolveEveryGeneratedIdentityWithGeneratedRules(t *testing.T) {
	t.Parallel()

	allFacts := MandatoryFacts{
		ControlPlaneMutation: true, ApprovalResolution: true, AlertMutation: true,
		ProtectedBoundaryAuthFailure: true, EnforcedOutcome: true,
		EnforcementStateChange: true, SchemaValidationFailure: true,
		SQLiteFailure: true, ExporterInitializationFailure: true,
		DurableHealthTransition: true, DestinationTestActivity: true,
		ManagedAIDFailOpen: true,
	}
	for _, group := range generatedProducerGroups {
		var (
			classification Classification
			found          bool
		)
		switch group.Kind {
		case ProducerGatewayEvent:
			classification, found = GatewayEventClassification(group.Key)
		case ProducerAuditAction:
			classification, found = AuditActionClassification(group.Key)
		default:
			t.Fatalf("generated producer %s/%s has unknown kind", group.Kind, group.Key)
		}
		if !found {
			t.Fatalf("generated producer %s/%s has no public classification", group.Kind, group.Key)
		}
		if classification.EventNamePolicy != group.EventNamePolicy ||
			classification.SeverityPolicy != group.SeverityPolicy {
			t.Fatalf("producer %s/%s public and generated policies disagree", group.Kind, group.Key)
		}
		for _, identity := range generatedProducerGroupIdentities(group) {
			label := fmt.Sprintf("%s/%s:%s/%s", group.Kind, group.Key, identity.Bucket, identity.EventName)
			context := ClassificationContext{
				Bucket: identity.Bucket, EventName: identity.EventName, RawSeverity: "HIGH",
				MandatoryFacts: allFacts, Enforced: true, StateChanged: true, FindingCount: 1,
			}
			resolved, err := classification.Resolve(context)
			if err != nil {
				t.Fatalf("resolve generated identity %s: %v", label, err)
			}
			wantIdentity := EventIdentity{
				Bucket: identity.Bucket, Signal: SignalLogs, Name: identity.EventName,
			}
			if resolved.Identity != wantIdentity {
				t.Fatalf("generated identity %s resolved identity=%+v want=%+v", label, resolved.Identity, wantIdentity)
			}
			if resolved.Mandatory != (len(identity.LegacyMandatoryRules) != 0) {
				t.Fatalf("generated identity %s mandatory=%t rules=%v", label, resolved.Mandatory, identity.LegacyMandatoryRules)
			}
			wantCompanions := make([]CompanionRule, 0, len(identity.CompanionRules))
			for _, rule := range identity.CompanionRules {
				switch rule {
				case CompanionEnforcementWhenEnforced:
					if identity.Bucket != BucketEnforcementAction {
						wantCompanions = append(wantCompanions, rule)
					}
				case CompanionAssetLifecycleOnChange, CompanionFindingPerObservation:
					wantCompanions = append(wantCompanions, rule)
				default:
					t.Fatalf("generated identity %s has unknown companion %q", label, rule)
				}
			}
			if !reflect.DeepEqual(resolved.RequiredCompanions, wantCompanions) {
				t.Fatalf("generated identity %s companions=%v want=%v", label, resolved.RequiredCompanions, wantCompanions)
			}
		}
	}
}

func TestClassifiedDefaultEventNamesMatchReviewedSnapshot(t *testing.T) {
	t.Parallel()

	names := classificationDefaultEventNames()
	for _, name := range names {
		if !IsRegisteredEventName(name) {
			t.Errorf("classified default event name %q is not registered", name)
		}
	}

	const wantSHA256 = "5cc2f2850b00149772a06377b792307ed417f454b261827fa3157f95731af4ae"
	sum := sha256.Sum256([]byte(strings.Join(eventNamesToStrings(names), "\n")))
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		t.Fatalf("classified default event-name snapshot changed: sha256=%s names=%v", got, names)
	}
}

func TestMetricInstrumentEventNamesMatchGeneratedCatalog(t *testing.T) {
	t.Parallel()

	var catalog struct {
		Families []struct {
			EventName EventName `json:"event_name"`
			Signal    Signal    `json:"signal"`
		} `json:"families"`
	}
	if err := json.Unmarshal(publicschemas.TelemetryV8Catalog(), &catalog); err != nil {
		t.Fatalf("decode embedded telemetry catalog: %v", err)
	}

	fromCatalog := make([]EventName, 0, len(catalog.Families))
	for _, family := range catalog.Families {
		if family.Signal != SignalMetrics {
			continue
		}
		fromCatalog = append(fromCatalog, family.EventName)
		if !IsRegisteredEventName(family.EventName) {
			t.Errorf("generated metric %q is not registered", family.EventName)
		}
	}
	assertSameEventNameSet(t, generatedFamilyEventNames(SignalMetrics), fromCatalog)
}

func TestSpanFamilyEventNamesMatchSpecCatalog(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(repositoryFile(t, "docs/design/observability-v8/11-trace-and-span-contract.md"))
	if err != nil {
		t.Fatalf("read trace contract: %v", err)
	}
	inCatalog := false
	var fromSpec []EventName
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "## 7. Span Family Catalog":
			inCatalog = true
		case inCatalog && strings.HasPrefix(line, "## "):
			inCatalog = false
		case inCatalog && strings.HasPrefix(line, "| `"):
			columns := strings.Split(line, "|")
			if len(columns) < 4 {
				t.Fatalf("malformed span family table row %q", line)
			}
			family := strings.Trim(strings.TrimSpace(columns[2]), "`")
			fromSpec = append(fromSpec, EventName(family))
		}
	}
	if len(fromSpec) == 0 {
		t.Fatal("span family catalog was not found in trace contract")
	}
	for _, family := range fromSpec {
		if !IsRegisteredEventName(family) {
			t.Errorf("declared span family %q is not registered", family)
		}
	}
	assertSameEventNameSet(t, generatedFamilyEventNames(SignalTraces), fromSpec)
}

func TestLifecycleCompatibilityNamesMatchCanonicalSchema(t *testing.T) {
	t.Parallel()

	var schema struct {
		Properties map[string]struct {
			Enum []EventName `json:"enum"`
		} `json:"properties"`
	}
	readJSONFile(t, repositoryFile(t, "schemas/otel/agent-lifecycle-event.schema.json"), &schema)
	fromSchema := schema.Properties["defenseclaw.agent.lifecycle.event"].Enum
	want := make([]EventName, 0, len(fromSchema))
	for _, family := range generatedFamilyIdentityDescriptors() {
		if strings.HasPrefix(family.FamilyID, "log.compat.") && family.Identity.Name != "hook_decision" {
			want = append(want, family.Identity.Name)
		}
		if strings.HasPrefix(family.FamilyID, "log.compat.") && !IsRegisteredEventName(family.Identity.Name) {
			t.Errorf("compatibility event name %q is not registered", family.Identity.Name)
		}
	}
	assertSameEventNameSet(t, want, fromSchema)
}

func TestPreviouslyMissingDiscoveryFamilyBuildersSucceed(t *testing.T) {
	t.Parallel()

	builder, _ := testFamilyBuilder(t)
	tests := []struct {
		name  string
		want  EventIdentity
		build func() (Record, error)
	}{
		{
			name: "agent completed",
			want: EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalLogs, Name: "agent.discovery.completed"},
			build: func() (Record, error) {
				return builder.BuildLogAgentDiscoveryCompleted(LogAgentDiscoveryCompletedInput{
					Envelope: testFamilyEnvelope(), Outcome: OutcomeCompleted,
					DefenseClawAgentDiscoverySource: "cli", DefenseClawAgentDiscoveryCacheHit: false,
					DefenseClawAgentDiscoveryResult: "ok", DefenseClawAgentDiscoveryDurationMs: 1,
					DefenseClawAgentDiscoveryAgentsTotal: 2, DefenseClawAgentDiscoveryInstalledTotal: 1,
				})
			},
		},
		{
			name: "agent rejected",
			want: EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalLogs, Name: "agent.discovery.rejected"},
			build: func() (Record, error) {
				return builder.BuildLogAgentDiscoveryRejected(LogAgentDiscoveryRejectedInput{
					Envelope: testFamilyEnvelope(), Outcome: OutcomeRejected,
					DefenseClawAgentDiscoverySource: "api", DefenseClawAgentDiscoveryResult: "malformed",
				})
			},
		},
		{
			name: "agent signal",
			want: EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalLogs, Name: "agent.discovery.signal"},
			build: func() (Record, error) {
				return builder.BuildLogAgentDiscoverySignal(LogAgentDiscoverySignalInput{
					Envelope: testFamilyEnvelope(), DefenseClawAgentDiscoveryConnector: "codex",
					DefenseClawAgentDiscoveryInstalled: true, DefenseClawAgentDiscoveryHasConfig: true,
					DefenseClawAgentDiscoveryHasBinary: true, DefenseClawAgentDiscoveryProbeStatus: "ok",
				})
			},
		},
		{
			name: "AI discovery completed",
			want: EventIdentity{Bucket: BucketAIDiscovery, Signal: SignalLogs, Name: "ai.discovery.completed"},
			build: func() (Record, error) {
				return builder.BuildLogAIDiscoveryCompleted(LogAIDiscoveryCompletedInput{
					Envelope: testFamilyEnvelope(), Outcome: OutcomeCompleted,
					DefenseClawAIDiscoveryScanID: "scan-1", DefenseClawAIDiscoverySource: "sidecar",
					DefenseClawAIDiscoveryPrivacyMode: "enhanced", DefenseClawAIDiscoveryResult: "ok",
					DefenseClawAIDiscoveryDurationMs: 1, DefenseClawAIDiscoverySignalsTotal: 3,
					DefenseClawAIDiscoveryActiveSignals: 2, DefenseClawAIDiscoveryNewSignals: 1,
					DefenseClawAIDiscoveryChangedSignals: 0, DefenseClawAIDiscoveryGoneSignals: 0,
					DefenseClawAIDiscoveryFilesScanned: 4, DefenseClawAIDiscoveryDedupeSuppressed: 0,
					DefenseClawAIDiscoveryErrors: 0,
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, err := test.build()
			if err != nil {
				t.Fatal(err)
			}
			if record.Identity() != test.want {
				t.Fatalf("identity=%+v, want %+v", record.Identity(), test.want)
			}
		})
	}
}

func generatedFamilyEventNames(signal Signal) []EventName {
	names := make([]EventName, 0, len(generatedFamilyIdentityDescriptors()))
	for _, family := range generatedFamilyIdentityDescriptors() {
		if family.Identity.Signal == signal {
			names = append(names, family.Identity.Name)
		}
	}
	return names
}

func familySignalForTest(t *testing.T, signal Signal) familySignal {
	t.Helper()
	switch signal {
	case SignalLogs:
		return familySignalLog
	case SignalTraces:
		return familySignalTrace
	case SignalMetrics:
		return familySignalMetric
	default:
		t.Fatalf("unknown generated signal %q", signal)
		return familySignalInvalid
	}
}

func classificationDefaultEventNames() []EventName {
	unique := make(map[EventName]struct{})
	for _, classifications := range []map[ProducerKey]Classification{
		gatewayEventClassifications,
		auditActionClassifications,
	} {
		for _, classification := range classifications {
			if classification.DefaultEventName != "" {
				unique[classification.DefaultEventName] = struct{}{}
			}
		}
	}
	names := make([]EventName, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool { return names[left] < names[right] })
	return names
}

func assertSameEventNameSet(t *testing.T, left, right []EventName) {
	t.Helper()
	leftCopy := append([]EventName(nil), left...)
	rightCopy := append([]EventName(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	if !reflect.DeepEqual(leftCopy, rightCopy) {
		t.Fatalf("event-name sets differ\nregistry: %v\nsource:   %v", leftCopy, rightCopy)
	}
}

func eventNamesToStrings(names []EventName) []string {
	result := make([]string, len(names))
	for i, name := range names {
		result[i] = string(name)
	}
	return result
}

func repositoryFile(t *testing.T, path string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve event registry test path")
	}
	return filepath.Join(filepath.Dir(currentFile), "..", "..", path)
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
