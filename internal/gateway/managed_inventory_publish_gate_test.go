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

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// managedGateEmitter is a capture that can also fail, so the "an emit error must
// not record a digest" path is reachable.
type managedGateEmitter struct {
	endpointInventoryCapture
	failEventName observability.EventName
}

func (emitter *managedGateEmitter) Emit(
	ctx context.Context,
	metadata router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if emitter.failEventName != "" {
		record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
		if err == nil && record.EventName() == emitter.failEventName {
			return pipeline.LocalLogOutcome{}, errors.New("emit rejected")
		}
	}
	return emitter.endpointInventoryCapture.Emit(ctx, metadata, build)
}

// managedGateScanCounts counts the endpoint-inventory records per collection so a
// test can distinguish "collection republished in full" from "silent".
func managedGateScanCounts(records []observability.Record) map[string]int {
	counts := map[string]int{}
	for _, record := range records {
		if record.EventName() == "ai.discovery.completed" {
			counts["signals_summary"]++
			continue
		}
		counts[string(record.EventName())]++
	}
	return counts
}

func managedGateReport(scanID string, skills ...string) inventory.AIDiscoveryReport {
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: scanID, Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: len(skills), ActiveSignals: len(skills),
		},
	}
	for _, skill := range skills {
		report.Signals = append(report.Signals, inventory.AISignal{
			SignalID: "ai-skill-" + skill, SignatureID: "skill", Category: inventory.SignalSkill,
			Vendor: "local", Product: skill, Confidence: .9, State: inventory.AIStateSeen,
			Detector: "skill_dir", EvidenceHash: "evidence-" + skill,
			Basenames: []string{skill},
			// skill_entry is the evidence type discoveredEntriesFromReport
			// enumerates; a bare directory row would produce no component.
			Evidence: []inventory.AIEvidence{{
				Type: "skill_entry", Basename: skill, PathHash: "hash-" + skill,
				Quality: 1, Origin: "user",
			}},
		})
	}
	return report
}

// TestEmitEndpointInventoryGateSuppressesUnchangedCollections is the headline
// behavior: a steady-state managed endpoint publishes nothing after the baseline.
func TestEmitEndpointInventoryGateSuppressesUnchangedCollections(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()
	report := managedGateReport("scan-1", "alpha")

	baseline := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, baseline, false, &report, gate,
	); err != nil {
		t.Fatal(err)
	}
	baselineRecords := baseline.snapshot()
	if len(baselineRecords) == 0 {
		t.Fatal("baseline published nothing")
	}
	// Every collection of one cycle must share a single scan id so the cloud can
	// recognize the bundle as a set.
	scanIDs := map[string]struct{}{}
	for _, record := range baselineRecords {
		body := canonicalBody(t, record)
		if id, ok := body[observability.TelemetryAttributeDefenseClawAIDiscoveryScanID].(string); ok {
			scanIDs[id] = struct{}{}
		}
	}
	if len(scanIDs) != 1 {
		t.Fatalf("bundle spanned %d scan ids: %v", len(scanIDs), scanIDs)
	}
	if _, ok := scanIDs["inventory-scan-1"]; !ok {
		t.Fatalf("bundle scan id not derived from the discovery scan: %v", scanIDs)
	}

	// Second identical cycle: nothing at all.
	steady := &endpointInventoryCapture{}
	unchanged := managedGateReport("scan-2", "alpha")
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, steady, false, &unchanged, gate,
	); err != nil {
		t.Fatal(err)
	}
	if records := steady.snapshot(); len(records) != 0 {
		t.Fatalf("steady-state cycle published %d records: %v", len(records),
			managedGateScanCounts(records))
	}

	// A new skill republishes the skill collection only.
	changed := &endpointInventoryCapture{}
	added := managedGateReport("scan-3", "alpha", "beta")
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, changed, false, &added, gate,
	); err != nil {
		t.Fatal(err)
	}
	sources := map[string]int{}
	for _, record := range changed.snapshot() {
		body := canonicalBody(t, record)
		source, _ := body[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
		sources[source]++
	}
	if sources["endpoint_skill_inventory"] == 0 {
		t.Fatalf("added skill did not republish its collection: %v", sources)
	}
	for _, quiet := range []string{
		"endpoint_connector_inventory", "endpoint_mcp_inventory",
		"endpoint_per_connector_mcp_inventory",
	} {
		if sources[quiet] != 0 {
			t.Fatalf("collection %s republished for an unrelated change: %v", quiet, sources)
		}
	}

	// Removing it publishes exactly once, then settles.
	removed := &endpointInventoryCapture{}
	back := managedGateReport("scan-4", "alpha")
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, removed, false, &back, gate,
	); err != nil {
		t.Fatal(err)
	}
	if len(removed.snapshot()) == 0 {
		t.Fatal("removal was not published")
	}
	settled := &endpointInventoryCapture{}
	again := managedGateReport("scan-5", "alpha")
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, settled, false, &again, gate,
	); err != nil {
		t.Fatal(err)
	}
	if records := settled.snapshot(); len(records) != 0 {
		t.Fatalf("cycle after a removal published %d records", len(records))
	}
}

// TestEmitEndpointInventoryGateDailyBundleRepublishesEverything covers the
// guarantee that a cloud which missed the baseline re-baselines within a day.
func TestEmitEndpointInventoryGateDailyBundleRepublishesEverything(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()

	baselineReport := managedGateReport("scan-1", "alpha")
	baseline := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, baseline, false, &baselineReport, gate,
	); err != nil {
		t.Fatal(err)
	}
	baselineCount := len(baseline.snapshot())
	if baselineCount == 0 {
		t.Fatal("baseline published nothing")
	}

	// Backdate the bundle clock the way an operator or a real day would.
	gate.mu.Lock()
	gate.file.FullBundleAt = time.Now().UTC().Add(-managedInventoryFullBundleInterval - time.Minute)
	gate.cycleKnown = false
	gate.mu.Unlock()

	dueReport := managedGateReport("scan-2", "alpha")
	due := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, due, false, &dueReport, gate,
	); err != nil {
		t.Fatal(err)
	}
	if got := len(due.snapshot()); got != baselineCount {
		t.Fatalf("daily bundle published %d records, baseline was %d", got, baselineCount)
	}
	if managedPublishReadFile(t, gate).FullBundleAt.Before(
		time.Now().UTC().Add(-time.Minute),
	) {
		t.Fatal("daily bundle did not re-stamp the bundle clock")
	}

	// And the next cycle is quiet again.
	quietReport := managedGateReport("scan-3", "alpha")
	quiet := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, quiet, false, &quietReport, gate,
	); err != nil {
		t.Fatal(err)
	}
	if records := quiet.snapshot(); len(records) != 0 {
		t.Fatalf("cycle after the daily bundle published %d records", len(records))
	}
}

// TestEmitEndpointInventoryGateWithoutDiscoveryReportCannotStampBundle protects
// the correctness of the bundle guarantee: a reload/startup emit carries no
// discovery report and therefore cannot enumerate the discovered MCP / skill /
// plugin collections. If it stamped the clock, the cloud would permanently miss
// those three.
func TestEmitEndpointInventoryGateWithoutDiscoveryReportCannotStampBundle(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()

	reload := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, reload, false, nil, gate,
	); err != nil {
		t.Fatal(err)
	}
	if len(reload.snapshot()) == 0 {
		t.Fatal("reload emit published nothing on a fresh gate")
	}
	if got := managedPublishReadFile(t, gate).FullBundleAt; !got.IsZero() {
		t.Fatalf("report-less cycle stamped the bundle clock: %s", got)
	}

	// The real bundle is therefore still due, and it must carry the three
	// discovery-derived collections.
	report := managedGateReport("scan-1", "alpha")
	bundle := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, bundle, false, &report, gate,
	); err != nil {
		t.Fatal(err)
	}
	sources := map[string]int{}
	for _, record := range bundle.snapshot() {
		body := canonicalBody(t, record)
		source, _ := body[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
		sources[source]++
	}
	if sources["endpoint_skill_inventory"] == 0 || sources["endpoint_discovered_mcp_inventory"] == 0 ||
		sources["endpoint_plugin_inventory"] == 0 {
		t.Fatalf("bundle missed a discovery-derived collection: %v", sources)
	}
	if managedPublishReadFile(t, gate).FullBundleAt.IsZero() {
		t.Fatal("complete bundle did not stamp the clock")
	}
}

// TestEmitEndpointInventoryGateDoesNotRecordFailedOrDegradedPublishes: a stored
// digest is a promise the cloud holds that content, so a failed or
// diagnostic-action publish must leave no digest and must retry.
func TestEmitEndpointInventoryGateDoesNotRecordFailedOrDegradedPublishes(t *testing.T) {
	withManagedEnterprise(t, true)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()

	t.Run("emit failure retries", func(t *testing.T) {
		gate := managedPublishTestState(t)
		failing := &managedGateEmitter{failEventName: "ai_component.observed"}
		report := managedGateReport("scan-1", "alpha")
		if err := emitEndpointInventory(
			t.Context(), cfg, registry, failing, false, &report, gate,
		); err == nil {
			t.Fatal("expected the injected emit failure to surface")
		}
		if got := managedPublishReadFile(t, gate).FullBundleAt; !got.IsZero() {
			t.Fatalf("a failed cycle consumed the daily bundle: %s", got)
		}
		// The next cycle republishes the same content.
		retry := &endpointInventoryCapture{}
		retryReport := managedGateReport("scan-2", "alpha")
		if err := emitEndpointInventory(
			t.Context(), cfg, registry, retry, false, &retryReport, gate,
		); err != nil {
			t.Fatal(err)
		}
		if len(retry.snapshot()) == 0 {
			t.Fatal("a failed publish was not retried")
		}
	})

	t.Run("diagnostic action retries", func(t *testing.T) {
		gate := managedPublishTestState(t)
		// partial=true forces every collection onto the local diagnostic action,
		// which never reaches the managed AI Defense route.
		capture := &endpointInventoryCapture{}
		report := managedGateReport("scan-1", "alpha")
		if err := emitEndpointInventory(
			t.Context(), cfg, registry, capture, true, &report, gate,
		); err != nil {
			t.Fatal(err)
		}
		if len(capture.snapshot()) == 0 {
			t.Fatal("a partial cycle published nothing; the gate must not suppress it")
		}
		if got := managedPublishReadFile(t, gate).FullBundleAt; !got.IsZero() {
			t.Fatalf("a degraded cycle consumed the daily bundle: %s", got)
		}
		// A later clean cycle with the same content still publishes.
		clean := &endpointInventoryCapture{}
		cleanReport := managedGateReport("scan-2", "alpha")
		if err := emitEndpointInventory(
			t.Context(), cfg, registry, clean, false, &cleanReport, gate,
		); err != nil {
			t.Fatal(err)
		}
		if len(clean.snapshot()) == 0 {
			t.Fatal("a diagnostic-action publish poisoned the digest")
		}
	})
}

// TestEmitEndpointInventoryNilGatePublishesEveryCall pins the OSS / ungated path.
func TestEmitEndpointInventoryNilGatePublishesEveryCall(t *testing.T) {
	withManagedEnterprise(t, true)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()
	report := managedGateReport("scan-1", "alpha")

	counts := make([]int, 0, 2)
	for range 2 {
		capture := &endpointInventoryCapture{}
		if err := emitEndpointInventory(
			t.Context(), cfg, registry, capture, false, &report, nil,
		); err != nil {
			t.Fatal(err)
		}
		counts = append(counts, len(capture.snapshot()))
	}
	if counts[0] == 0 || counts[0] != counts[1] {
		t.Fatalf("nil gate changed publish volume across calls: %v", counts)
	}
	// The exported entry point keeps its ungated signature and behavior.
	exported := &endpointInventoryCapture{}
	if err := EmitEndpointInventory(t.Context(), cfg, registry, exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.snapshot()) == 0 {
		t.Fatal("EmitEndpointInventory published nothing")
	}
}

// managedGateFanout reproduces inventory.fanoutReport's publisher order for one
// scan: the per-signal observer first, then the endpoint-inventory hook. The
// order is load-bearing — the signals path establishes the memoized bundle
// decision and the endpoint hook, which alone carries all six collections,
// stamps the daily bundle clock at the end of the cycle.
func managedGateFanout(
	t *testing.T,
	gate *managedInventoryPublishState,
	report inventory.AIDiscoveryReport,
) (map[string]int, map[string]int) {
	t.Helper()
	signalsCapture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: signalsCapture, publishGate: gate}
	if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}
	endpointCapture := &endpointInventoryCapture{}
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	if err := emitEndpointInventory(
		t.Context(), cfg, connector.NewDefaultRegistry(), endpointCapture, false, &report, gate,
	); err != nil {
		t.Fatal(err)
	}
	return managedGateScanCounts(signalsCapture.snapshot()),
		managedGateScanCounts(endpointCapture.snapshot())
}

// TestAIDiscoveryV8SignalsGateManagedSteadyState: the per-signal snapshot is
// suppressed in managed steady state, but the per-scan liveness summary is not.
func TestAIDiscoveryV8SignalsGateManagedSteadyState(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)

	signals, endpoint := managedGateFanout(t, gate, managedGateReport("scan-1", "alpha"))
	if signals["signals_summary"] != 1 || signals["ai_component.observed"] != 1 {
		t.Fatalf("baseline signals counts=%v", signals)
	}
	if len(endpoint) == 0 {
		t.Fatal("baseline endpoint bundle published nothing")
	}

	signals, endpoint = managedGateFanout(t, gate, managedGateReport("scan-2", "alpha"))
	if signals["signals_summary"] != 1 {
		t.Fatalf("liveness summary was suppressed: %v", signals)
	}
	if signals["ai_component.observed"] != 0 {
		t.Fatalf("steady-state per-signal records were published: %v", signals)
	}
	if len(endpoint) != 0 {
		t.Fatalf("steady-state endpoint collections were published: %v", endpoint)
	}

	// A lifecycle change republishes the whole snapshot, `seen` rows included.
	changed := managedGateReport("scan-3", "alpha", "beta")
	changed.Signals[1].State = inventory.AIStateNew
	changed.Summary.NewSignals = 1
	signals, _ = managedGateFanout(t, gate, changed)
	if signals["ai_component.discovered"] != 1 || signals["ai_component.observed"] != 1 {
		t.Fatalf("changed scan did not republish the full snapshot: %v", signals)
	}

	// The cycle after the change settles back into silence: the lifecycle-change
	// publish must also have fingerprinted the scan.
	signals, endpoint = managedGateFanout(t, gate, managedGateReport("scan-4", "alpha", "beta"))
	if signals["ai_component.observed"] != 0 {
		t.Fatalf("cycle after a lifecycle change republished signals: %v", signals)
	}
	if len(endpoint) != 0 {
		t.Fatalf("cycle after a lifecycle change republished collections: %v", endpoint)
	}
}

// TestAIDiscoveryV8SignalsWithoutEndpointHookFailsOpen documents the degraded
// window between the observer being bound and the endpoint-inventory hook being
// bound. Only the endpoint hook can stamp the daily bundle clock, so a
// signals-only sequence keeps publishing the full snapshot. That is today's
// behavior — fail-open, never silent — and it self-corrects on the first cycle
// where both publishers run.
func TestAIDiscoveryV8SignalsWithoutEndpointHookFailsOpen(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	for attempt, scanID := range []string{"scan-1", "scan-2"} {
		capture := &endpointInventoryCapture{}
		adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: gate}
		if err := adapter.EmitReport(t.Context(), managedGateReport(scanID, "alpha"), nil); err != nil {
			t.Fatal(err)
		}
		if counts := managedGateScanCounts(capture.snapshot()); counts["ai_component.observed"] != 1 {
			t.Fatalf("attempt %d: signals-only cycle went silent: %v", attempt, counts)
		}
	}
	// Once a full fanout runs, the bundle is stamped and steady state kicks in.
	managedGateFanout(t, gate, managedGateReport("scan-3", "alpha"))
	signals, endpoint := managedGateFanout(t, gate, managedGateReport("scan-4", "alpha"))
	if signals["ai_component.observed"] != 0 || len(endpoint) != 0 {
		t.Fatalf("full fanout did not settle: signals=%v endpoint=%v", signals, endpoint)
	}
}

// TestAIDiscoveryV8SignalsGateNeverDropsLifecycleDeltas: the counts term must
// keep new / changed / gone records — the exact records non-managed modes emit —
// publishable in every cycle, including one whose digest is unchanged.
func TestAIDiscoveryV8SignalsGateNeverDropsLifecycleDeltas(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)

	baseline := managedGateReport("scan-1", "alpha")
	baselineCapture := &endpointInventoryCapture{}
	baselineAdapter := &aiDiscoveryV8Adapter{runtime: baselineCapture, publishGate: gate}
	if err := baselineAdapter.EmitReport(t.Context(), baseline, nil); err != nil {
		t.Fatal(err)
	}

	// Same evidence set, but the scan reports a removal. `gone` signals are
	// excluded from the digest, so only the lifecycle-count term can save this.
	removal := managedGateReport("scan-2", "alpha")
	removal.Signals = append(removal.Signals, inventory.AISignal{
		SignalID: "ai-skill-beta", SignatureID: "skill", Category: inventory.SignalSkill,
		Vendor: "local", Product: "beta", Confidence: .9, State: inventory.AIStateGone,
		Detector: "skill_dir", EvidenceHash: "evidence-beta",
	})
	removal.Summary.GoneSignals = 1
	removalCapture := &endpointInventoryCapture{}
	removalAdapter := &aiDiscoveryV8Adapter{runtime: removalCapture, publishGate: gate}
	if err := removalAdapter.EmitReport(t.Context(), removal, nil); err != nil {
		t.Fatal(err)
	}
	if counts := managedGateScanCounts(removalCapture.snapshot()); counts["ai_component.removed"] != 1 {
		t.Fatalf("removal record was suppressed: %v", counts)
	}
}

// TestAIDiscoveryV8SignalsNonManagedUnchangedByGate is the OSS parity pin: the
// lifecycle-delta contract must hold across repeated identical reports, with no
// suppression and no state file.
func TestAIDiscoveryV8SignalsNonManagedUnchangedByGate(t *testing.T) {
	withManagedEnterprise(t, false)
	report := managedGateReport("scan-1", "alpha")
	report.Signals[0].State = inventory.AIStateNew
	report.Summary.NewSignals = 1
	report.Signals = append(report.Signals, inventory.AISignal{
		SignalID: "ai-skill-seen", SignatureID: "skill", Category: inventory.SignalSkill,
		Vendor: "local", Product: "seen", Confidence: .9, State: inventory.AIStateSeen,
		Detector: "skill_dir", EvidenceHash: "evidence-seen",
	})

	for attempt := range 2 {
		capture := &endpointInventoryCapture{}
		// Even with a gate bound, non-managed must be untouched.
		adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: managedPublishTestState(t)}
		if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
			t.Fatal(err)
		}
		counts := managedGateScanCounts(capture.snapshot())
		if counts["signals_summary"] != 1 {
			t.Fatalf("attempt %d: summary counts=%v", attempt, counts)
		}
		if counts["ai_component.discovered"] != 1 {
			t.Fatalf("attempt %d: non-managed delta was suppressed: %v", attempt, counts)
		}
		if counts["ai_component.observed"] != 0 {
			t.Fatalf("attempt %d: non-managed emitted a seen record: %v", attempt, counts)
		}
	}
}

// managedGateSourceCounts tallies emitted records by collection source, which is
// how a collection's presence or absence in a cycle is observed.
func managedGateSourceCounts(t *testing.T, records []observability.Record) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, record := range records {
		body := canonicalBody(t, record)
		source, _ := body[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
		counts[source]++
	}
	return counts
}

// TestEmitEndpointInventoryGatePartialReportCannotStampBundle: internal/inventory
// stamps Summary.Result "partial" whenever a scan recorded any error, and a
// detector that errored contributes none of its signals — so the collections
// derived from that report are truncated. Such a cycle must still publish (that
// is today's behavior and it self-corrects), but it must not be allowed to
// satisfy the daily complete-bundle guarantee with a partial copy.
func TestEmitEndpointInventoryGatePartialReportCannotStampBundle(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewDefaultRegistry()

	partial := managedGateReport("scan-partial", "alpha")
	partial.Summary.Result = "partial"
	partial.Summary.Errors = 1
	degraded := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, degraded, false, &partial, gate,
	); err != nil {
		t.Fatal(err)
	}
	if len(degraded.snapshot()) == 0 {
		t.Fatal("partial report published nothing; it must publish, just not anchor the bundle")
	}
	if got := managedPublishReadFile(t, gate).FullBundleAt; !got.IsZero() {
		t.Fatalf("partial report stamped the bundle clock: %s", got)
	}

	// The bundle is therefore still due, and the next complete scan takes it.
	complete := managedGateReport("scan-complete", "alpha")
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, &endpointInventoryCapture{}, false, &complete, gate,
	); err != nil {
		t.Fatal(err)
	}
	if managedPublishReadFile(t, gate).FullBundleAt.IsZero() {
		t.Fatal("complete report after a partial one did not stamp the bundle clock")
	}
}

// TestEmitEndpointInventoryGateEmptyPerConnectorMCPStillPublishes: a zero-count
// snapshot is how a collection reports that its last entry is gone. Skipping the
// per-connector MCP emission when the list is empty would leave the cloud holding
// removed servers forever, because the stored digest would never advance past the
// last non-empty publish.
func TestEmitEndpointInventoryGateEmptyPerConnectorMCPStillPublishes(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	// An empty registry with no active connectors leaves the per-connector MCP
	// fanout nothing to enumerate. Asserted rather than assumed so this test
	// fails loudly if the fixture ever stops being empty.
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("omnigent")}}
	registry := connector.NewRegistry()
	if entries := perConnectorMCPEntries(cfg, registry); len(entries) != 0 {
		t.Fatalf("fixture is not empty: %d per-connector MCP entries", len(entries))
	}

	// Both cycles carry a complete report: only such a cycle stamps the bundle
	// clock, and without that stamp every cycle stays forced and nothing can be
	// suppressed. The report does not feed this collection, which stays empty.
	baseline := managedGateReport("scan-1", "alpha")
	first := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, first, false, &baseline, gate,
	); err != nil {
		t.Fatal(err)
	}
	if counts := managedGateSourceCounts(t, first.snapshot()); counts["endpoint_per_connector_mcp_inventory"] == 0 {
		t.Fatalf("empty per-connector MCP collection was skipped: %v", counts)
	}

	// And the empty digest is stable, so it does not republish every cycle.
	steady := managedGateReport("scan-2", "alpha")
	second := &endpointInventoryCapture{}
	if err := emitEndpointInventory(
		t.Context(), cfg, registry, second, false, &steady, gate,
	); err != nil {
		t.Fatal(err)
	}
	if counts := managedGateSourceCounts(t, second.snapshot()); counts["endpoint_per_connector_mcp_inventory"] != 0 {
		t.Fatalf("empty per-connector MCP collection republished unchanged: %v", counts)
	}
}
