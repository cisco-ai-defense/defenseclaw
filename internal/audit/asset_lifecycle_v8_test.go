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

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestAssetDiscoveredV8RuntimeOwnsExactlyOneGeneratedOccurrence(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	const path = "/opt/plugins/plugin-example"
	if err := logger.LogAssetDiscoveredCtx(
		context.Background(), path, "type=plugin name=plugin-example",
		AssetLifecycleInput{
			AssetID: "plugin-example", AssetType: "plugin", TargetPath: path,
			Reason: "detected", Initiator: "watcher",
		},
	); err != nil {
		t.Fatalf("LogAssetDiscoveredCtx: %v", err)
	}

	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows=%#v err=%v, want one canonical row", rows, err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 {
		t.Fatalf("runtime metadata=%d records=%d, want 1/1", len(metadata), len(records))
	}
	record := records[0]
	if record.RecordID() != rows[0].ID ||
		record.EventName() != observability.EventName(observability.TelemetryEventAssetDiscovered) ||
		record.Bucket() != observability.BucketAssetLifecycle || record.Outcome() != "" ||
		record.Mandatory() || record.IsFloorOnly() || metadata[0].Identity() != record.Identity() ||
		metadata[0].Source() != observability.SourceWatcher ||
		metadata[0].Action() != observability.ProducerKey(ActionInstallDetected) {
		t.Fatalf("asset discovery contract record=%#v metadata=%#v", record.Identity(), metadata[0].Identity())
	}
	body := assetLifecycleBody(t, record)
	if rows[0].Structured["defenseclaw.asset.target_path"] != path {
		t.Fatalf("canonical SQLite projection lost target path: %#v", rows[0].Structured)
	}
	for key, want := range map[string]any{
		"defenseclaw.asset.id":                   "plugin-example",
		"defenseclaw.asset.type":                 "plugin",
		"defenseclaw.asset.transition":           "discover",
		"defenseclaw.asset.target_path":          path,
		"defenseclaw.asset.transition_reason":    "detected",
		"defenseclaw.asset.transition_initiator": "watcher",
	} {
		if got := body[key]; got != want {
			t.Fatalf("%s=%v, want %v; body=%#v", key, got, want, body)
		}
	}
	for _, fabricated := range []string{
		"defenseclaw.asset.previous_state", "defenseclaw.asset.resulting_state",
		"defenseclaw.asset.transition_code", "defenseclaw.asset.version",
		"defenseclaw.asset.install_action", "defenseclaw.asset.file_action",
		"defenseclaw.asset.runtime_action",
	} {
		if _, present := body[fabricated]; present {
			t.Fatalf("generated asset discovery fabricated %s: %#v", fabricated, body)
		}
	}
}

func TestAssetDiscoveredV8OmitUnknownType(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogAssetDiscoveredCtx(
		context.Background(), "/opt/assets/example", "type unavailable",
		AssetLifecycleInput{AssetID: "asset/example", TargetPath: "/opt/assets/example"},
	); err != nil {
		t.Fatalf("LogAssetDiscoveredCtx: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if _, present := assetLifecycleBody(t, records[0])["defenseclaw.asset.type"]; present {
		t.Fatal("unknown asset type was not omitted")
	}
}

func TestAssetDiscoveredV8CollectionDisabledDropsBeforeBuild(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionDrop)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogAssetDiscoveredCtx(
		context.Background(), "/skills/example", "detected",
		AssetLifecycleInput{AssetID: "skill-example", AssetType: "skill"},
	); err != nil {
		t.Fatalf("LogAssetDiscoveredCtx: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	metadata, records := runtime.snapshot()
	if err != nil || len(rows) != 0 || len(metadata) != 1 || len(records) != 0 {
		t.Fatalf("drop rows=%d metadata=%d records=%d err=%v", len(rows), len(metadata), len(records), err)
	}
}

type countingAssetRuntime struct {
	next  RuntimeV8Emitter
	calls int
}

func (runtime *countingAssetRuntime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	runtime.calls++
	return runtime.next.EmitRuntimeV8(ctx, metadata, builder)
}

func TestAssetDiscoveredV8StoreFailureDoesNotFallBackToLegacyFanout(t *testing.T) {
	logger := newTestLogger(t)
	inner := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	runtime := &countingAssetRuntime{next: inner}
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.store.Close(); err != nil {
		t.Fatal(err)
	}

	err := logger.LogAssetDiscoveredCtx(
		context.Background(), "/plugins/example", "detected",
		AssetLifecycleInput{AssetID: "plugin-example", AssetType: "plugin"},
	)
	if err == nil || !strings.Contains(err.Error(), "emit asset lifecycle") || runtime.calls != 1 {
		t.Fatalf("store failure err=%v runtime calls=%d", err, runtime.calls)
	}
}

func TestAssetDiscoveredV8InvalidSourceIDFailsWithoutFallback(t *testing.T) {
	logger := newTestLogger(t)
	inner := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	runtime := &countingAssetRuntime{next: inner}
	logger.SetRuntimeV8Emitter(runtime)
	emitErr := logger.LogAssetDiscoveredCtx(
		context.Background(), "/plugins/plugin with spaces", "detected",
		AssetLifecycleInput{AssetID: "plugin with spaces", AssetType: "plugin"},
	)
	rows, listErr := logger.store.ListEvents(10)
	if emitErr == nil || !strings.Contains(emitErr.Error(), "stable asset ID") || listErr != nil ||
		len(rows) != 0 || runtime.calls != 0 {
		t.Fatalf("invalid identity rows=%d runtime calls=%d err=%v list=%v",
			len(rows), runtime.calls, emitErr, listErr)
	}
}

func TestAssetDiscoveredUnboundFailsWithoutFanout(t *testing.T) {
	logger := newTestLogger(t)
	err := logger.LogAssetDiscoveredCtx(
		context.Background(), "/plugins/example", "detected",
		AssetLifecycleInput{AssetID: "plugin-example", AssetType: "plugin"},
	)
	rows, listErr := logger.store.ListEvents(10)
	if err == nil || !strings.Contains(err.Error(), "v8 runtime is unavailable") || listErr != nil || len(rows) != 0 {
		t.Fatalf("unbound rows=%d err=%v list=%v", len(rows), err, listErr)
	}
}

func TestCompatibilityLifecycleActionsUseV8WithoutPrimaryAssetRelabeling(t *testing.T) {
	for _, action := range []string{
		string(ActionInstallRejected), string(ActionInstallAllowed), string(ActionInstallAllowedSkipEnforce),
		string(ActionInstallClean), string(ActionInstallWarning), string(ActionInstallScanError),
		string(ActionInstallEnforced),
		string(ActionWatcherBlock), string(ActionQuarantine), string(ActionRestore), string(ActionDeploy),
		string(ActionDisable),
		string(ActionEnable), string(ActionAPISkillDisable), string(ActionAPISkillEnable),
		string(ActionAPIPluginDisable), string(ActionAPIPluginEnable),
	} {
		t.Run(action, func(t *testing.T) {
			logger := newTestLogger(t)
			inner := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			runtime := &countingAssetRuntime{next: inner}
			logger.SetRuntimeV8Emitter(runtime)
			if err := logger.LogActionCtx(context.Background(), action, "asset-example", "source fact"); err != nil {
				t.Fatalf("LogActionCtx: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			_, records := inner.snapshot()
			if err != nil || len(rows) != 1 || runtime.calls != 1 || len(records) != 1 {
				t.Fatalf("rows=%d runtime calls=%d records=%d err=%v", len(rows), runtime.calls, len(records), err)
			}
			if got := string(records[0].EventName()); !strings.HasPrefix(got, "legacy.audit.") ||
				got == observability.TelemetryEventAssetDiscovered ||
				got == observability.TelemetryEventAssetQuarantined {
				t.Fatalf("compatibility action %q was relabeled as %q", action, got)
			}
		})
	}
}

func TestAmbiguousLifecycleActionsFailClosedWithoutTypedContext(t *testing.T) {
	for _, action := range []string{string(ActionBlock), string(ActionAllow), string(ActionStop)} {
		t.Run(action, func(t *testing.T) {
			logger := newTestLogger(t)
			inner := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			runtime := &countingAssetRuntime{next: inner}
			logger.SetRuntimeV8Emitter(runtime)
			if err := logger.LogActionCtx(context.Background(), action, "asset-example", "source fact"); err == nil {
				t.Fatal("ambiguous action without typed classification did not fail closed")
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 0 || runtime.calls != 0 {
				t.Fatalf("rows=%d runtime calls=%d err=%v", len(rows), runtime.calls, err)
			}
		})
	}
}

func TestWatcherBlockEnforcementCallsiteUsesSingleMandatoryV8Occurrence(t *testing.T) {
	logger := newTestLogger(t)
	inner := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	runtime := &countingAssetRuntime{next: inner}
	logger.SetRuntimeV8Emitter(runtime)

	if err := logger.LogActionWithEnforcement(
		string(ActionWatcherBlock), "plugin-example", "type=plugin reason=blocked",
		map[string]string{
			"source_path": "/plugins/example", "install": "block", "file": "quarantine", "runtime": "allow",
		},
	); err != nil {
		t.Fatalf("LogActionWithEnforcement: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	_, records := inner.snapshot()
	if err != nil || len(rows) != 1 || runtime.calls != 1 || len(records) != 1 {
		t.Fatalf("rows=%d runtime calls=%d records=%d err=%v", len(rows), runtime.calls, len(records), err)
	}
	if records[0].EventName() != "legacy.audit.watcher.block" || !records[0].Mandatory() ||
		records[0].Outcome() != observability.OutcomeBlocked {
		t.Fatalf("watcher block record identity=%#v mandatory=%t outcome=%q",
			records[0].Identity(), records[0].Mandatory(), records[0].Outcome())
	}
}

func assetLifecycleBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("asset lifecycle record body is absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatalf("asset lifecycle body: %v", err)
	}
	return object
}
