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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const testBundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T7"

type fakeBundleReceiptSink struct {
	receipts   []audit.PolicyBundleReceipt
	bundles    []audit.PolicyBundle
	principals []string
	versions   []uint64
	changes    []audit.ConfigChange
	// offers is every change offered, the refused offers included.
	offers    []audit.ConfigChange
	changeErr error
	// receiptOffers is every receipt offered, the refused offers included.
	receiptOffers []receiptOffer
	receiptErr    error
}

type receiptOffer struct {
	receipt  audit.PolicyBundleReceipt
	delivery *observability.RemoteDelivery
	pins     *audit.ConfigChangePins
}

func (f *fakeBundleReceiptSink) LogConfigChange(
	change audit.ConfigChange, _ *observability.RemoteDelivery, _ *audit.ConfigChangePins,
) error {
	f.offers = append(f.offers, change)
	if f.changeErr != nil {
		return f.changeErr
	}
	f.changes = append(f.changes, change)
	return nil
}

func (f *fakeBundleReceiptSink) LogPolicyBundleReceipt(principal string, b audit.PolicyBundle, r audit.PolicyBundleReceipt,
	delivery *observability.RemoteDelivery, pins *audit.ConfigChangePins,
) error {
	f.receiptOffers = append(f.receiptOffers, receiptOffer{r, delivery, pins})
	if f.receiptErr != nil {
		return f.receiptErr
	}
	f.bundles, f.receipts = append(f.bundles, b), append(f.receipts, r)
	f.principals = append(f.principals, principal)
	return nil
}

func (f *fakeBundleReceiptSink) RecordPolicyBundleVersion(_ context.Context, v uint64) error {
	f.versions = append(f.versions, v)
	return nil
}

func writeTestPublicReceipt(t *testing.T, path string, r enterprisestatus.PublicReceipt) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBundleReceiptReporterReportsEachTerminalReceiptOnce(t *testing.T) {
	dir := t.TempDir()
	path := enterprisestatus.PublicReceiptPath(dir)
	sink := &fakeBundleReceiptSink{}
	newReporter := func() *bundleReceiptReporter {
		r := &bundleReceiptReporter{receiptPath: path, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
			sink: sink, enforcedVersion: func() uint64 { return 4 }}
		r.reported = r.readMarker()
		return r
	}
	reporter := newReporter()
	reporter.poll(context.Background()) // no receipt yet: only the gauge
	writeTestPublicReceipt(t, path, enterprisestatus.PublicReceipt{SchemaVersion: 1, ReceiptID: testBundleID,
		BundleID: testBundleID, Version: 4, Actor: "os:uid:0:root", Principal: "operator:manual-r4", DeliveryID: "agent-7:d.4",
		State: enterprisestatus.BundleConfirmed, FinishedAt: "2026-10-12T10:00:00.000Z",
		CurrentBundleID: testBundleID, CurrentVersion: 4, ChangeSummary: "first", Restart: true, RestartRequired: true})
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	newReporter().poll(context.Background()) // a restarted gateway does not report it again
	if len(sink.receipts) != 1 || sink.receipts[0].State != "confirmed" || sink.bundles[0].ChangeSummary != "first" ||
		sink.receipts[0].Actor != "os:uid:0:root" || sink.principals[0] != "operator:manual-r4" ||
		sink.receipts[0].EnforcingVersion != 4 || !sink.receipts[0].Restart || !sink.receipts[0].RestartRequired ||
		sink.receipts[0].DeliveryID != "agent-7:d.4" {
		t.Fatalf("receipts = %+v", sink.receipts)
	}
	writeTestPublicReceipt(t, path, enterprisestatus.PublicReceipt{SchemaVersion: 1, ReceiptID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8",
		Version: 5, State: enterprisestatus.BundleFailed, ErrorCode: "signature_invalid",
		FinishedAt: "2026-10-12T10:05:00.000Z", CurrentBundleID: testBundleID, CurrentVersion: 4})
	reporter.lastModTime = time.Time{} // same second as the first write
	reporter.poll(context.Background())
	if len(sink.receipts) != 2 || sink.receipts[1].ErrorCode != "signature_invalid" || sink.receipts[1].EnforcingVersion != 4 {
		t.Fatalf("receipts = %+v", sink.receipts)
	}
	if len(sink.versions) != 2 || sink.versions[0] != 4 {
		t.Fatalf("version gauge = %v, want one record per reporter start", sink.versions)
	}
}

func TestBundleReceiptReporterEmitsRefusalWithoutReplacingConfirmation(t *testing.T) {
	dir := t.TempDir()
	path := enterprisestatus.PublicReceiptPath(dir)
	sink := &fakeBundleReceiptSink{}
	r := &bundleReceiptReporter{receiptPath: path, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		refusalMarkerPath: filepath.Join(dir, bundleRefusalMarkerName), sink: sink,
		enforcedVersion: func() uint64 { return 2 }}
	base := enterprisestatus.PublicReceipt{SchemaVersion: 1, ReceiptID: testBundleID,
		BundleID: testBundleID, Version: 2, State: enterprisestatus.BundleConfirmed,
		FinishedAt: "2026-10-13T06:13:33Z", CurrentBundleID: testBundleID, CurrentVersion: 2}
	writeTestPublicReceipt(t, path, base)
	r.poll(context.Background())
	base.LastRefusal = &enterprisestatus.BundleRefusal{ReceiptID: "r-01JAZ3Y8Q2K7V4N6M5P0R9S8T8",
		BundleID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9", Version: 1,
		ErrorCode: "capability_loss", Time: "2026-10-13T06:16:41Z", DeliveryID: "agent-7:d.1",
		WarningCodes: []string{"capability_disabled"}, DisabledByBundle: []string{"sandbox"}}
	writeTestPublicReceipt(t, path, base)
	r.lastModTime = time.Time{}
	r.poll(context.Background())
	r.poll(context.Background())
	if len(sink.receipts) != 2 || sink.receipts[0].State != "confirmed" ||
		sink.receipts[1].State != "failed" || sink.receipts[1].ErrorCode != "capability_loss" ||
		len(sink.receipts[1].WarningCodes) != 1 || sink.receipts[1].WarningCodes[0] != "capability_disabled" ||
		len(sink.receipts[1].DisabledByBundle) != 1 || sink.receipts[1].DisabledByBundle[0] != "sandbox" ||
		sink.receipts[1].EnforcingVersion != 2 || sink.receipts[1].DeliveryID != "agent-7:d.1" {
		t.Fatalf("receipts = %+v", sink.receipts)
	}
}

func TestBundleReceiptReporterDoesNotRepeatInitialRefusal(t *testing.T) {
	dir := t.TempDir()
	path := enterprisestatus.PublicReceiptPath(dir)
	sink := &fakeBundleReceiptSink{}
	r := &bundleReceiptReporter{receiptPath: path, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		refusalMarkerPath: filepath.Join(dir, bundleRefusalMarkerName), sink: sink,
		enforcedVersion: func() uint64 { return 2 }}
	refusal := &enterprisestatus.BundleRefusal{ReceiptID: testBundleID, BundleID: testBundleID,
		Version: 1, ErrorCode: "signature_invalid", Time: "2026-10-13T06:00:00Z"}
	writeTestPublicReceipt(t, path, enterprisestatus.PublicReceipt{SchemaVersion: 1,
		ReceiptID: testBundleID, BundleID: testBundleID, Version: 1, State: "failed",
		ErrorCode: refusal.ErrorCode, FinishedAt: refusal.Time, LastRefusal: refusal})
	r.poll(context.Background())
	writeTestPublicReceipt(t, path, enterprisestatus.PublicReceipt{SchemaVersion: 1,
		ReceiptID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", BundleID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8",
		Version: 2, State: "confirmed", FinishedAt: "2026-10-13T06:05:00Z", LastRefusal: refusal})
	r.lastModTime = time.Time{}
	r.poll(context.Background())
	if len(sink.receipts) != 2 {
		t.Fatalf("receipts = %+v", sink.receipts)
	}
}

func TestBundleReceiptReporterDrainsConsecutiveRefusalsBeforePoll(t *testing.T) {
	dir := t.TempDir()
	store := enterprisebundle.NewStore(filepath.Join(dir, "bundles"), filepath.Join(dir, "lifecycle"))
	var ids []string
	codes := []enterprisebundle.Code{enterprisebundle.CodeSignatureInvalid, enterprisebundle.CodeConfigInvalid}
	for _, code := range codes {
		receipt, err := store.Receive(testBundleID, 9, "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, receipt.ReceiptID)
		if err := store.Fail(receipt, code, "refused"); err != nil {
			t.Fatal(err)
		}
	}
	if ids[0] == ids[1] {
		t.Fatalf("deliveries reused receipt ID %q", ids[0])
	}
	private, err := store.Receipts()
	if err != nil || len(private) != 2 || private[0].State != enterprisebundle.StateFailed ||
		private[1].State != enterprisebundle.StateFailed {
		t.Fatalf("private failed receipts = %+v, %v", private, err)
	}
	if latest, err := enterprisestatus.ReadPublicReceipt(store.PublicReceiptPath()); err != nil ||
		latest.LastRefusal == nil || latest.LastRefusal.ReceiptID != ids[1] {
		t.Fatalf("latest refusal = %+v, %v", latest, err)
	}
	_, logger := newNativeSkillRuntimeTestStore(t)
	capture := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(capture)
	newReporter := func() *bundleReceiptReporter {
		r := &bundleReceiptReporter{receiptPath: store.PublicReceiptPath(),
			markerPath:        filepath.Join(dir, bundleReceiptMarkerName),
			refusalMarkerPath: filepath.Join(dir, bundleRefusalMarkerName), sink: logger,
			enforcedVersion: func() uint64 { return 0 }}
		r.reported, r.reportedRefusal = r.readMarker(), r.readRefusalMarker()
		return r
	}
	reporter := newReporter()
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	newReporter().poll(context.Background())
	records := capture.snapshot()
	if len(records) != 2 {
		t.Fatalf("audit records = %d, want both refusals once", len(records))
	}
	for i, record := range records {
		if record.EventName() != observability.EventName(observability.TelemetryEventConfigBundleReceipt) {
			t.Fatalf("audit event %d = %s", i, record.EventName())
		}
		encoded, err := record.Bytes()
		if err != nil || !strings.Contains(string(encoded), `"defenseclaw.policy.bundle.receipt_id":"`+ids[i]+`"`) ||
			!strings.Contains(string(encoded), `"defenseclaw.policy.bundle.error_code":"`+string(codes[i])+`"`) ||
			!strings.Contains(string(encoded), `"defenseclaw.policy.bundle.version":9`) {
			t.Fatalf("audit record %d = %s, %v", i, encoded, err)
		}
	}
}

func TestBundleReceiptReporterOnlyOnStandaloneEnterprise(t *testing.T) {
	if r := newBundleReceiptReporter(&config.Config{DataDir: t.TempDir()}, filepath.Join(t.TempDir(), "config.yaml"), &audit.Logger{}); r != nil {
		t.Fatal("a per-user gateway started the bundle receipt reporter")
	}
}

func TestPolicyHealthBundleFieldsGolden(t *testing.T) {
	previous := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(previous) })
	liveGeneration.Store(&Generation{Config: &config.Config{}, N: 5, ConfigGen: 9, ConfigGenRecorded: true,
		BundleID: testBundleID, BundleVersion: 4, Digest: "sha256:" + strings.Repeat("b", 64),
		BuiltAt: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)})
	health, ok := CurrentPolicyHealth()
	if !ok {
		t.Fatal("no policy health")
	}
	health.LastReloadError, health.OPAUnavailable, health.PendingRestart = "", "", nil
	raw, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"effective_digest":"sha256:` + strings.Repeat("b", 64) + `","generation":5,"config_generation":9,` +
		`"config_generation_recorded":true,"bundle_id":"` + testBundleID + `","bundle_version":4,` +
		`"built_at":"2026-10-12T00:00:00Z","component_count":0}`
	if string(raw) != want {
		t.Fatalf("/health policy =\n%s\nwant\n%s", raw, want)
	}
}

func TestConfigChangeActivityNamesPolicyBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"generation": 3, "config_sha256": configSHA256ForTest(raw), "actor": "control-plane:acme/alice",
		"reason": "policy bundle " + testBundleID + " version 4: tighten egress", "written_at": "2026-10-12T00:00:00Z",
		"bundle_id": testBundleID, "bundle_version": 4, "signer_key_id": "fleet-2026-10"}
	encoded, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "config.generation.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	in, generation, ok := configChangeActivity(path, nil, raw, []string{"guardrail"}, []string{}, 2, true)
	if !ok || generation != 3 || in.Bundle == nil || in.Bundle.ID != testBundleID || in.Bundle.Version != 4 ||
		in.Bundle.SignerKeyID != "fleet-2026-10" || in.Bundle.ChangeSummary != "tighten egress" || in.After["bundle_id"] != testBundleID {
		t.Fatalf("activity = %+v bundle=%+v", in, in.Bundle)
	}
	state["local_actor"] = "os:uid:0:root"
	encoded, _ = json.Marshal(state)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "config.generation.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, _, ok := configChangeActivity(path, nil, raw, []string{"guardrail"}, []string{}, 2, true); !ok ||
		applied.Actor != "os:uid:0:root" || applied.Principal != "control-plane:acme/alice" {
		t.Fatalf("bundle actor/principal = %+v, ok=%v", applied, ok)
	}
	if in, _, _ := configChangeActivity(path, nil, raw, []string{"guardrail"}, []string{}, 1, true); in.Bundle == nil ||
		in.Actor != "os:uid:0:root" || in.Principal != "control-plane:acme/alice" || len(in.Diff) != 0 || in.After["coalesced"] != true {
		t.Fatalf("coalesced signed bundle lost its final policy identity or attributed the aggregate diff: %+v", in)
	}
}

func configSHA256ForTest(raw []byte) string {
	return configwrite.SHA256Hex(raw)
}

// The reported-marker folder is made durably before a marker goes in it: a
// change's record pin is removed once its marker is on disk, so a folder a
// power loss took back would leave the change with neither, and its next
// offer would build another record under its id. A folder that cannot be
// made that way writes no marker.
func TestBundleReceiptReporterMakesItsMarkerFolderDurably(t *testing.T) {
	r := &bundleReceiptReporter{markerPath: filepath.Join(t.TempDir(), bundleReceiptMarkerName)}
	previous := mkdirMarkers
	t.Cleanup(func() { mkdirMarkers = previous })
	var made []string
	mkdirMarkers = func(folder string) error {
		made = append(made, folder)
		return configwrite.MkdirDurable(folder)
	}
	if !r.markSeen(testBundleID) {
		t.Fatal("the marker was not written")
	}
	if len(made) != 1 || made[0] != r.seenDir() || !r.reportedOnDisk(testBundleID) {
		t.Fatalf("marker folder made by %v, marker on disk %t; want one durable make of %s",
			made, r.reportedOnDisk(testBundleID), r.seenDir())
	}
	const other = "r-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	mkdirMarkers = func(string) error { return os.ErrPermission }
	if r.markSeen(other) || r.reportedOnDisk(other) {
		t.Fatal("a marker was written although its folder could not be made durably")
	}
}

// GAP-0376: a spooled receipt the audit store refused (SQLITE_BUSY) is
// offered again at every poll as the same occurrence: with its record pins
// and one remote delivery state, so the destinations that have it do not
// get it again, and it is marked reported only once the store keeps it.
// Its first offer is a first offer (it entered the spool while the
// reporter ran); none after it is.
func TestBundleReceiptReporterOffersARefusedReceiptAgainAsTheSameOccurrence(t *testing.T) {
	dir := t.TempDir()
	path := enterprisestatus.PublicReceiptPath(dir)
	sink := &fakeBundleReceiptSink{receiptErr: errors.New("database is locked (SQLITE_BUSY)")}
	pins := audit.NewConfigChangePins(filepath.Join(dir, changeRecordPinsDirName))
	r := &bundleReceiptReporter{receiptPath: path, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		sink: sink, enforcedVersion: func() uint64 { return 0 }, pins: pins}
	spool := filepath.Join(filepath.Dir(path), enterprisestatus.PublicReceiptEventsDirName)
	if err := os.MkdirAll(spool, 0o755); err != nil {
		t.Fatal(err)
	}
	r.poll(context.Background()) // the spools are read at start: empty
	writeTestPublicReceipt(t, filepath.Join(spool, testBundleID+".json"), enterprisestatus.PublicReceipt{
		SchemaVersion: 1, ReceiptID: testBundleID, BundleID: testBundleID, Version: 2,
		State: enterprisestatus.BundleConfirmed, FinishedAt: "2026-10-26T20:00:00.123Z", CurrentVersion: 2})
	for poll := 0; poll < 3; poll++ {
		r.poll(context.Background())
	}
	if r.reportedOnDisk(testBundleID) {
		t.Fatal("a receipt the store refused is marked reported")
	}
	sink.receiptErr = nil
	r.poll(context.Background())
	r.poll(context.Background())
	if len(sink.receiptOffers) != 4 || len(sink.receipts) != 1 {
		t.Fatalf("offers = %d, stored = %d, want 3 refused offers and one stored", len(sink.receiptOffers), len(sink.receipts))
	}
	for i, offer := range sink.receiptOffers {
		if offer.delivery == nil || offer.delivery != sink.receiptOffers[0].delivery || offer.pins != pins {
			t.Fatalf("offer %d has another delivery state or no record pins", i)
		}
		if offer.receipt.FirstOffer != (i == 0) || offer.receipt.FinishedAt != "2026-10-26T20:00:00.123Z" {
			t.Fatalf("offer %d = %+v, want a first offer only once and the receipt's time", i, offer.receipt)
		}
	}
	if !r.reportedOnDisk(testBundleID) {
		t.Fatal("the stored receipt is not marked reported")
	}
}
