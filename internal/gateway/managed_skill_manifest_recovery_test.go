// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

type durableManifestStore struct {
	parts  map[int]string
	total  int
	calls  int
	err    error
	scope  string
	before func()
}

func (store *durableManifestStore) ReadManifestReceipt(_ context.Context, hash string, _ int) (managedaid.ManifestReceipt, error) {
	store.calls++
	if store.before != nil {
		store.before()
	}
	if store.err != nil {
		return managedaid.ManifestReceipt{}, store.err
	}
	scope := store.scope
	if scope == "" {
		scope = "sha256:" + strings.Repeat("b", 64)
	}
	receipt := managedaid.ManifestReceipt{Version: 1, Nonce: strings.Repeat("1", 32), Scope: scope, Revision: "sha256:" + strings.Repeat("c", 64), ManifestHash: hash, PartsTotal: store.total, State: "complete", Parts: []managedaid.ManifestPartReceipt{}, MissingParts: []int{}}
	if len(store.parts) == 0 {
		receipt.State = "not_seen"
		receipt.PartsTotal = 0
		return receipt, nil
	}
	for part := 1; part <= store.total; part++ {
		if digest, ok := store.parts[part]; ok {
			receipt.Parts = append(receipt.Parts, managedaid.ManifestPartReceipt{Part: part, SHA256: digest})
		} else {
			receipt.State = "incomplete"
			receipt.MissingParts = append(receipt.MissingParts, part)
		}
	}
	return receipt, nil
}
func manifestTextDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func completedManifestFixture(t *testing.T) (*managedInventoryPublishState, *durableManifestStore, endpointInventoryComponent, []string, *int) {
	t.Helper()
	state := managedPublishTestState(t)
	data := strings.Repeat(strings.Repeat("x", 1023)+"\n", skillManifestPartBytes/1024*5+10)
	parts, ok := splitSkillManifest([]byte(data))
	if !ok || len(parts) != 6 {
		t.Fatalf("fixture parts=%d ok=%t", len(parts), ok)
	}
	hash := manifestTextDigest(data)
	skill := manifestSkill("owned-fixture", hash)
	state.file.SkillManifests = map[string]managedSkillManifest{hash: {Sent: 6, Parts: 6}}
	record := managedManifestReceiptState{Parts: 6, Digests: map[int]string{}, Submitted: map[int]time.Time{}}
	store := &durableManifestStore{parts: map[int]string{}, total: 6}
	for i, text := range parts {
		digest := manifestTextDigest(text)
		record.Digests[i+1] = digest
		record.Submitted[i+1] = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
		store.parts[i+1] = digest
	}
	state.file.ManifestReceipts = map[string]managedManifestReceiptState{hash: record}
	reads := new(int)
	state.SetSkillManifestReader(func(got string) ([]byte, bool) { *reads++; return []byte(data), got == hash })
	state.SetSkillManifestReceiptReader(store)
	return state, store, skill, parts, reads
}

func recoveryTestCycle(t *testing.T, state *managedInventoryPublishState, skill endpointInventoryComponent, at time.Time, submit bool) []endpointInventoryComponent {
	t.Helper()
	cycle := state.beginCycle(fmt.Sprint(at.UnixNano()), at, true)
	rows := cycle.trackSkills([]endpointInventoryComponent{skill}, true)
	cycle.refreshManifestReceipts(t.Context(), nil, rows)
	cycle.attachSkillManifests(rows)
	carried := []endpointInventoryComponent{}
	for _, row := range rows {
		if row.skillManifest != "" {
			carried = append(carried, row)
		}
	}
	if submit {
		cycle.recordPublished(endpointSkillInventorySource, "fixture", len(rows))
		for _, row := range carried {
			r := cloneManifestReceipt(cycle.receipts[row.skillManifestHash])
			r.Submitted[row.skillManifestPart] = at
			r.LastScan = cycle.scanID
			if cycle.manifestProjected == nil {
				cycle.manifestProjected = map[string]managedManifestReceiptState{}
			}
			cycle.manifestProjected[row.skillManifestHash] = r
		}
	}
	cycle.commit()
	return carried
}

func TestManifestRecoveryRepairsOnlyDurablyMissingPart(t *testing.T) {
	state, store, skill, parts, reads := completedManifestFixture(t)
	delete(store.parts, 3)
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
	if got := recoveryTestCycle(t, state, skill, at, false); len(got) != 0 {
		t.Fatal("replayed before in-flight grace")
	}
	if *reads != 0 {
		t.Fatal("receipt-only cycle read a complete local file")
	}
	// Receipt-only progress must survive unchanged collection digests and restart.
	state.file = loadManagedInventoryPublishFile(state.path)
	got := recoveryTestCycle(t, state, skill, at.Add(3*time.Minute), true)
	if len(got) != 1 || got[0].skillManifestPart != 3 || got[0].skillManifest != parts[2] {
		t.Fatalf("repair=%v; want only missing part3", got)
	}
	if progress := state.file.SkillManifests[skill.skillManifestHash]; progress.Sent != 6 || progress.Parts != 6 {
		t.Fatalf("initial cursor reset: %+v", progress)
	}
	// Enqueue/local success does not acknowledge durable storage; it still lacks3.
	if state.file.ManifestReceipts[skill.skillManifestHash].State == "complete" {
		t.Fatal("local publication manufactured durable completion")
	}
	store.parts[3] = manifestTextDigest(got[0].skillManifest)
	*reads = 0
	if got = recoveryTestCycle(t, state, skill, at.Add(6*time.Minute), false); len(got) != 0 {
		t.Fatal("cloud complete replayed body")
	}
	if state.file.ManifestReceipts[skill.skillManifestHash].State != "complete" {
		t.Fatal("durable completion not persisted")
	}
	for day := 1; day <= 3; day++ {
		state.file = loadManagedInventoryPublishFile(state.path)
		if got = recoveryTestCycle(t, state, skill, at.Add(time.Duration(day)*24*time.Hour), true); len(got) != 0 {
			t.Fatal("daily/restart replayed complete body")
		}
	}
	if *reads != 0 {
		t.Fatalf("complete restart/daily path performed %d body reads", *reads)
	}
}

func TestManifestRecoveryPartialScanPreservesCompletedReceipts(t *testing.T) {
	withManagedEnterprise(t, true)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("PATH", t.TempDir())

	state := managedPublishTestState(t)
	now := time.Now().UTC()
	alpha := manifestTextDigest("alpha manifest")
	beta := manifestTextDigest("beta manifest")
	store := &durableManifestStore{parts: map[int]string{1: alpha}, total: 1}
	state.SetSkillManifestReceiptReader(store)
	reads := 0
	state.SetSkillManifestReader(func(string) ([]byte, bool) {
		reads++
		return nil, false
	})
	state.file.SkillManifests = map[string]managedSkillManifest{
		alpha: {Sent: 1, Parts: 1}, beta: {Sent: 1, Parts: 1},
	}
	state.file.ManifestReceipts = map[string]managedManifestReceiptState{
		alpha: {State: "complete", Parts: 1, Digests: map[int]string{1: alpha}},
		beta:  {State: "complete", Parts: 1, Digests: map[int]string{1: beta}, CheckedAt: now},
	}
	seed := state.beginCycle("seed", now, false)
	seed.recordPublished(endpointSkillInventorySource, "fixture", 2)
	seed.commit()

	cfg := &config.Config{
		Claw:        config.ClawConfig{Mode: config.ClawMode("codex")},
		AIDiscovery: config.AIDiscoveryConfig{IncludeSkillManifests: true},
	}
	registry := connector.NewDefaultRegistry()
	emit := func(report inventory.AIDiscoveryReport, manifestHashes ...string) {
		t.Helper()
		for i, hash := range manifestHashes {
			report.Signals[i].Evidence[0].Skill = &inventory.AISkillFacts{ManifestHash: hash}
		}
		if err := emitEndpointInventory(t.Context(), cfg, registry, &endpointInventoryCapture{}, false, &report, state); err != nil {
			t.Fatal(err)
		}
	}
	partial := managedGateReport("partial", "alpha")
	partial.Summary.Result = aiDiscoveryResultPartial
	partial.Summary.DetectorErrors = map[string]string{"skill_dir": "incomplete scan"}
	emit(partial, alpha)
	state.file = loadManagedInventoryPublishFile(state.path)
	if state.file.ManifestReceipts[beta].State != "complete" || state.file.SkillManifests[beta].Sent != 1 {
		t.Fatal("partial scan discarded the omitted manifest's durable progress")
	}
	if store.calls != 0 || reads != 0 {
		t.Fatalf("partial scan made %d receipt requests and %d manifest reads", store.calls, reads)
	}

	emit(managedGateReport("complete", "alpha", "beta"), alpha, beta)
	state.file = loadManagedInventoryPublishFile(state.path)
	if store.calls != 1 || reads != 0 {
		t.Fatalf("complete scan made %d receipt requests and %d manifest reads, want 1 and 0", store.calls, reads)
	}
	if state.file.ManifestReceipts[alpha].State != "complete" || state.file.ManifestReceipts[beta].State != "complete" {
		t.Fatal("complete scan lost a completed receipt")
	}
}

func TestManifestRecoveryErrorsAndRepresentationConflictNeverReplay(t *testing.T) {
	for _, which := range []string{"unsupported", "unavailable", "digest mismatch", "scope mismatch", "stale reader"} {
		t.Run(which, func(t *testing.T) {
			state, store, skill, _, reads := completedManifestFixture(t)
			at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
			switch which {
			case "unsupported":
				store.err = managedaid.ErrReceiptUnsupported
			case "unavailable":
				store.err = managedaid.ErrReceiptUnavailable
			case "digest mismatch":
				store.parts[1] = "sha256:" + strings.Repeat("d", 64)
			case "scope mismatch":
				r := state.file.ManifestReceipts[skill.skillManifestHash]
				r.Scope = "sha256:" + strings.Repeat("e", 64)
				state.file.ManifestReceipts[skill.skillManifestHash] = r
			case "stale reader":
				delete(store.parts, 3)
				store.before = func() { state.SetSkillManifestReceiptReader(nil) }
			}
			for n := 0; n < 2; n++ {
				if got := recoveryTestCycle(t, state, skill, at.Add(time.Duration(n)*time.Hour), true); len(got) != 0 {
					t.Fatalf("%s replayed body", which)
				}
			}
			if *reads != 0 {
				t.Fatalf("%s read body", which)
			}
			if state.file.ManifestReceipts[skill.skillManifestHash].State == "complete" {
				t.Fatal("invalid/unavailable receipt acknowledged completion")
			}
		})
	}
}

func TestManifestRecoveryAuthoritativeLossReplacesCompleteSnapshot(t *testing.T) {
	state, store, skill, _, _ := completedManifestFixture(t)
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
	recoveryTestCycle(t, state, skill, at, false)
	if state.file.ManifestReceipts[skill.skillManifestHash].State != "complete" {
		t.Fatal("fixture not acknowledged")
	}
	delete(store.parts, 4)
	if got := recoveryTestCycle(t, state, skill, at.Add(time.Hour), false); len(got) != 0 {
		t.Fatal("storage invalidation bypassed grace")
	}
	got := recoveryTestCycle(t, state, skill, at.Add(time.Hour+3*time.Minute), true)
	if len(got) != 1 || got[0].skillManifestPart != 4 {
		t.Fatalf("fresh negative snapshot not used: %+v", got)
	}
}

func TestManifestRecoveryFailedRefreshCannotReplayEarlierMissingSnapshot(t *testing.T) {
	state, store, skill, _, reads := completedManifestFixture(t)
	delete(store.parts, 2)
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
	recoveryTestCycle(t, state, skill, at, false)
	store.err = managedaid.ErrReceiptUnavailable
	if got := recoveryTestCycle(t, state, skill, at.Add(3*time.Minute), true); len(got) != 0 || *reads != 0 {
		t.Fatal("failed fresh lookup replayed stale negative receipt")
	}
	record := state.file.ManifestReceipts[skill.skillManifestHash]
	if record.Failures != 1 || !record.NextCheck.After(at.Add(3*time.Minute)) {
		t.Fatal("receipt failure did not persist bounded backoff")
	}
	before := store.calls
	recoveryTestCycle(t, state, skill, at.Add(4*time.Minute), false)
	if store.calls != before {
		t.Fatal("backoff made receipt network call")
	}
}

type countingReceiptReader struct {
	hashes   []string
	deadline time.Duration
	cancel   context.CancelFunc
}

func (r *countingReceiptReader) ReadManifestReceipt(ctx context.Context, hash string, _ int) (managedaid.ManifestReceipt, error) {
	r.hashes = append(r.hashes, hash)
	deadline, ok := ctx.Deadline()
	if ok {
		r.deadline = time.Until(deadline)
	}
	if r.cancel != nil {
		r.cancel()
	}
	return managedaid.ManifestReceipt{}, managedaid.ErrReceiptUnavailable
}

func TestManifestRecoveryReceiptBudgetAndPersistentFairness(t *testing.T) {
	state := managedPublishTestState(t)
	reader := &countingReceiptReader{}
	state.SetSkillManifestReceiptReader(reader)
	var rows []endpointInventoryComponent
	for n := range 40 {
		hash := fmt.Sprintf("sha256:%064x", n+1)
		rows = append(rows, manifestSkill(fmt.Sprint(n), hash))
	}
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
	for n := range 3 {
		cycle := state.beginCycle(fmt.Sprint(n), at.Add(time.Duration(n)*time.Hour), true)
		before := len(reader.hashes)
		cycle.refreshManifestReceipts(t.Context(), nil, rows)
		cycle.commit()
		if len(reader.hashes)-before != skillManifestReceiptOperations {
			t.Fatalf("operations=%d", len(reader.hashes)-before)
		}
		state.file = loadManagedInventoryPublishFile(state.path)
	}
	seen := map[string]bool{}
	for _, hash := range reader.hashes {
		seen[hash] = true
	}
	if len(seen) != len(rows) {
		t.Fatalf("fair rotation checked %d of %d hashes", len(seen), len(rows))
	}
	if reader.deadline <= 0 || reader.deadline > skillManifestReceiptBudget {
		t.Fatalf("receipt context budget=%v", reader.deadline)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader.cancel = cancel
	cycle := state.beginCycle("cancel", at.Add(4*time.Hour), true)
	before := len(reader.hashes)
	cycle.refreshManifestReceipts(ctx, nil, rows)
	if len(reader.hashes)-before != 1 {
		t.Fatal("cancelled budget kept making receipt operations")
	}
}

func TestManifestRecoveryInitialPartsPrecedeRepairAndRespectBodyBudget(t *testing.T) {
	state := managedPublishTestState(t)
	data := []byte(strings.Repeat("x", skillManifestPartBytes))
	state.SetSkillManifestReader(func(string) ([]byte, bool) { return data, true })
	state.file.SkillManifests = map[string]managedSkillManifest{}
	cycle := state.beginCycle("budget", time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC), true)
	cycle.receipts = map[string]managedManifestReceiptState{}
	cycle.receiptFresh = map[string]bool{}
	var rows []endpointInventoryComponent
	for n := range 12 {
		hash := fmt.Sprintf("sha256:%064x", n+1)
		rows = append(rows, manifestSkill(fmt.Sprint(n), hash))
		state.file.SkillManifests[hash] = managedSkillManifest{Sent: 1, Parts: 1}
		cycle.receipts[hash] = managedManifestReceiptState{Parts: 1, Digests: map[int]string{1: manifestTextDigest(string(data))}, State: "not_seen", Missing: []int{1}, CheckedAt: cycle.now, MissingSince: cycle.now.Add(-time.Hour)}
		cycle.receiptFresh[hash] = true
	}
	freshHash := "sha256:" + strings.Repeat("f", 64)
	rows = append(rows, manifestSkill("initial", freshHash))
	cycle.attachSkillManifests(rows)
	bytes, count := 0, 0
	initial := false
	for _, row := range rows {
		bytes += len(row.skillManifest)
		if row.skillManifest != "" {
			count++
			initial = initial || row.id == "initial"
		}
	}
	if bytes > skillManifestCycleBytes || count != 8 || !initial {
		t.Fatalf("bytes=%d count=%d initial=%t", bytes, count, initial)
	}
}

func TestManifestRecoveryDisabledDoesNoReceiptOrStateWork(t *testing.T) {
	state, store, skill, _, reads := completedManifestFixture(t)
	state.SetSkillManifestReceiptReader(nil)
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC)
	if got := recoveryTestCycle(t, state, skill, at, false); len(got) != 0 || store.calls != 0 || *reads != 0 {
		t.Fatal("disabled reader performed receipt/body work")
	}
}

type recordingPreviewEmitter struct {
	*observabilityruntime.Runtime
	previews int
}

func (e *recordingPreviewEmitter) ProjectManagedLogBatch(ctx context.Context, items []observabilityruntime.LogBatchItem) ([]pipeline.LocalLogOutcome, error) {
	e.previews++
	return e.Runtime.ProjectManagedLogBatch(ctx, items)
}

func TestManifestRecoveryLegacyPreviewIsPureAndUsesFinalRedaction(t *testing.T) {
	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	emitter := &recordingPreviewEmitter{Runtime: runtime}
	state := managedPublishTestState(t)
	text := "---\nname: support-runbook\n---\nOwner contact: analyst@example.test\n"
	hash := manifestTextDigest(text)
	row := stateSkill("legacy-runbook", hash)
	row.skillContentStatus = "ok"
	row.skillManifestHash = hash
	row.skillManifestSize = int64(len(text))
	row.signal = "skill"
	state.file.SkillManifests = map[string]managedSkillManifest{hash: {Sent: 1, Parts: 1}}
	state.SetSkillManifestReader(func(got string) ([]byte, bool) { return []byte(text), got == hash })
	cycle := state.beginCycle("legacy-preview", time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC), true)
	digests, ok := cycle.previewManifest(t.Context(), emitter, row, []string{text})
	if !ok || digests[1] == manifestTextDigest(text) {
		t.Fatal("legacy preview failed or hashed unredacted source")
	}
	select {
	case <-adapter.delivered:
		t.Fatal("preview enqueued body")
	default:
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action=?`, string(config.ObservabilityV8ManagedSkillInventoryAction)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("preview persisted records=%d err=%v", count, err)
	}
	store := &durableManifestStore{parts: map[int]string{1: digests[1]}, total: 1}
	state.SetSkillManifestReceiptReader(store)
	cycle.refreshManifestReceipts(t.Context(), emitter, []endpointInventoryComponent{row})
	cycle.commit()
	if emitter.previews != 2 || state.file.ManifestReceipts[hash].State != "complete" {
		t.Fatalf("legacy preview count=%d state=%s", emitter.previews, state.file.ManifestReceipts[hash].State)
	}
	cycle = state.beginCycle("legacy-restart", cycle.now.Add(time.Hour), true)
	cycle.refreshManifestReceipts(t.Context(), emitter, []endpointInventoryComponent{row})
	cycle.commit()
	if emitter.previews != 2 {
		t.Fatal("known projected digests previewed legacy text again")
	}
	// Cloud-ahead/crash rollback: an exact authenticated complete receipt
	// advances local progress without another body read or a collection emit.
	state.file.SkillManifests = map[string]managedSkillManifest{}
	state.file.ManifestReceipts = nil
	cycle = state.beginCycle("cloud-ahead", cycle.now.Add(2*time.Hour), true)
	cycle.refreshManifestReceipts(t.Context(), emitter, []endpointInventoryComponent{row})
	carried := []endpointInventoryComponent{row}
	cycle.attachSkillManifests(carried)
	cycle.commit()
	if carried[0].skillManifest != "" {
		t.Fatal("verified complete cloud-ahead manifest replayed")
	}
	state.file = loadManagedInventoryPublishFile(state.path)
	if state.file.SkillManifests[hash] != (managedSkillManifest{Sent: 1, Parts: 1}) {
		t.Fatal("receipt-only complete progress lost on restart")
	}

	// The guard evaluates the final current-policy projection before dispatcher
	// enqueue: a raw-policy change must not send different bytes for an old part.
	row.skillManifest = text
	row.skillManifestPart = 1
	row.skillManifestParts = 1
	guarded := observabilityruntime.WithManagedManifestDigest(t.Context(), hash, digests[1], 1, 1)
	raw := legacyredaction.WithSinkPolicy(guarded, legacyredaction.SinkPolicyRaw)
	if _, err = emitEndpointInventoryComponent(raw, runtime, endpointSkillInventorySource, "drift", row, observability.SourceSystem, config.ObservabilityV8ManagedSkillInventoryAction, "endpoint_inventory", endpointInventoryDetector); err == nil {
		t.Fatal("changed projection was allowed to enqueue")
	}
	select {
	case <-adapter.delivered:
		t.Fatal("representation conflict uploaded body")
	default:
	}
	// Confirm the same expected representation can flow through the real emitter.
	if _, err = emitEndpointInventoryComponent(guarded, runtime, endpointSkillInventorySource, "matching", row, observability.SourceSystem, config.ObservabilityV8ManagedSkillInventoryAction, "endpoint_inventory", endpointInventoryDetector); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRecoveryDestinationReloadRejectsOldReceiptGeneration(t *testing.T) {
	runtime, path, adapter := newManagedAIDFailOpenRuntime(t)
	text := "---\nname: stable-runbook\n---\nStable recovery instructions.\n"
	hash := manifestTextDigest(text)
	row := stateSkill("stable-runbook", hash)
	row.skillContentStatus = "ok"
	row.skillManifestHash = hash
	row.skillManifestSize = int64(len(text))
	row.signal = "skill"
	cycle := managedPublishTestState(t).beginCycle("generation", time.Now(), true)
	digests, ok := cycle.previewManifest(t.Context(), runtime, row, []string{text})
	if !ok {
		t.Fatal("preview failed")
	}
	oldGeneration := runtime.Active().Generation()
	ctx := observabilityruntime.WithManagedManifestGeneration(t.Context(), oldGeneration)
	ctx = observabilityruntime.WithManagedManifestDigest(ctx, hash, digests[1], 1, 1)
	disabled := false
	retentionDays := 0
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{Path: path, JudgeBodiesPath: filepath.Join(filepath.Dir(path), "judge-bodies.db"), RetentionDays: &retentionDays},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
			observability.BucketPlatformHealth: {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
			observability.BucketDiagnostic:     {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
			observability.BucketAIDiscovery:    {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{DeploymentMode: "managed_enterprise", Endpoint: "https://new-receipt-destination.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false)); reloadErr != nil {
		t.Fatalf("reload code=%s field=%s component=%s", reloadErr.Code(), reloadErr.FieldPath(), reloadErr.ComponentName())
	}
	// Raw text, digest and part identity are unchanged; only destination changed.
	row.skillManifest = text
	row.skillManifestPart = 1
	row.skillManifestParts = 1
	if _, err = emitEndpointInventoryComponent(ctx, runtime, endpointSkillInventorySource, "old-receipt", row, observability.SourceSystem, config.ObservabilityV8ManagedSkillInventoryAction, "endpoint_inventory", endpointInventoryDetector); err == nil {
		t.Fatal("old destination receipt authorized new destination emission")
	}
	select {
	case <-adapter.delivered:
		t.Fatal("old receipt uploaded to new destination")
	default:
	}
}

func TestManifestRecoveryReceiptCommitPreservesInFlightSubmissionSnapshot(t *testing.T) {
	state, _, skill, _, _ := completedManifestFixture(t)
	hash := skill.skillManifestHash
	state.file.SkillManifests[hash] = managedSkillManifest{Sent: 1, Parts: 6}
	// attachSkillManifests retains this map after dropping the publisher lock.
	inFlight := state.file.SkillManifests
	cycle := state.beginCycle("ack-only", time.Date(2026, 11, 19, 1, 0, 0, 0, time.UTC), true)
	cycle.receiptEpoch = state.receiptEpoch
	cycle.receipts = map[string]managedManifestReceiptState{}
	cycle.receiptAcknowledged = map[string]managedSkillManifest{hash: {Sent: 6, Parts: 6}}
	cycle.receiptDirty = true
	cycle.commit()
	if inFlight[hash] != (managedSkillManifest{Sent: 1, Parts: 6}) {
		t.Fatal("receipt-only commit mutated another scan's retained progress snapshot")
	}
	if state.file.SkillManifests[hash] != (managedSkillManifest{Sent: 6, Parts: 6}) {
		t.Fatal("receipt-only acknowledgement did not publish replacement progress")
	}
}

func TestManifestRecoveryStalePublishPreservesNewerAcknowledgement(t *testing.T) {
	state, _, skill, _, _ := completedManifestFixture(t)
	hash := skill.skillManifestHash
	state.file.SkillManifests[hash] = managedSkillManifest{Sent: 1, Parts: 6}
	stale := state.beginCycle("stale-publish", time.Now(), true)
	stale.receiptEpoch = state.receiptEpoch
	stale.skills = map[string]managedSkillState{skill.id: {Name: skill.itemName}}
	stale.manifests = map[string]managedSkillManifest{hash: {Sent: 1, Parts: 6}}
	stale.recordPublished(endpointSkillInventorySource, "current-rows", 1)

	ack := state.beginCycle("ack", time.Now(), false)
	ack.receiptEpoch = state.receiptEpoch
	ack.receipts = map[string]managedManifestReceiptState{}
	ack.receiptAcknowledged = map[string]managedSkillManifest{hash: {Sent: 6, Parts: 6}}
	ack.receiptDirty = true
	ack.commit()
	stale.commit()
	if got := state.file.SkillManifests[hash]; got != (managedSkillManifest{Sent: 6, Parts: 6}) {
		t.Fatalf("stale publish regressed acknowledged progress: %+v", got)
	}
	if got := loadManagedInventoryPublishFile(state.path).SkillManifests[hash]; got != (managedSkillManifest{Sent: 6, Parts: 6}) {
		t.Fatalf("durable progress regressed: %+v", got)
	}
	if stale.manifests[hash].Sent != 1 {
		t.Fatal("commit mutated the stale cycle's retained snapshot")
	}
}
