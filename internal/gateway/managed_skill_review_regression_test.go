// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

type removalBatchCapture struct {
	endpointInventoryCapture
	calls     int
	failFirst bool
}

func (capture *removalBatchCapture) Emit(ctx context.Context, metadata router.Metadata, build observabilityruntime.EmitBuilder) (pipeline.LocalLogOutcome, error) {
	capture.calls++
	if capture.failFirst && capture.calls == 1 {
		return pipeline.LocalLogOutcome{}, errors.New("fixture publication refused")
	}
	return capture.endpointInventoryCapture.Emit(ctx, metadata, build)
}

func TestSkillTurnoverFitsTheManagedLimitAndRetriesOnlyPendingRemovals(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("first-batch-fails=", fail), func(t *testing.T) {
			state := managedPublishTestState(t)
			at := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
			oldRows := make([]endpointInventoryComponent, 300)
			nextRows := make([]endpointInventoryComponent, 300)
			for i := range oldRows {
				oldRows[i] = stateSkill(fmt.Sprintf("old-%03d", i), manifestTextDigest("old"))
				nextRows[i] = stateSkill(fmt.Sprintf("new-%03d", i), manifestTextDigest("new"))
			}
			skillCycle(t, state, at, true, true, oldRows...)
			cycle := state.beginCycle("turnover", at.Add(time.Hour), true)
			rows := cycle.trackSkills(nextRows, true)
			if len(rows) != 600 {
				t.Fatalf("fixture rows=%d", len(rows))
			}
			capture := &removalBatchCapture{failFirst: fail}
			publish := endpointInventoryCycle{scanID: "turnover", cycle: cycle}
			rows, err := prepareManagedSkillSnapshot(t.Context(), capture, rows, true, publish)
			if (err != nil) != fail {
				t.Fatalf("batch failure=%v", err)
			}
			if !fail {
				if len(rows) != 300 || !managedInventorySnapshotEligible(endpointSkillInventorySource, config.ObservabilityV8ManagedSkillInventoryAction, rows) {
					t.Fatal("supported current collection did not recover after removals")
				}
				if err := emitEndpointInventorySnapshot(t.Context(), capture, endpointSkillInventorySource, rows, false, config.ObservabilityV8ManagedSkillInventoryAction, publish); err != nil {
					t.Fatal(err)
				}
			}
			cycle.commit()
			state.file = loadManagedInventoryPublishFile(state.path)
			if !fail {
				if len(state.file.Skills) != 300 {
					t.Fatalf("current accepted skills=%d", len(state.file.Skills))
				}
				for _, row := range nextRows {
					if _, ok := state.file.Skills[row.id]; !ok {
						t.Fatal("new skill lost")
					}
				}
				return
			}
			// One refused removal remains; none of the new rows was published or
			// prematurely marked unchanged. Accepted removal progress survives restart.
			if len(state.file.Skills) != 1 || state.file.Skills["old-000"].Name != "old-000" {
				t.Fatalf("pending removal count=%d, first present=%t", len(state.file.Skills), state.file.Skills["old-000"].Name == "old-000")
			}
			retry := state.beginCycle("retry", at.Add(2*time.Hour), true)
			rows = retry.trackSkills(nextRows, true)
			for _, row := range rows {
				if row.skillState != skillStateRemoved && row.skillState != skillStateNew {
					t.Fatal("unpublished current row lost its new state")
				}
			}
			if len(rows) != 301 {
				t.Fatalf("retry rows=%d", len(rows))
			}
			if err := emitEndpointInventorySnapshot(t.Context(), &endpointInventoryCapture{}, endpointSkillInventorySource, rows, false, config.ObservabilityV8ManagedSkillInventoryAction, endpointInventoryCycle{scanID: "retry", cycle: retry}); err != nil {
				t.Fatal(err)
			}
			retry.commit()
			if len(state.file.Skills) != 300 {
				t.Fatalf("retry did not settle: %d", len(state.file.Skills))
			}
		})
	}
}

func TestManifestRecoveryOversizedRowsPreserveReceiptHistory(t *testing.T) {
	state, store, skill, _, _ := completedManifestFixture(t)
	hash := skill.skillManifestHash
	record := state.file.ManifestReceipts[hash]
	record.Scope = "sha256:" + strings.Repeat("a", 64)
	state.file.ManifestReceipts[hash] = record
	cycle := state.beginCycle("oversized", time.Now(), false)
	rows := make([]endpointInventoryComponent, 513)
	for i := range rows {
		rows[i] = skill
		rows[i].id = fmt.Sprint(i)
	}
	rows[len(rows)-1].skillState = skillStateRemoved
	rows, err := prepareManagedSkillSnapshot(t.Context(), &removalBatchCapture{failFirst: true}, rows, true, endpointInventoryCycle{scanID: "oversized", cycle: cycle})
	if err == nil || len(rows) != 513 {
		t.Fatal("refused removal did not retain the ineligible collection")
	}
	cycle.refreshManifestReceipts(t.Context(), nil, rows)
	cycle.recordPublished("unrelated", "digest", 1)
	cycle.commit()
	if store.calls != 0 {
		t.Fatal("diagnostic-only collection queried receipts")
	}
	restored := loadManagedInventoryPublishFile(state.path).ManifestReceipts[hash]
	if restored.Scope != record.Scope || len(restored.Digests) != len(record.Digests) {
		t.Fatal("oversized collection pruned receipt history")
	}
}

func TestManifestRecoveryDestinationChangeRebaselinesAndRejectsOldCycles(t *testing.T) {
	state, _, skill, parts, _ := completedManifestFixture(t)
	hash := skill.skillManifestHash
	first := "sha256:" + strings.Repeat("d", 64)
	second := "sha256:" + strings.Repeat("e", 64)
	state.file.ManifestDestination = first
	prior := state.file.ManifestReceipts[hash]
	prior.Scope = "sha256:" + strings.Repeat("b", 64)
	prior.State = "conflict"
	state.file.ManifestReceipts[hash] = prior
	stale := state.beginCycle("old-destination", time.Now(), true)
	stale.recordPublished(endpointSkillInventorySource, "old-digest", 1)
	newStore := &durableManifestStore{parts: map[int]string{}, total: 6, scope: "sha256:" + strings.Repeat("f", 64)}
	binding := manifestReceiptRuntimeBinding{destination: second}
	state.SetSkillManifestReceiptReader(newStore, binding)
	oldRow := skill
	oldRow.skillManifest, oldRow.skillManifestPart, oldRow.skillManifestParts = parts[0], 1, len(parts)
	if _, current := stale.manifestEmissionContext(t.Context(), oldRow); current {
		t.Fatal("old receiver cycle retained body emission permission")
	}
	stale.commit()
	if len(state.file.SkillManifests) != 0 || len(state.file.ManifestReceipts) != 0 || len(state.file.Collections) != 0 {
		t.Fatal("old destination progress survived rebind or stale commit")
	}
	cycle := state.beginCycle("new-destination", time.Now(), true)
	rows := cycle.trackSkills([]endpointInventoryComponent{skill}, true)
	cycle.refreshManifestReceipts(t.Context(), nil, rows)
	cycle.attachSkillManifests(rows)
	if rows[0].skillManifestPart != 1 || rows[0].skillManifest != parts[0] {
		t.Fatal("new destination did not receive the unchanged manifest")
	}
	cycle.recordPublished(endpointSkillInventorySource, "new-digest", 1)
	cycle.commit()
	state.file = loadManagedInventoryPublishFile(state.path)
	if state.file.ManifestDestination != second || state.file.SkillManifests[hash].Sent != 1 || state.file.ManifestReceipts[hash].Scope != newStore.scope {
		t.Fatal("new destination baseline did not persist")
	}
	// A normal rebind of this receiver preserves progress and keeps the scope
	// mismatch protection; a changed scope alone cannot authorize a reset.
	newStore.scope = "sha256:" + strings.Repeat("a", 64)
	state.SetSkillManifestReceiptReader(newStore, binding)
	if state.file.SkillManifests[hash].Sent != 1 {
		t.Fatal("ordinary reload reset progress")
	}
	check := state.beginCycle("same-destination", time.Now().Add(time.Hour), true)
	freshRows := []endpointInventoryComponent{skill}
	check.refreshManifestReceipts(t.Context(), nil, freshRows)
	check.attachSkillManifests(freshRows)
	if freshRows[0].skillManifest != "" {
		t.Fatal("same-binding scope mismatch replayed a body")
	}
	if check.receipts[hash].State != "conflict" {
		t.Fatal("same-binding scope mismatch was accepted")
	}
}

func TestManifestDestinationIdentityPersistsWithoutReplayingProgress(t *testing.T) {
	state, store, skill, _, reads := completedManifestFixture(t)
	identity := manifestTextDigest("managed receiver")
	state.SetSkillManifestReceiptReader(store, manifestReceiptRuntimeBinding{destination: identity})
	state.beginCycle("adopt-receiver", time.Now(), false).commit()
	state.file = loadManagedInventoryPublishFile(state.path)
	stamp := state.file.UpdatedAt
	if state.file.ManifestDestination != identity || state.file.SkillManifests[skill.skillManifestHash].Sent != 6 {
		t.Fatal("receiver adoption lost legacy progress or its durable identity")
	}
	state.SetSkillManifestReceiptReader(store, manifestReceiptRuntimeBinding{destination: identity})
	state.beginCycle("quiet-rebind", stamp.Add(time.Hour), false).commit()
	if !state.file.UpdatedAt.Equal(stamp) || store.calls != 0 || *reads != 0 {
		t.Fatal("unchanged receiver rebind performed publication, receipt or body work")
	}
}
