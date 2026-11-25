// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const (
	skillManifestReceiptGrace      = 2 * time.Minute
	skillManifestReceiptInterval   = 30 * time.Minute
	skillManifestReceiptOperations = 16
	skillManifestReceiptBudget     = 10 * time.Second
	maxManifestReceiptHashes       = 512 // managed skill collection ceiling; digest metadata only
)

// Local submission history remains separate from durable storage snapshots.
// Only bounded digests/timestamps are retained, never source or redacted text.
type managedManifestReceiptState struct {
	Parts        int               `json:"parts"`
	Digests      map[int]string    `json:"digests,omitempty"`
	Submitted    map[int]time.Time `json:"submitted,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	Revision     string            `json:"revision,omitempty"`
	State        string            `json:"state,omitempty"`
	Missing      []int             `json:"missing,omitempty"`
	CheckedAt    time.Time         `json:"checked_at,omitempty"`
	LastScan     string            `json:"last_scan,omitempty"`
	RetryCursor  int               `json:"retry_cursor,omitempty"`
	MissingSince time.Time         `json:"missing_since,omitempty"`
	Failures     int               `json:"failures,omitempty"`
	NextCheck    time.Time         `json:"next_check,omitempty"`
}

type manifestReceiptRuntimeBinding struct {
	generation  uint64
	current     func() uint64
	destination string
}

func (state *managedInventoryPublishState) SetSkillManifestReceiptReader(reader managedaid.ManifestReceiptReader, bindings ...manifestReceiptRuntimeBinding) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.receiptReader = reader
	state.receiptBinding = manifestReceiptRuntimeBinding{}
	if len(bindings) == 1 {
		state.receiptBinding = bindings[0]
		if destination := bindings[0].destination; managedaid.ValidManifestSHA256(destination) {
			if state.file.ManifestDestination != destination {
				state.destinationDirty = true
			}
			if prior := state.file.ManifestDestination; prior != "" && prior != destination {
				// A different managed receiver needs its own baseline. Preserve
				// the scope-mismatch guard for ordinary reloads of this receiver.
				state.file.Collections = map[string]managedInventoryPublishRecord{}
				state.file.Skills = nil
				state.file.SkillManifests = nil
				state.file.ManifestReceipts = nil
				state.file.ManifestReceiptCursor = ""
				state.file.ManifestBodyCursor = ""
				state.file.FullBundleAt = time.Time{}
				state.cycleKnown = false
				state.destinationEpoch++
			}
			// Older state has no receiver identity. Adopt the current one
			// without discarding supported legacy submission progress.
			state.file.ManifestDestination = destination
		}
	}
	state.receiptEpoch++
}

func (state *managedInventoryPublishState) manifestDestinationEpoch() uint64 {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.destinationEpoch
}

type skillManifestProjectionPreview interface {
	ProjectManagedLogBatch(context.Context, []observabilityruntime.LogBatchItem) ([]pipeline.LocalLogOutcome, error)
}

type manifestBuilderCollector struct {
	items []observabilityruntime.LogBatchItem
}

func (c *manifestBuilderCollector) Emit(ctx context.Context, metadata router.Metadata, builder observabilityruntime.EmitBuilder) (pipeline.LocalLogOutcome, error) {
	c.items = append(c.items, observabilityruntime.LogBatchItem{Context: ctx, Metadata: metadata, Builder: builder})
	return pipeline.LocalLogOutcome{}, nil
}

func cloneManifestReceipt(in managedManifestReceiptState) managedManifestReceiptState {
	out := in
	out.Digests = make(map[int]string, len(in.Digests))
	out.Submitted = make(map[int]time.Time, len(in.Submitted))
	out.Missing = append([]int(nil), in.Missing...)
	for k, v := range in.Digests {
		out.Digests[k] = v
	}
	for k, v := range in.Submitted {
		out.Submitted[k] = v
	}
	return out
}

func projectedManifestDigest(outcome pipeline.LocalLogOutcome, hash string, part, total int) (string, bool) {
	for _, work := range outcome.OptionalWork() {
		if work.Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
			continue
		}
		raw, err := work.Projection().Bytes()
		if err != nil {
			return "", false
		}
		var wire struct {
			Body map[string]json.RawMessage `json:"body"`
		}
		if json.Unmarshal(raw, &wire) != nil {
			return "", false
		}
		var gotHash, text string
		var gotPart, gotTotal int
		if json.Unmarshal(wire.Body["defenseclaw.inventory.skill.manifest_hash"], &gotHash) != nil || json.Unmarshal(wire.Body["defenseclaw.inventory.skill.manifest"], &text) != nil || json.Unmarshal(wire.Body["defenseclaw.inventory.skill.manifest_part"], &gotPart) != nil || json.Unmarshal(wire.Body["defenseclaw.inventory.skill.manifest_parts"], &gotTotal) != nil || gotHash != hash || gotPart != part || gotTotal != total || text == "" {
			return "", false
		}
		sum := sha256.Sum256([]byte(text))
		return "sha256:" + hex.EncodeToString(sum[:]), true
	}
	return "", false
}

func (cycle *managedInventoryPublishCycle) previewManifest(ctx context.Context, emitter sidecarRuntimeEmitter, component endpointInventoryComponent, parts []string) (map[int]string, bool) {
	preview, ok := emitter.(skillManifestProjectionPreview)
	if !ok || len(parts) == 0 || len(parts) > maxSkillManifestParts {
		return nil, false
	}
	collector := &manifestBuilderCollector{}
	for i, text := range parts {
		row := component
		if cycle.receiptGeneration != 0 {
			ctx = observabilityruntime.WithManagedManifestGeneration(ctx, cycle.receiptGeneration)
		}
		row.skillManifest = text
		row.skillManifestPart = i + 1
		row.skillManifestParts = len(parts)
		if _, err := emitEndpointInventoryComponent(ctx, collector, endpointSkillInventorySource, endpointInventoryCycleScanID(cycle.scanID), row, observability.SourceSystem, config.ObservabilityV8ManagedSkillInventoryAction, "endpoint_inventory", endpointInventoryDetector); err != nil {
			return nil, false
		}
	}
	outcomes, err := preview.ProjectManagedLogBatch(ctx, collector.items)
	if err != nil || len(outcomes) != len(parts) {
		return nil, false
	}
	digests := make(map[int]string, len(parts))
	for i, outcome := range outcomes {
		digest, ok := projectedManifestDigest(outcome, component.skillManifestHash, i+1, len(parts))
		if !ok {
			return nil, false
		}
		digests[i+1] = digest
	}
	return digests, true
}

func (cycle *managedInventoryPublishCycle) observeManifestProjection(component endpointInventoryComponent, outcome pipeline.LocalLogOutcome) {
	if cycle == nil || component.skillManifest == "" {
		return
	}
	hash := component.skillManifestHash
	record := cloneManifestReceipt(cycle.receipts[hash])
	digest, ok := projectedManifestDigest(outcome, hash, component.skillManifestPart, component.skillManifestParts)
	if !ok {
		record.State = "conflict"
	} else if prior := record.Digests[component.skillManifestPart]; prior != "" && prior != digest {
		record.State = "conflict"
	} else {
		record.Parts = component.skillManifestParts
		record.Digests[component.skillManifestPart] = digest
		record.Submitted[component.skillManifestPart] = cycle.now
		record.LastScan = cycle.scanID
	}
	if cycle.manifestProjected == nil {
		cycle.manifestProjected = map[string]managedManifestReceiptState{}
	}
	cycle.manifestProjected[hash] = record
}

func receiptSnapshotMatches(record managedManifestReceiptState, receipt managedaid.ManifestReceipt) bool {
	if receipt.State == "conflict" || record.Parts > 0 && record.Parts != receipt.PartsTotal && receipt.State != "not_seen" {
		return false
	}
	for _, part := range receipt.Parts {
		if record.Digests[part.Part] == "" || record.Digests[part.Part] != part.SHA256 {
			return false
		}
	}
	return true
}

// refreshManifestReceipts checks at most sixteen fairly rotated active hashes.
// Network work and legacy preview run without holding the publisher mutex.
func (cycle *managedInventoryPublishCycle) refreshManifestReceipts(ctx context.Context, emitter sidecarRuntimeEmitter, components []endpointInventoryComponent) {
	if cycle == nil || cycle.state == nil || ctx == nil {
		return
	}
	if !managedInventorySnapshotEligible(endpointSkillInventorySource, config.ObservabilityV8ManagedSkillInventoryAction, components) {
		return
	}
	state := cycle.state
	state.mu.Lock()
	reader, epoch, cursor := state.receiptReader, state.receiptEpoch, state.file.ManifestReceiptCursor
	cycle.receiptGeneration = state.receiptBinding.generation
	prior := make(map[string]managedManifestReceiptState, len(state.file.ManifestReceipts))
	for h, r := range state.file.ManifestReceipts {
		prior[h] = cloneManifestReceipt(r)
	}
	read := state.readSkillManifest
	state.mu.Unlock()
	if reader == nil {
		return
	}
	cycle.receiptEpoch = epoch
	cycle.receipts = make(map[string]managedManifestReceiptState)
	cycle.receiptFresh = make(map[string]bool)
	byHash := map[string]endpointInventoryComponent{}
	for _, row := range components {
		if managedaid.ValidManifestSHA256(row.skillManifestHash) && row.skillState != skillStateRemoved {
			if _, ok := byHash[row.skillManifestHash]; !ok {
				byHash[row.skillManifestHash] = row
			}
		}
	}
	if len(byHash) > maxManifestReceiptHashes {
		cycle.receipts = nil
		return
	}
	hashes := make([]string, 0, len(byHash))
	for hash := range byHash {
		hashes = append(hashes, hash)
		if record, ok := prior[hash]; ok {
			cycle.receipts[hash] = record
		}
	}
	sort.Strings(hashes)
	start := sort.SearchStrings(hashes, cursor)
	if start < len(hashes) && hashes[start] == cursor {
		start++
	}
	if start >= len(hashes) {
		start = 0
	}
	deadline, cancel := context.WithTimeout(ctx, skillManifestReceiptBudget)
	defer cancel()
	operations := 0
	for step := 0; step < len(hashes) && operations < skillManifestReceiptOperations; step++ {
		hash := hashes[(start+step)%len(hashes)]
		record := cloneManifestReceipt(cycle.receipts[hash])
		interval := skillManifestReceiptInterval
		if record.State == "incomplete" || record.State == "not_seen" {
			interval = skillManifestReceiptGrace
		}
		if cycle.now.Before(record.NextCheck) || !record.CheckedAt.IsZero() && cycle.now.Before(record.CheckedAt.Add(interval)) {
			continue
		}
		if deadline.Err() != nil {
			break
		}
		operations++
		cycle.receiptCursor = hash
		cycle.receiptDirty = true
		progress := stateManifestProgress(cycle, hash)
		receipt, err := reader.ReadManifestReceipt(deadline, hash, progress.Parts)
		state.mu.Lock()
		current := state.receiptEpoch == epoch && (state.receiptBinding.current == nil || state.receiptBinding.current() == cycle.receiptGeneration)
		state.mu.Unlock()
		if !current {
			cycle.receipts = nil
			cycle.receiptDirty = false
			return
		}
		if err != nil {
			deferManifestReceipt(&record, cycle.now)
			cycle.receipts[hash] = record
			continue
		}
		// The production reader verifies nonce and strict wire structure. Repeat
		// scope/shape validation here so an injected provider cannot assert ACKs.
		if managedaid.ValidateManifestReceipt(receipt, hash, receipt.Nonce) != nil {
			deferManifestReceipt(&record, cycle.now)
			cycle.receipts[hash] = record
			continue
		}
		if record.Scope != "" && record.Scope != receipt.Scope {
			record.State = "conflict"
			record.CheckedAt = cycle.now
			cycle.receipts[hash] = record
			continue
		}
		needsPreview := len(record.Digests) < progress.Sent || record.Parts != progress.Parts && progress.Sent > 0 || receipt.State != "not_seen" && record.Parts == 0
		for _, part := range receipt.Parts {
			needsPreview = needsPreview || record.Digests[part.Part] == ""
		}
		if needsPreview {
			if read == nil {
				continue
			}
			data, ok := read(hash)
			if !ok {
				continue
			}
			parts, ok := splitSkillManifest(data)
			if !ok || len(parts) == 0 || len(parts) > maxSkillManifestParts {
				continue
			}
			digests, ok := cycle.previewManifest(deadline, emitter, byHash[hash], parts)
			if !ok {
				continue
			}
			compatible := true
			for part, digest := range record.Digests {
				if digests[part] != digest {
					compatible = false
					break
				}
			}
			if !compatible {
				record.State = "conflict"
				record.CheckedAt = cycle.now
				cycle.receipts[hash] = record
				continue
			}
			record.Parts = len(parts)
			record.Digests = digests
		}
		if !cycle.receiptContextCurrent() {
			cycle.receipts = nil
			cycle.receiptDirty = false
			return
		}
		record.Failures = 0
		record.NextCheck = time.Time{}
		cycle.receiptFresh[hash] = true
		record.CheckedAt = cycle.now
		record.Scope = receipt.Scope
		record.Revision = receipt.Revision
		if receipt.State != "complete" && record.MissingSince.IsZero() {
			record.MissingSince = cycle.now
		}
		if receipt.State == "complete" {
			record.MissingSince = time.Time{}
		}
		if !receiptSnapshotMatches(record, receipt) {
			record.State = "conflict"
			record.Missing = nil
		} else {
			record.State = receipt.State
			if receipt.State == "complete" {
				if cycle.receiptAcknowledged == nil {
					cycle.receiptAcknowledged = map[string]managedSkillManifest{}
				}
				cycle.receiptAcknowledged[hash] = managedSkillManifest{Sent: record.Parts, Parts: record.Parts}
			}
			record.Missing = append([]int(nil), receipt.MissingParts...)
			if receipt.State == "not_seen" {
				record.Missing = make([]int, record.Parts)
				for i := range record.Missing {
					record.Missing[i] = i + 1
				}
			}
		}
		cycle.receipts[hash] = record
	}
}

func stateManifestProgress(cycle *managedInventoryPublishCycle, hash string) managedSkillManifest {
	cycle.state.mu.Lock()
	defer cycle.state.mu.Unlock()
	return cycle.state.file.SkillManifests[hash]
}

func (cycle *managedInventoryPublishCycle) missingManifestPart(hash string, progress managedSkillManifest, record managedManifestReceiptState) int {
	if cycle.receipts == nil || !cycle.receiptFresh[hash] || record.State != "incomplete" && record.State != "not_seen" || record.CheckedAt.IsZero() || record.Parts != progress.Parts || progress.Parts == 0 || cycle.now.Before(record.MissingSince.Add(skillManifestReceiptGrace)) {
		return 0
	}
	for offset := 0; offset < len(record.Missing); offset++ {
		i := (record.RetryCursor + offset) % len(record.Missing)
		part := record.Missing[i]
		if part < 1 || part > progress.Sent || record.Digests[part] == "" || cycle.now.Before(record.Submitted[part].Add(skillManifestReceiptGrace)) {
			continue
		}
		record.RetryCursor = (i + 1) % len(record.Missing)
		cycle.receipts[hash] = record
		return part
	}
	return 0
}

// Failed lookups back off without turning errors into missing-part evidence.
func deferManifestReceipt(record *managedManifestReceiptState, now time.Time) {
	record.Failures = min(record.Failures+1, 6)
	record.NextCheck = now.Add(skillManifestReceiptGrace * time.Duration(1<<(record.Failures-1)))
}

func (cycle *managedInventoryPublishCycle) receiptContextCurrent() bool {
	cycle.state.mu.Lock()
	defer cycle.state.mu.Unlock()
	return cycle.receiptEpoch == cycle.state.receiptEpoch && (cycle.state.receiptBinding.current == nil || cycle.state.receiptBinding.current() == cycle.receiptGeneration)
}

func (cycle *managedInventoryPublishCycle) manifestEmissionContext(ctx context.Context, component endpointInventoryComponent) (context.Context, bool) {
	if cycle == nil || component.skillManifest == "" {
		return ctx, true
	}
	if cycle.state != nil && cycle.destinationEpoch != cycle.state.manifestDestinationEpoch() {
		return ctx, false
	}
	if cycle.receiptEpoch != 0 && !cycle.receiptContextCurrent() {
		return ctx, false
	}
	if cycle.receiptGeneration != 0 {
		ctx = observabilityruntime.WithManagedManifestGeneration(ctx, cycle.receiptGeneration)
	}
	digest := cycle.receipts[component.skillManifestHash].Digests[component.skillManifestPart]
	if digest == "" {
		return ctx, true
	}
	return observabilityruntime.WithManagedManifestDigest(ctx, component.skillManifestHash, digest, component.skillManifestPart, component.skillManifestParts), true
}

// Receipt metadata is optional in the current publish-state schema.
// Reject impossible/unbounded recovery metadata without discarding Sent/Parts.
func sanitizeManifestReceipts(file *managedInventoryPublishFile) {
	if len(file.ManifestReceipts) > maxManifestReceiptHashes {
		file.ManifestReceipts = nil
		return
	}
	for hash, record := range file.ManifestReceipts {
		valid := managedaid.ValidManifestSHA256(hash) && record.Parts >= 0 && record.Parts <= maxSkillManifestParts && len(record.Digests) <= maxSkillManifestParts && len(record.Submitted) <= maxSkillManifestParts && len(record.Missing) <= maxSkillManifestParts && record.Failures >= 0 && record.Failures <= 6 && record.RetryCursor >= 0 && record.RetryCursor <= maxSkillManifestParts
		for part, digest := range record.Digests {
			valid = valid && part >= 1 && part <= record.Parts && managedaid.ValidManifestSHA256(digest)
		}
		for part := range record.Submitted {
			valid = valid && part >= 1 && part <= record.Parts
		}
		last := 0
		for _, part := range record.Missing {
			valid = valid && part > last && part <= record.Parts
			last = part
		}
		valid = valid && (record.Scope == "" || managedaid.ValidManifestSHA256(record.Scope)) && (record.Revision == "" || managedaid.ValidManifestSHA256(record.Revision))
		switch record.State {
		case "", "not_seen", "incomplete", "complete", "conflict":
		default:
			valid = false
		}
		if !valid {
			delete(file.ManifestReceipts, hash)
		}
	}
}
