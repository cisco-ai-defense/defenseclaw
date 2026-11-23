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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Change-gated managed inventory publishing.
//
// managed_enterprise publishes the complete endpoint AI inventory to AI Defense
// on the full-scan cadence (managedEnterpriseScanInterval). Re-sending an
// identical snapshot every tick is pure waste: the ingest endpoint does not ack,
// drops on queue-full, and a steady-state endpoint produces byte-identical
// collections 48x a day. This file gates those publishes on a content digest so
// a collection ships only when its meaningful contents changed, with one
// guaranteed complete bundle every managedInventoryFullBundleInterval so a cloud
// that missed the baseline always re-baselines within a day.
//
// Outside Secure Client the same gate keeps the endpoint inventory sent to
// the operator's own destinations in its own file,
// endpointInventoryPublishStateFile, so a machine that later moves to Secure
// Client re-baselines AI Defense in full.
// Every method here is nil-receiver safe with "never suppress" semantics.
const (
	// managedInventoryFullBundleInterval is release-owned: AI Defense receives
	// one complete, self-consistent copy of the endpoint inventory at least
	// this often even when nothing changed. Deliberately not operator
	// configurable, matching the rest of the managed AID publishing contract
	// (managedEnterpriseScanInterval, the generated managed destination).
	managedInventoryFullBundleInterval = 24 * time.Hour

	managedInventoryPublishStateFile = "managed_inventory_publish_state.json"
	// endpointInventoryPublishStateFile is the inventory state of an OSS
	// per-user or managed standalone gateway, in that gateway's data dir.
	endpointInventoryPublishStateFile = "endpoint_inventory_publish_state.json"
	// Version 2 invalidates v1 publish digests so the first complete scan after
	// upgrade re-baselines AI Defense with connector-native MCP details. This is
	// required because v1 could record a successful native publish before the
	// backend consumer was enabled, suppressing an unchanged retry for 24 hours.
	managedInventoryPublishStateVersion = 2

	// managedInventorySignalsKey is the state key for the per-signal lifecycle
	// snapshot. The six endpoint collections key on their own `source` strings.
	managedInventorySignalsKey = "ai_discovery_signals"

	// Digest framing. Fields inside one row are joined with the ASCII unit
	// separator; rows are framed with the ASCII record separator and
	// length-prefixed so ("a","bc") and ("ab","c") cannot collide.
	managedInventoryFieldSeparator  = "\x1f"
	managedInventoryRecordSeparator = "\x1e"
)

// managedInventoryPublishRecord is the last successful publish of one
// collection. PublishedAt and Records are operational breadcrumbs for support
// bundles; only Digest participates in the gate decision.
type managedInventoryPublishRecord struct {
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"published_at"`
	Records     int       `json:"records"`
}

type managedInventoryPublishFile struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	// FullBundleAt is the last time a complete, non-degraded bundle shipped.
	// Zero means "never", which forces a bundle on the next cycle.
	FullBundleAt time.Time                                `json:"full_bundle_published_at"`
	Collections  map[string]managedInventoryPublishRecord `json:"collections"`
	// Skills is the last published state of each skill (managed_skill_state.go).
	Skills map[string]managedSkillState `json:"skills,omitempty"`
	// SkillManifests is how much of each SKILL.md, by hash, was locally submitted
	// (managed_skill_manifest.go).
	SkillManifests        map[string]managedSkillManifest        `json:"skill_manifests,omitempty"`
	ManifestReceipts      map[string]managedManifestReceiptState `json:"manifest_receipts,omitempty"`
	ManifestReceiptCursor string                                 `json:"manifest_receipt_cursor,omitempty"`
	ManifestBodyCursor    string                                 `json:"manifest_body_cursor,omitempty"`
	ManifestDestination   string                                 `json:"manifest_destination,omitempty"`
}

// managedInventoryPublishState is the durable, process-wide publish memory. It
// lives on *Sidecar rather than inside an emitter closure because the emitter
// closures are rebuilt on every config reload, and it is persisted to disk so a
// restart or upgrade does not trigger a fleet-wide republish storm or reset the
// daily bundle clock.
type managedInventoryPublishState struct {
	commitMu sync.Mutex
	mu       sync.Mutex
	path     string
	file     managedInventoryPublishFile
	// aidBundle: the daily bundle is AI Defense's complete copy, so only a
	// complete, non-degraded cycle stamps it (Secure Client). Elsewhere it is
	// the daily refresh of the operator's own destinations, stamped by any
	// forced scan cycle: a collection that stays partial must not make every
	// scan send every collection again.
	aidBundle bool

	// Bundle-due decision memoized per discovery scan so the two publishers
	// reached from one inventory.fanoutReport agree, even though the timestamp
	// is only re-stamped at the end of the cycle.
	cycleScanID string
	cycleKnown  bool
	cycleForced bool

	readSkillManifest func(hash string) ([]byte, bool)
	receiptReader     managedaid.ManifestReceiptReader
	receiptEpoch      uint64
	receiptBinding    manifestReceiptRuntimeBinding
	destinationEpoch  uint64
	destinationDirty  bool
}

// newManagedInventoryPublishState returns the publish state of cfg's
// gateway: the managed inventory state on a Secure Client endpoint, the
// operator inventory state everywhere else. It returns nil without a data dir.
func newManagedInventoryPublishState(cfg *config.Config) *managedInventoryPublishState {
	if cfg == nil {
		return nil
	}
	dataDir := strings.TrimSpace(cfg.DataDir)
	if dataDir == "" {
		return nil
	}
	name := endpointInventoryPublishStateFile
	aidBundle := managed.IsManagedEnterprise(cfg.DeploymentMode) && cfg.ManagedAIDOnly()
	if aidBundle {
		name = managedInventoryPublishStateFile
	}
	state := &managedInventoryPublishState{
		path:      filepath.Join(dataDir, name),
		aidBundle: aidBundle,
	}
	state.file = loadManagedInventoryPublishFile(state.path)
	return state
}

// loadManagedInventoryPublishFile fails open in the "publish everything"
// direction. A missing, unreadable, malformed, or forward-versioned file yields
// empty state, which has a zero FullBundleAt and no stored digests, so the next
// cycle republishes the complete bundle. Suppression is never inferred from a
// state file we could not understand.
func loadManagedInventoryPublishFile(path string) managedInventoryPublishFile {
	empty := managedInventoryPublishFile{
		Version:     managedInventoryPublishStateVersion,
		Collections: map[string]managedInventoryPublishRecord{},
	}
	raw, err := safefile.ReadRegularFileBounded(path, 32<<20)
	if err != nil {
		// A first-run absence is the norm; only surface real read errors.
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"[sidecar] managed inventory publish state unreadable; republishing full inventory: %v\n", err)
		}
		return empty
	}
	var file managedInventoryPublishFile
	if err := json.Unmarshal(raw, &file); err != nil {
		fmt.Fprintf(os.Stderr,
			"[sidecar] managed inventory publish state malformed; republishing full inventory: %v\n", err)
		return empty
	}
	if file.Version != managedInventoryPublishStateVersion {
		fmt.Fprintf(os.Stderr,
			"[sidecar] managed inventory publish state version %d unsupported; republishing full inventory\n",
			file.Version)
		return empty
	}
	if file.Collections == nil {
		file.Collections = map[string]managedInventoryPublishRecord{}
	}
	sanitizeManifestReceipts(&file)
	return file
}

// bundleDue reports whether the daily complete-bundle deadline has passed. The
// answer is memoized on scanID so both publishers in one fanout agree; an empty
// scanID (the reload/startup and API paths, which carry no discovery scan)
// evaluates the deadline directly, which yields the same answer because
// FullBundleAt is only advanced at the end of a cycle.
func (state *managedInventoryPublishState) bundleDue(scanID string, now time.Time) bool {
	if state == nil {
		return true
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	scanID = strings.TrimSpace(scanID)
	if scanID != "" && state.cycleKnown && state.cycleScanID == scanID {
		return state.cycleForced
	}
	// A future-dated stamp is treated as due rather than trusted. Otherwise a
	// device whose clock jumped forward and was then corrected — or a corrupt /
	// tampered state file — would suppress the daily bundle for as long as the
	// skew lasted, with no way to recover short of deleting the file. Forcing one
	// extra bundle is the cheap, self-correcting direction.
	forced := state.file.FullBundleAt.IsZero() ||
		state.file.FullBundleAt.After(now) ||
		!now.Before(state.file.FullBundleAt.Add(managedInventoryFullBundleInterval))
	if scanID != "" {
		state.cycleKnown = true
		state.cycleScanID = scanID
		state.cycleForced = forced
	}
	return forced
}

// beginCycle opens a publish cycle.
//
// bundleScope declares that this cycle attempts the COMPLETE endpoint bundle.
// Only a complete, forced, non-degraded cycle re-stamps FullBundleAt: a reload
// or startup emit carries no discovery report and therefore cannot enumerate
// the discovered skill / plugin / MCP collections, so letting it satisfy the
// daily bundle would suppress the real bundle for another 24 h and leave the
// cloud permanently missing those collections.
func (state *managedInventoryPublishState) beginCycle(
	scanID string,
	now time.Time,
	bundleScope bool,
) *managedInventoryPublishCycle {
	if state == nil {
		return nil
	}
	return &managedInventoryPublishCycle{
		state:            state,
		now:              now,
		scanID:           strings.TrimSpace(scanID),
		forced:           state.bundleDue(scanID, now),
		bundleScope:      bundleScope,
		published:        map[string]managedInventoryPublishRecord{},
		destinationEpoch: state.manifestDestinationEpoch(),
	}
}

// managedInventoryPublishCycle accumulates one cycle's decisions so the state
// file is written at most once per cycle (and not at all in steady state).
type managedInventoryPublishCycle struct {
	state                  *managedInventoryPublishState
	now                    time.Time
	scanID                 string
	forced                 bool
	bundleScope            bool
	degraded               bool
	published              map[string]managedInventoryPublishRecord
	skills                 map[string]managedSkillState
	skillRemovalCandidates map[string]managedSkillState
	skillRemovals          map[string]managedSkillState
	manifests              map[string]managedSkillManifest
	receipts               map[string]managedManifestReceiptState
	manifestProjected      map[string]managedManifestReceiptState
	receiptEpoch           uint64
	receiptCursor          string
	bodyCursor             string
	receiptDirty           bool
	receiptFresh           map[string]bool
	receiptGeneration      uint64
	receiptAcknowledged    map[string]managedSkillManifest
	destinationEpoch       uint64
}

// forcedBundle reports whether this cycle ignores digests and publishes
// everything. A nil cycle (no publish state) always publishes.
func (cycle *managedInventoryPublishCycle) forcedBundle() bool {
	return cycle == nil || cycle.forced
}

// shouldPublish reports whether a collection needs to ship this cycle. A nil
// cycle (no publish state: no data folder) never suppresses.
func (cycle *managedInventoryPublishCycle) shouldPublish(key, digest string) bool {
	if cycle == nil || cycle.state == nil || cycle.forced {
		return true
	}
	cycle.state.mu.Lock()
	defer cycle.state.mu.Unlock()
	stored, ok := cycle.state.file.Collections[key]
	if !ok || stored.Digest == "" {
		return true
	}
	return stored.Digest != digest
}

// recordPublished remembers a collection that shipped completely and cleanly.
// Callers must not record a degraded or failed publish: a stored digest is a
// promise that the cloud holds that exact content.
func (cycle *managedInventoryPublishCycle) recordPublished(key, digest string, records int) {
	if cycle == nil || key == "" || digest == "" {
		return
	}
	cycle.published[key] = managedInventoryPublishRecord{
		Digest:      digest,
		PublishedAt: cycle.now,
		Records:     records,
	}
}

// covers reports whether AI Defense has accepted this exact collection, either
// during the current cycle or in a previous successful cycle. It is used to
// keep child inventory from referencing a parent whose managed publish failed.
func (cycle *managedInventoryPublishCycle) covers(key, digest string) bool {
	if cycle == nil || digest == "" {
		return false
	}
	if current, ok := cycle.published[key]; ok && current.Digest == digest {
		return true
	}
	if cycle.state == nil {
		return false
	}
	cycle.state.mu.Lock()
	defer cycle.state.mu.Unlock()
	stored, ok := cycle.state.file.Collections[key]
	return ok && stored.Digest == digest
}

// managedInventoryPublishRejected reports whether an emit that returned no error
// nevertheless failed to hand its record to the managed AI Defense destination.
//
// A nil error from Emit is not a delivery receipt, and it is not even evidence
// that the record was queued. The managed AID route is an OPTIONAL projection:
// when its redaction profile cannot be resolved, or projecting the canonical
// record fails, the pipeline records an OptionalFailure against that destination
// and returns (outcome, nil) without queueing anything — see the managed-fallback
// path in internal/observability/pipeline/local_logs.go. Recording a digest on
// the strength of that nil would break this file's central rule that a stored
// digest is a promise the cloud holds that exact content, and would suppress the
// republish for up to managedInventoryFullBundleInterval.
//
// Deliberately scoped to the managed AID destination: another optional
// destination failing says nothing about what AI Defense received, and treating
// it as a managed failure would republish for reasons unrelated to the gate.
//
// True delivery failures after enqueue (queue-full drop, network loss — the
// endpoint does not ack) remain invisible here by construction; the daily
// complete bundle is what covers those.
func managedInventoryPublishRejected(outcome pipeline.LocalLogOutcome) bool {
	for _, failure := range outcome.OptionalFailures() {
		if failure.DestinationName() == config.ObservabilityV8ManagedAIDDestinationName {
			return true
		}
	}
	return false
}

// markDegraded disqualifies this cycle from satisfying the daily bundle. Any
// emit error, or any collection that fell back to the local diagnostic action
// (partial, over-limit, or carrier-rejected — none of which reach the managed
// egress route), means the cloud did not receive a complete copy.
func (cycle *managedInventoryPublishCycle) markDegraded() {
	if cycle != nil {
		cycle.degraded = true
	}
}

// commit merges this cycle's results into the durable state and writes it at
// most once. A cycle that published nothing and did not complete a bundle
// performs no write at all, which is the steady-state path.
func (cycle *managedInventoryPublishCycle) commit() {
	if cycle == nil || cycle.state == nil {
		return
	}
	state := cycle.state
	// Keep the durable replacements in the same order as their state merges.
	// A slow earlier writer must not replace a newer acknowledgement on disk.
	state.commitMu.Lock()
	defer state.commitMu.Unlock()
	stampBundle := cycle.forced && cycle.bundleScope && !cycle.degraded
	if !state.aidBundle {
		stampBundle = cycle.forced && cycle.scanID != ""
	}
	state.mu.Lock()
	if cycle.destinationEpoch != state.destinationEpoch {
		state.mu.Unlock()
		return
	}
	if len(cycle.published) == 0 && !stampBundle && !cycle.receiptDirty && len(cycle.skillRemovals) == 0 && !state.destinationDirty {
		state.mu.Unlock()
		return
	}
	currentReceiptContext := cycle.receiptEpoch == state.receiptEpoch && (state.receiptBinding.current == nil || state.receiptBinding.current() == cycle.receiptGeneration)
	if cycle.receipts != nil && currentReceiptContext {
		state.file.ManifestReceipts = cycle.receipts
		if len(cycle.receiptAcknowledged) > 0 {
			// Other in-flight scans retain this immutable map after releasing
			// mu. Publish a replacement instead of mutating their snapshot.
			progress := make(map[string]managedSkillManifest, len(state.file.SkillManifests)+len(cycle.receiptAcknowledged))
			for hash, submitted := range state.file.SkillManifests {
				progress[hash] = submitted
			}
			for hash, acknowledged := range cycle.receiptAcknowledged {
				progress[hash] = acknowledged
			}
			state.file.SkillManifests = progress
		}
		if cycle.receiptCursor != "" {
			state.file.ManifestReceiptCursor = cycle.receiptCursor
		}
		if _, ok := cycle.published[endpointSkillInventorySource]; ok {
			for hash, record := range cycle.manifestProjected {
				state.file.ManifestReceipts[hash] = record
			}
		}
	}
	if state.file.Collections == nil {
		state.file.Collections = map[string]managedInventoryPublishRecord{}
	}
	for key, record := range cycle.published {
		state.file.Collections[key] = record
	}
	if _, ok := cycle.published[endpointSkillInventorySource]; ok && cycle.skills != nil {
		state.file.Skills = cycle.skills
		if cycle.manifests != nil && (cycle.receiptEpoch == 0 || currentReceiptContext) {
			progress := make(map[string]managedSkillManifest, len(cycle.manifests))
			for hash, submitted := range cycle.manifests {
				if latest := state.file.SkillManifests[hash]; latest.Parts == submitted.Parts && latest.Sent > submitted.Sent {
					submitted.Sent = latest.Sent
				}
				progress[hash] = submitted
			}
			state.file.SkillManifests = progress
			if cycle.bodyCursor != "" {
				state.file.ManifestBodyCursor = cycle.bodyCursor
			}
		}
	} else if len(cycle.skillRemovals) > 0 {
		remaining := make(map[string]managedSkillState, len(state.file.Skills))
		for id, skill := range state.file.Skills {
			remaining[id] = skill
		}
		for id, removed := range cycle.skillRemovals {
			if current, ok := remaining[id]; ok && current == removed {
				delete(remaining, id)
			}
		}
		state.file.Skills = remaining
	}
	if stampBundle {
		state.file.FullBundleAt = cycle.now.UTC()
		// The next cycle must re-derive the deadline against the new stamp.
		state.cycleKnown = false
		state.cycleScanID = ""
		state.cycleForced = false
	}
	state.file.Version = managedInventoryPublishStateVersion
	state.file.UpdatedAt = cycle.now.UTC()
	state.destinationDirty = false
	payload, err := json.MarshalIndent(state.file, "", "  ")
	path := state.path
	state.mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] encode managed inventory publish state: %v\n", err)
		return
	}
	payload = append(payload, '\n')
	// Same secure-write path as the AI discovery state store: on managed
	// Windows this validates the trusted runtime directory and its ACLs before
	// an atomic replace; elsewhere it falls back to a private atomic write.
	if err := managed.WriteServiceRuntimeFile(
		managed.PinnedDeploymentMode(), path, "managed inventory publish state", payload,
	); err != nil {
		// A failed write only costs a redundant republish next cycle: the
		// in-memory state already advanced, so this process stays quiet while
		// a restart falls back to publishing everything.
		fmt.Fprintf(os.Stderr, "[sidecar] persist managed inventory publish state: %v\n", err)
	}
}

// managedInventoryDigest hashes an unordered set of rows into a stable
// fingerprint.
//
// Rows are sorted here rather than trusting any caller-side ordering: the
// emit-time sort in emitInventorySnapshot is a stable sort on (itemName, id),
// which preserves *input* order for duplicate pairs, and input order depends on
// detector and map iteration. The collection key and row count are mixed in so
// an empty collection has a stable digest that is still distinct from "nothing
// stored yet".
func managedInventoryDigest(key string, rows []string) string {
	sort.Strings(rows)
	hash := sha256.New()
	fmt.Fprintf(hash, "v%d%s%s%s%d",
		managedInventoryPublishStateVersion, managedInventoryRecordSeparator,
		key, managedInventoryRecordSeparator, len(rows))
	for _, row := range rows {
		fmt.Fprintf(hash, "%s%d%s%s", managedInventoryRecordSeparator, len(row),
			managedInventoryRecordSeparator, row)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// managedInventoryOptionalBool renders a *bool as a three-valued token. nil and
// false MUST NOT collide, and the pointer address must never reach the hash.
func managedInventoryOptionalBool(value *bool) string {
	if value == nil {
		return ""
	}
	return strconv.FormatBool(*value)
}

// managedInventoryComponentsDigest fingerprints one endpoint collection.
//
// Every field here is derived from configuration, the connector registry, or
// evidence basenames and path hashes, so it moves only when the endpoint really
// changed. Three fields on the shared struct are deliberately excluded:
//
//   - agentScannedAt is report.ScannedAt, a wall-clock timestamp that advances
//     every scan and would defeat the gate outright;
//   - agentProbeStatus flips on a transient `--version` probe timeout with no
//     underlying inventory change.
//
// agentVersion IS included: an agent upgrade is a real inventory change. All
// three are populated only by emitManagedAgentInventory (the API-driven
// /api/v1/agents/discover path, which is not gated), so today this is a
// defensive contract for the shared struct rather than live behavior.
//
// Not represented here at all, and therefore excluded by construction: the
// per-emit scanID (not a struct field) and scannedAt (passed empty for all six
// endpoint collections). The digest covers the component set only, never the
// summary envelope.
func managedInventoryComponentsDigest(key string, components []endpointInventoryComponent) string {
	rows := make([]string, 0, len(components))
	for _, component := range components {
		if component.skillState == skillStateRemoved {
			// Sent once (hasRemovedSkill); the collection then settles.
			continue
		}
		rows = append(rows, strings.Join([]string{
			component.id,
			component.componentType,
			component.signal,
			component.product,
			strconv.FormatBool(component.active),
			component.itemName,
			component.itemDescription,
			component.connectorSource,
			component.connectorToolInspectionMode,
			component.connectorSubprocessPolicy,
			component.mcpTransport,
			component.mcpCommandBasename,
			component.mcpCommandFingerprint,
			component.mcpArgumentsFingerprint,
			component.mcpSourceScope,
			component.mcpServerURL,
			component.mcpURLHost,
			component.mcpAuthProviderType,
			managedInventoryOptionalBool(component.mcpDisabled),
			component.mcpToolSource,
			component.mcpToolParentID,
			component.mcpToolObservedAt,
			component.agentConnector,
			managedInventoryOptionalBool(component.agentInstalled),
			managedInventoryOptionalBool(component.agentHasConfig),
			component.agentConfigBasename,
			component.agentConfigPathHash,
			managedInventoryOptionalBool(component.agentHasBinary),
			component.agentBinaryBasename,
			component.agentBinaryPathHash,
			component.agentVersion,
			component.skillContentHash,
			component.skillContentStatus,
			component.skillFirstSeen,
			component.skillScope,
			component.skillLocation,
			strings.Join(component.skillAgents, ","),
			component.skillPublisher,
			component.skillPublisherSource,
			component.skillPlugin,
			component.skillPluginVersion,
			managedInventoryOptionalBool(component.skillPluginEnabled),
			component.vendor,
			component.skillVersion,
			strconv.FormatInt(component.skillManifestSize, 10),
		}, managedInventoryFieldSeparator))
	}
	return managedInventoryDigest(key, rows)
}

// managedInventorySignalsDigest fingerprints the per-signal lifecycle snapshot.
//
// EvidenceHash is the anchor: it is sha256 over the signal's AIEvidence rows
// (type, basename, path hash, value hash, workspace hash, quality, match kind,
// origin — no timestamps, no PIDs), and it is the exact hash the shipped
// lifecycle classifier already compares to decide `changed`. Its scan-to-scan
// stability is therefore already load-bearing: if it flapped, discovery would
// today emit spurious ai_component.changed events and signals would never
// settle into `seen`.
//
// Excluded because they move on their own: State (a new -> seen transition is
// bookkeeping, not an inventory change), Confidence (time-decayed every scan),
// FirstSeen / LastSeen / LastActiveAt (timestamps), Runtime (PIDs and process
// uptime) and ModelProvenanceHubResolvedAt (enrichment freshness marker).
//
// `gone` signals are excluded from the input entirely; a removal is surfaced to
// the gate by the caller's lifecycle-count term instead, so it publishes once
// and then stabilizes.
func managedInventorySignalsDigest(key string, signals []inventory.AISignal) string {
	rows := make([]string, 0, len(signals))
	for _, signal := range signals {
		if signal.State == inventory.AIStateGone {
			continue
		}
		rows = append(rows, strings.Join([]string{
			signal.SignalID,
			signal.Category,
			signal.Fingerprint,
			signal.EvidenceHash,
		}, managedInventoryFieldSeparator))
	}
	return managedInventoryDigest(key, rows)
}
