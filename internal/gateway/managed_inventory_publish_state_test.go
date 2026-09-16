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
	"encoding/json"
	"errors"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func managedPublishTestState(t *testing.T) *managedInventoryPublishState {
	t.Helper()
	state := newManagedInventoryPublishState(&config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        t.TempDir(),
	})
	if state == nil {
		t.Fatal("managed_enterprise config produced a nil publish gate")
	}
	return state
}

func managedPublishReadFile(t *testing.T, state *managedInventoryPublishState) managedInventoryPublishFile {
	t.Helper()
	raw, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatalf("read publish state: %v", err)
	}
	var file managedInventoryPublishFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode publish state: %v", err)
	}
	return file
}

// managedPublishStoredRecord reads one collection's durable record, tolerating a
// state file that was never created. A cycle that promises nothing performs no
// write at all, so "no file" and "no record for this key" are the same answer.
func managedPublishStoredRecord(
	t *testing.T,
	state *managedInventoryPublishState,
	key string,
) (managedInventoryPublishRecord, bool) {
	t.Helper()
	if _, err := os.Stat(state.path); errors.Is(err, fs.ErrNotExist) {
		return managedInventoryPublishRecord{}, false
	}
	record, ok := managedPublishReadFile(t, state).Collections[key]
	return record, ok
}

// managedPublishFullComponent exercises every field the components digest is
// supposed to cover, so the sensitivity sweep below can perturb one at a time.
func managedPublishFullComponent() endpointInventoryComponent {
	mcpDisabled := false
	installed := true
	hasConfig := true
	hasBinary := false
	return endpointInventoryComponent{
		id:                          "component-1",
		componentType:               "mcp_server",
		signal:                      "configured_mcp_server",
		product:                     "filesystem",
		active:                      true,
		itemName:                    "filesystem",
		itemDescription:             "local filesystem bridge",
		connectorSource:             "built-in",
		connectorToolInspectionMode: "both",
		connectorSubprocessPolicy:   "none",
		mcpTransport:                "stdio",
		mcpCommandBasename:          "npx",
		mcpURLHost:                  "localhost:8080",
		mcpAuthProviderType:         "oauth",
		mcpDisabled:                 &mcpDisabled,
		agentConnector:              "claudecode",
		agentInstalled:              &installed,
		agentHasConfig:              &hasConfig,
		agentConfigBasename:         "settings.json",
		agentConfigPathHash:         "cfg-hash",
		agentHasBinary:              &hasBinary,
		agentBinaryBasename:         "claude",
		agentBinaryPathHash:         "bin-hash",
		agentVersion:                "1.2.3",
		agentProbeStatus:            "ok",
		agentScannedAt:              "2026-09-15T10:00:00Z",
	}
}

func managedPublishFullSignal() inventory.AISignal {
	lastActive := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	return inventory.AISignal{
		SignalID:                     "signal-1",
		SignatureID:                  "skill",
		Category:                     inventory.SignalSkill,
		Fingerprint:                  "fingerprint-1",
		EvidenceHash:                 "evidence-1",
		State:                        inventory.AIStateSeen,
		Confidence:                   0.91,
		FirstSeen:                    lastActive.Add(-time.Hour),
		LastSeen:                     lastActive,
		LastActiveAt:                 &lastActive,
		Runtime:                      &inventory.ProcessRuntime{PID: 4242, UptimeSec: 120},
		ModelProvenanceHubResolvedAt: lastActive,
	}
}

// TestManagedInventoryDigestIgnoresVolatileFields is the highest-value test in
// this file: a digest that absorbs a field which moves on its own defeats the
// entire change gate silently — every cycle looks changed and nothing is saved.
func TestManagedInventoryDigestIgnoresVolatileFields(t *testing.T) {
	baseComponent := managedPublishFullComponent()
	componentBase := managedInventoryComponentsDigest("key", []endpointInventoryComponent{baseComponent})
	componentCases := map[string]func(*endpointInventoryComponent){
		"agentScannedAt": func(component *endpointInventoryComponent) {
			component.agentScannedAt = "2026-09-15T10:30:00Z"
		},
		"agentProbeStatus": func(component *endpointInventoryComponent) {
			component.agentProbeStatus = "timeout"
		},
	}
	for name, mutate := range componentCases {
		t.Run("component/"+name, func(t *testing.T) {
			perturbed := managedPublishFullComponent()
			mutate(&perturbed)
			got := managedInventoryComponentsDigest("key", []endpointInventoryComponent{perturbed})
			if got != componentBase {
				t.Fatalf("volatile field %s changed the digest: %s != %s", name, got, componentBase)
			}
		})
	}

	baseSignal := managedPublishFullSignal()
	signalBase := managedInventorySignalsDigest("key", []inventory.AISignal{baseSignal})
	later := time.Date(2026, 9, 15, 10, 30, 0, 0, time.UTC)
	signalCases := map[string]func(*inventory.AISignal){
		"State":        func(signal *inventory.AISignal) { signal.State = inventory.AIStateNew },
		"Confidence":   func(signal *inventory.AISignal) { signal.Confidence = 0.42 },
		"FirstSeen":    func(signal *inventory.AISignal) { signal.FirstSeen = later },
		"LastSeen":     func(signal *inventory.AISignal) { signal.LastSeen = later },
		"LastActiveAt": func(signal *inventory.AISignal) { signal.LastActiveAt = &later },
		"Runtime": func(signal *inventory.AISignal) {
			signal.Runtime = &inventory.ProcessRuntime{PID: 9999, UptimeSec: 999}
		},
		"RuntimeNil": func(signal *inventory.AISignal) { signal.Runtime = nil },
		"ModelProvenanceHubResolvedAt": func(signal *inventory.AISignal) {
			signal.ModelProvenanceHubResolvedAt = later
		},
	}
	for name, mutate := range signalCases {
		t.Run("signal/"+name, func(t *testing.T) {
			perturbed := managedPublishFullSignal()
			mutate(&perturbed)
			got := managedInventorySignalsDigest("key", []inventory.AISignal{perturbed})
			if got != signalBase {
				t.Fatalf("volatile field %s changed the digest: %s != %s", name, got, signalBase)
			}
		})
	}
}

// TestManagedInventoryDigestDetectsMeaningfulFields is the mirror image: a field
// accidentally dropped from the allowlist would hide a real inventory change for
// up to managedInventoryFullBundleInterval.
func TestManagedInventoryDigestDetectsMeaningfulFields(t *testing.T) {
	baseComponent := managedPublishFullComponent()
	componentBase := managedInventoryComponentsDigest("key", []endpointInventoryComponent{baseComponent})
	otherBool := true
	componentCases := map[string]func(*endpointInventoryComponent){
		"id":                          func(c *endpointInventoryComponent) { c.id = "component-2" },
		"componentType":               func(c *endpointInventoryComponent) { c.componentType = "skill_entry" },
		"signal":                      func(c *endpointInventoryComponent) { c.signal = "discovered_skill" },
		"product":                     func(c *endpointInventoryComponent) { c.product = "other" },
		"active":                      func(c *endpointInventoryComponent) { c.active = false },
		"itemName":                    func(c *endpointInventoryComponent) { c.itemName = "other" },
		"itemDescription":             func(c *endpointInventoryComponent) { c.itemDescription = "other" },
		"connectorSource":             func(c *endpointInventoryComponent) { c.connectorSource = "plugin" },
		"connectorToolInspectionMode": func(c *endpointInventoryComponent) { c.connectorToolInspectionMode = "request" },
		"connectorSubprocessPolicy":   func(c *endpointInventoryComponent) { c.connectorSubprocessPolicy = "all" },
		"mcpTransport":                func(c *endpointInventoryComponent) { c.mcpTransport = "http" },
		"mcpCommandBasename":          func(c *endpointInventoryComponent) { c.mcpCommandBasename = "uvx" },
		"mcpURLHost":                  func(c *endpointInventoryComponent) { c.mcpURLHost = "127.0.0.1:9000" },
		"mcpAuthProviderType":         func(c *endpointInventoryComponent) { c.mcpAuthProviderType = "none" },
		"mcpDisabled":                 func(c *endpointInventoryComponent) { c.mcpDisabled = &otherBool },
		"mcpDisabledNil":              func(c *endpointInventoryComponent) { c.mcpDisabled = nil },
		"agentConnector":              func(c *endpointInventoryComponent) { c.agentConnector = "codex" },
		"agentInstalled":              func(c *endpointInventoryComponent) { c.agentInstalled = nil },
		"agentHasConfig":              func(c *endpointInventoryComponent) { c.agentHasConfig = nil },
		"agentConfigBasename":         func(c *endpointInventoryComponent) { c.agentConfigBasename = "config.toml" },
		"agentConfigPathHash":         func(c *endpointInventoryComponent) { c.agentConfigPathHash = "cfg-hash-2" },
		"agentHasBinary":              func(c *endpointInventoryComponent) { c.agentHasBinary = &otherBool },
		"agentBinaryBasename":         func(c *endpointInventoryComponent) { c.agentBinaryBasename = "codex" },
		"agentBinaryPathHash":         func(c *endpointInventoryComponent) { c.agentBinaryPathHash = "bin-hash-2" },
		"agentVersion":                func(c *endpointInventoryComponent) { c.agentVersion = "1.2.4" },
	}
	for name, mutate := range componentCases {
		t.Run("component/"+name, func(t *testing.T) {
			perturbed := managedPublishFullComponent()
			mutate(&perturbed)
			if got := managedInventoryComponentsDigest(
				"key", []endpointInventoryComponent{perturbed},
			); got == componentBase {
				t.Fatalf("meaningful field %s did not change the digest", name)
			}
		})
	}

	baseSignal := managedPublishFullSignal()
	signalBase := managedInventorySignalsDigest("key", []inventory.AISignal{baseSignal})
	signalCases := map[string]func(*inventory.AISignal){
		"SignalID":     func(s *inventory.AISignal) { s.SignalID = "signal-2" },
		"Category":     func(s *inventory.AISignal) { s.Category = inventory.SignalPlugin },
		"Fingerprint":  func(s *inventory.AISignal) { s.Fingerprint = "fingerprint-2" },
		"EvidenceHash": func(s *inventory.AISignal) { s.EvidenceHash = "evidence-2" },
	}
	for name, mutate := range signalCases {
		t.Run("signal/"+name, func(t *testing.T) {
			perturbed := managedPublishFullSignal()
			mutate(&perturbed)
			if got := managedInventorySignalsDigest(
				"key", []inventory.AISignal{perturbed},
			); got == signalBase {
				t.Fatalf("meaningful field %s did not change the digest", name)
			}
		})
	}
}

// TestManagedInventoryDigestOptionalBoolIsThreeValued pins the *bool trap: nil
// and false must not collide, or losing an explicit `disabled: false` would look
// like no change at all.
func TestManagedInventoryDigestOptionalBoolIsThreeValued(t *testing.T) {
	yes, no := true, false
	digests := map[string]string{}
	for name, value := range map[string]*bool{"nil": nil, "false": &no, "true": &yes} {
		component := endpointInventoryComponent{id: "c", mcpDisabled: value}
		digests[name] = managedInventoryComponentsDigest(
			"key", []endpointInventoryComponent{component},
		)
	}
	if digests["nil"] == digests["false"] ||
		digests["nil"] == digests["true"] ||
		digests["false"] == digests["true"] {
		t.Fatalf("optional bool digests collided: %+v", digests)
	}
	if managedInventoryOptionalBool(nil) != "" ||
		managedInventoryOptionalBool(&no) != "false" ||
		managedInventoryOptionalBool(&yes) != "true" {
		t.Fatal("optional bool token rendering changed")
	}
}

// TestManagedInventoryDigestFramingResistsConcatenation guards the separator /
// length-prefix framing: without it ("a","bc") and ("ab","c") hash the same.
func TestManagedInventoryDigestFramingResistsConcatenation(t *testing.T) {
	left := managedInventoryComponentsDigest("key", []endpointInventoryComponent{
		{itemName: "a", product: "bc"},
	})
	right := managedInventoryComponentsDigest("key", []endpointInventoryComponent{
		{itemName: "ab", product: "c"},
	})
	if left == right {
		t.Fatal("field framing collided across a shifted boundary")
	}
	// Row framing: one row "ab" vs two rows "a" and "b".
	single := managedInventoryDigest("key", []string{"ab"})
	pair := managedInventoryDigest("key", []string{"a", "b"})
	if single == pair {
		t.Fatal("row framing collided across a shifted boundary")
	}
	// The collection key is mixed in, so the same rows under two keys differ.
	if managedInventoryDigest("key-a", []string{"row"}) ==
		managedInventoryDigest("key-b", []string{"row"}) {
		t.Fatal("collection key does not participate in the digest")
	}
}

// TestManagedInventoryDigestIsOrderIndependent matters because the emit-time
// sort is a stable sort on (itemName, id): duplicate pairs keep their input
// order, which is detector and map-iteration dependent.
func TestManagedInventoryDigestIsOrderIndependent(t *testing.T) {
	components := []endpointInventoryComponent{
		{id: "a", itemName: "same"},
		{id: "b", itemName: "same"},
		{id: "c", itemName: "other"},
		// Two fully duplicate (itemName, id) rows: a stable sort cannot order
		// these deterministically, so only the digest's own sort saves us.
		{id: "d", itemName: "dup", product: "first"},
		{id: "d", itemName: "dup", product: "second"},
	}
	want := managedInventoryComponentsDigest("key", components)
	random := rand.New(rand.NewSource(7))
	for attempt := 0; attempt < 25; attempt++ {
		shuffled := append([]endpointInventoryComponent(nil), components...)
		random.Shuffle(len(shuffled), func(left, right int) {
			shuffled[left], shuffled[right] = shuffled[right], shuffled[left]
		})
		if got := managedInventoryComponentsDigest("key", shuffled); got != want {
			t.Fatalf("attempt %d: digest depends on input order", attempt)
		}
	}
}

func TestManagedInventoryDigestEmptyCollectionIsStable(t *testing.T) {
	first := managedInventoryComponentsDigest("key", nil)
	second := managedInventoryComponentsDigest("key", []endpointInventoryComponent{})
	if first != second || first == "" {
		t.Fatalf("empty collection digest unstable: %q vs %q", first, second)
	}
	if first == managedInventoryComponentsDigest(
		"key", []endpointInventoryComponent{{id: "c"}},
	) {
		t.Fatal("empty collection collided with a populated one")
	}
	// "Nothing stored yet" must still publish, which is what makes the empty
	// digest distinct from an absent record rather than equal to it.
	state := managedPublishTestState(t)
	cycle := state.beginCycle("scan-1", time.Now().UTC(), true)
	if !cycle.shouldPublish("key", first) {
		t.Fatal("empty collection with no stored record was suppressed")
	}
}

// TestManagedInventorySignalsDigestExcludesGone documents why the caller needs a
// lifecycle-count term: a removal is invisible to the digest by construction.
func TestManagedInventorySignalsDigestExcludesGone(t *testing.T) {
	present := managedPublishFullSignal()
	removed := managedPublishFullSignal()
	removed.SignalID = "signal-gone"
	removed.State = inventory.AIStateGone
	withGone := managedInventorySignalsDigest("key", []inventory.AISignal{present, removed})
	withoutGone := managedInventorySignalsDigest("key", []inventory.AISignal{present})
	if withGone != withoutGone {
		t.Fatal("gone signals reached the digest input")
	}
}

func TestManagedInventoryPublishStateGating(t *testing.T) {
	state := managedPublishTestState(t)
	now := time.Now().UTC()

	// Cycle 1: nothing stored, so the bundle is due and everything publishes.
	first := state.beginCycle("scan-1", now, true)
	if !first.forcedBundle() {
		t.Fatal("first cycle was not treated as a due bundle")
	}
	if !first.shouldPublish("collection", "digest-a") {
		t.Fatal("first cycle suppressed an unpublished collection")
	}
	first.recordPublished("collection", "digest-a", 3)
	first.commit()
	file := managedPublishReadFile(t, state)
	if file.FullBundleAt.IsZero() {
		t.Fatal("a clean forced bundle did not stamp full_bundle_published_at")
	}
	if record := file.Collections["collection"]; record.Digest != "digest-a" || record.Records != 3 {
		t.Fatalf("collection record not persisted: %+v", record)
	}

	// Cycle 2: identical content, bundle not due -> suppressed, no write.
	before, err := os.Stat(state.path)
	if err != nil {
		t.Fatal(err)
	}
	second := state.beginCycle("scan-2", now.Add(time.Hour), true)
	if second.forcedBundle() {
		t.Fatal("bundle came due one hour after a stamp")
	}
	if second.shouldPublish("collection", "digest-a") {
		t.Fatal("unchanged collection was published")
	}
	second.commit()
	after, err := os.Stat(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("a fully suppressed cycle rewrote the state file")
	}

	// Cycle 3: content changed -> publishes, and only that collection.
	third := state.beginCycle("scan-3", now.Add(2*time.Hour), true)
	if !third.shouldPublish("collection", "digest-b") {
		t.Fatal("changed collection was suppressed")
	}
	if third.shouldPublish("other", "digest-a") == false {
		t.Fatal("an unpublished second collection was suppressed")
	}
	third.recordPublished("collection", "digest-b", 4)
	third.commit()
	if got := managedPublishReadFile(t, state).Collections["collection"].Digest; got != "digest-b" {
		t.Fatalf("changed digest not persisted: %q", got)
	}

	// Cycle 4: back to the earlier content -> still a change relative to the
	// last publish, so it ships.
	fourth := state.beginCycle("scan-4", now.Add(3*time.Hour), true)
	if !fourth.shouldPublish("collection", "digest-a") {
		t.Fatal("reverting to older content was suppressed")
	}
}

func TestManagedInventoryPublishStateDailyBundle(t *testing.T) {
	state := managedPublishTestState(t)
	start := time.Now().UTC()
	baseline := state.beginCycle("scan-1", start, true)
	baseline.recordPublished("collection", "digest-a", 1)
	baseline.commit()
	stamped := managedPublishReadFile(t, state).FullBundleAt
	if stamped.IsZero() {
		t.Fatal("baseline did not stamp the bundle clock")
	}

	// Just under the interval: still suppressed.
	early := state.beginCycle("scan-2", start.Add(managedInventoryFullBundleInterval-time.Minute), true)
	if early.forcedBundle() || early.shouldPublish("collection", "digest-a") {
		t.Fatal("bundle came due before the interval elapsed")
	}
	early.commit()

	// At the interval: everything republishes even though nothing changed.
	due := state.beginCycle("scan-3", start.Add(managedInventoryFullBundleInterval), true)
	if !due.forcedBundle() {
		t.Fatal("bundle did not come due at the interval")
	}
	if !due.shouldPublish("collection", "digest-a") {
		t.Fatal("a due bundle suppressed an unchanged collection")
	}
	due.recordPublished("collection", "digest-a", 1)
	due.commit()
	restamped := managedPublishReadFile(t, state).FullBundleAt
	if !restamped.After(stamped) {
		t.Fatalf("bundle clock not advanced: %s !> %s", restamped, stamped)
	}

	// The cycle right after a bundle is quiet again.
	quiet := state.beginCycle("scan-4", start.Add(managedInventoryFullBundleInterval+time.Minute), true)
	if quiet.forcedBundle() || quiet.shouldPublish("collection", "digest-a") {
		t.Fatal("cycle after a bundle was still forced")
	}
}

// TestManagedInventoryPublishStateBundleDecisionSharedAcrossPublishers pins the
// cross-publisher agreement: the signals path asks first and the endpoint path
// stamps last, so both must see the same answer within one discovery scan.
func TestManagedInventoryPublishStateBundleDecisionSharedAcrossPublishers(t *testing.T) {
	state := managedPublishTestState(t)
	start := time.Now().UTC()
	baseline := state.beginCycle("scan-1", start, true)
	baseline.recordPublished("collection", "digest-a", 1)
	baseline.commit()

	due := start.Add(managedInventoryFullBundleInterval)
	// Signals publisher (bundleScope=false) runs first and observes the bundle.
	signals := state.beginCycle("scan-due", due, false)
	if !signals.forcedBundle() {
		t.Fatal("signals publisher did not observe the due bundle")
	}
	signals.recordPublished(managedInventorySignalsKey, "signals-a", 2)
	signals.commit()
	// It must not have consumed the day's bundle: it cannot ship the six
	// collections, so only the endpoint hook may stamp.
	if afterSignals := managedPublishReadFile(t, state).FullBundleAt; !afterSignals.Before(due) {
		t.Fatal("a signals-only cycle stamped the bundle clock")
	}

	// Endpoint publisher, same scan, still sees forced and stamps.
	endpoint := state.beginCycle("scan-due", due, true)
	if !endpoint.forcedBundle() {
		t.Fatal("endpoint publisher lost the memoized bundle decision")
	}
	endpoint.recordPublished("collection", "digest-a", 1)
	endpoint.commit()
	if !managedPublishReadFile(t, state).FullBundleAt.Equal(due) {
		t.Fatal("endpoint publisher did not stamp the bundle clock")
	}
}

func TestManagedInventoryPublishStateDegradedCycleDoesNotConsumeBundle(t *testing.T) {
	for _, test := range []struct {
		name        string
		bundleScope bool
		degrade     bool
	}{
		{name: "degraded", bundleScope: true, degrade: true},
		{name: "no-bundle-scope", bundleScope: false, degrade: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := managedPublishTestState(t)
			now := time.Now().UTC()
			cycle := state.beginCycle("scan-1", now, test.bundleScope)
			if !cycle.forcedBundle() {
				t.Fatal("fresh state was not forced")
			}
			cycle.recordPublished("collection", "digest-a", 1)
			if test.degrade {
				cycle.markDegraded()
			}
			cycle.commit()
			if got := managedPublishReadFile(t, state).FullBundleAt; !got.IsZero() {
				t.Fatalf("bundle clock stamped by an ineligible cycle: %s", got)
			}
			// The retry on the next tick must still be forced.
			retry := state.beginCycle("scan-2", now.Add(30*time.Minute), true)
			if !retry.forcedBundle() {
				t.Fatal("bundle retry was not forced")
			}
		})
	}
}

// TestManagedInventoryPublishStateFutureStampIsDue: a clock that jumped forward
// and was then corrected must not wedge the daily bundle until the skew elapses.
func TestManagedInventoryPublishStateFutureStampIsDue(t *testing.T) {
	state := managedPublishTestState(t)
	now := time.Now().UTC()
	seed := state.beginCycle("scan-1", now, true)
	seed.recordPublished("collection", "digest-a", 1)
	seed.commit()

	state.mu.Lock()
	state.file.FullBundleAt = now.Add(30 * 24 * time.Hour)
	state.cycleKnown = false
	state.mu.Unlock()

	corrected := state.beginCycle("scan-2", now, true)
	if !corrected.forcedBundle() {
		t.Fatal("a future-dated bundle stamp suppressed the bundle")
	}
	corrected.recordPublished("collection", "digest-a", 1)
	corrected.commit()
	if got := managedPublishReadFile(t, state).FullBundleAt; got.After(now) {
		t.Fatalf("future stamp was not replaced: %s", got)
	}
}

func TestManagedInventoryPublishStateFailOpen(t *testing.T) {
	forwardVersion, err := json.Marshal(managedInventoryPublishFile{
		Version:      managedInventoryPublishStateVersion + 1,
		FullBundleAt: time.Now().UTC(),
		Collections: map[string]managedInventoryPublishRecord{
			"collection": {Digest: "digest-a"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		content []byte
		write   bool
	}{
		{name: "missing", write: false},
		{name: "malformed", content: []byte("{not json"), write: true},
		{name: "empty", content: nil, write: true},
		{name: "forward-version", content: forwardVersion, write: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if test.write {
				if err := os.WriteFile(
					filepath.Join(dataDir, managedInventoryPublishStateFile), test.content, 0o600,
				); err != nil {
					t.Fatal(err)
				}
			}
			state := newManagedInventoryPublishState(&config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				DataDir:        dataDir,
			})
			if state == nil {
				t.Fatal("nil gate in managed mode")
			}
			cycle := state.beginCycle("scan-1", time.Now().UTC(), true)
			if !cycle.forcedBundle() {
				t.Fatal("unreadable state did not fail open to a full bundle")
			}
			if !cycle.shouldPublish("collection", "digest-a") {
				t.Fatal("unreadable state suppressed a collection")
			}
		})
	}
}

func TestManagedInventoryPublishStateSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        dataDir,
	}
	first := newManagedInventoryPublishState(cfg)
	now := time.Now().UTC()
	cycle := first.beginCycle("scan-1", now, true)
	cycle.recordPublished("collection", "digest-a", 1)
	cycle.commit()

	// A restart rebuilds the gate from disk: neither the digests nor the daily
	// bundle clock may reset, or an upgrade would trigger a fleet republish.
	second := newManagedInventoryPublishState(cfg)
	restarted := second.beginCycle("scan-2", now.Add(time.Hour), true)
	if restarted.forcedBundle() {
		t.Fatal("restart reset the daily bundle clock")
	}
	if restarted.shouldPublish("collection", "digest-a") {
		t.Fatal("restart lost the stored digest")
	}
}

// TestManagedInventoryPublishStateNilOutsideManagedEnterprise is the OSS pin:
// no gate object, therefore no digest work and no state file, in every other
// deployment mode.
func TestManagedInventoryPublishStateNilOutsideManagedEnterprise(t *testing.T) {
	for _, mode := range []string{"", "standalone", "oss", "managed", "enterprise", "MANAGED-ENTERPRISE"} {
		t.Run("mode="+mode, func(t *testing.T) {
			dataDir := t.TempDir()
			if state := newManagedInventoryPublishState(&config.Config{
				DeploymentMode: mode, DataDir: dataDir,
			}); state != nil {
				t.Fatalf("mode %q produced a publish gate", mode)
			}
			entries, err := os.ReadDir(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("mode %q created state on disk: %v", mode, entries)
			}
		})
	}
	if newManagedInventoryPublishState(nil) != nil {
		t.Fatal("nil config produced a publish gate")
	}
	// Managed mode without a data dir has nowhere durable to remember publishes,
	// so it must fall back to the ungated behavior rather than suppress in memory.
	if newManagedInventoryPublishState(&config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
	}) != nil {
		t.Fatal("managed mode without a data dir produced a publish gate")
	}
}

// TestManagedInventoryPublishStateNilReceiverNeverSuppresses is the invariant the
// whole OSS-parity argument rests on.
func TestManagedInventoryPublishStateNilReceiverNeverSuppresses(t *testing.T) {
	var state *managedInventoryPublishState
	if !state.bundleDue("scan-1", time.Now()) {
		t.Fatal("nil state reported the bundle as not due")
	}
	cycle := state.beginCycle("scan-1", time.Now(), true)
	if cycle != nil {
		t.Fatal("nil state produced a cycle")
	}
	if !cycle.forcedBundle() || !cycle.shouldPublish("collection", "digest-a") {
		t.Fatal("nil cycle suppressed a publish")
	}
	// Must not panic.
	cycle.recordPublished("collection", "digest-a", 1)
	cycle.markDegraded()
	cycle.commit()
}
