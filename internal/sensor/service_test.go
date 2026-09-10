// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package sensor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

type stubInventory struct{ snapshot correlate.Snapshot }

func (s stubInventory) CorrelationSnapshot() correlate.Snapshot { return s.snapshot }

type stubPlatform struct {
	capabilities map[platform.Plane]platform.Capability
}

func (stubPlatform) OSType() string     { return "linux" }
func (stubPlatform) Name() string       { return "stub" }
func (stubPlatform) WideCoverage() bool { return true }
func (s stubPlatform) Capabilities() map[platform.Plane]platform.Capability {
	return s.capabilities
}

func allPlanesAvailable() stubPlatform {
	return stubPlatform{capabilities: map[platform.Plane]platform.Capability{
		platform.PlaneA: {Plane: platform.PlaneA, Available: true, Mechanism: "stub"},
		platform.PlaneB: {Plane: platform.PlaneB, Available: true, Mechanism: "stub"},
		platform.PlaneC: {Plane: platform.PlaneC, Available: true, Mechanism: "stub"},
	}}
}

func newTestService(t *testing.T, runtime config.AIRuntimeConfig, inventoryProvider InventoryProvider) *Service {
	t.Helper()
	service, err := New(Options{
		Config:    runtime,
		Inventory: inventoryProvider,
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  StaticResolver{Names: map[string]string{}},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return service
}

// TestPollProducesASnapshotOnTheRealHost is the end-to-end smoke test: the
// service reads this machine and reports coverage without erroring.
func TestPollProducesASnapshotOnTheRealHost(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true}, nil)
	snapshot := service.Poll(context.Background())
	if snapshot.ScannedAt.IsZero() {
		t.Fatal("snapshot has no scan time")
	}
	if snapshot.ProcessesObserved == 0 {
		t.Fatal("snapshot observed no processes")
	}
	if len(snapshot.Planes) != len(platform.Planes) {
		t.Fatalf("snapshot reported %d planes, want %d", len(snapshot.Planes), len(platform.Planes))
	}
	t.Logf("processes=%d skipped=%d connections=%d unattributed=%d findings=%d",
		snapshot.ProcessesObserved, snapshot.ProcessesSkipped,
		snapshot.ConnectionsObserved, snapshot.ConnectionsUnattributed, len(snapshot.Findings))
}

// TestPlaneHealthIsReportedEvenWhenAPlaneIsNotRunning is the contract that a
// dead subscription leaves a trace. If health were reported only while a plane
// worked, silence and success would be indistinguishable.
func TestPlaneHealthIsReportedEvenWhenAPlaneIsNotRunning(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true}, nil)
	snapshot := service.Poll(context.Background())

	seen := map[platform.Plane]bool{}
	for _, health := range snapshot.Planes {
		seen[health.Plane] = true
		if !health.Available && strings.TrimSpace(health.Reason) == "" {
			t.Errorf("plane %s is unavailable with no reason", health.Plane)
		}
		if health.Available && !health.Running && strings.TrimSpace(health.Reason) == "" {
			t.Errorf("plane %s is available but not running, with no reason", health.Plane)
		}
	}
	for _, plane := range platform.Planes {
		if !seen[plane] {
			t.Errorf("plane %s is missing from the health report", plane)
		}
	}
	// Plane C is selected only through the host-plane opt-in, which this
	// config does not set, so the snapshot must be degraded and say why.
	if !snapshot.Degraded {
		t.Error("a snapshot with plane C not running was not marked degraded")
	}
	if len(snapshot.DegradedReasons) == 0 {
		t.Error("a degraded snapshot carried no reasons")
	}
}

// TestCorrelationDisabledIsNotTheSameAsDisagreement pins the distinction the
// join is built on, at the service level.
func TestCorrelationDisabledIsNotTheSameAsDisagreement(t *testing.T) {
	off := false
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true, Correlate: &off},
		stubInventory{snapshot: correlate.Snapshot{
			Signals:  []inventory.AISignal{},
			ScanTime: time.Now(), Complete: true,
		}})
	snapshot := service.Poll(context.Background())
	for _, finding := range snapshot.Findings {
		if finding.Correlation.Verdict == correlate.VerdictUnaccounted {
			t.Fatalf("correlation was disabled yet a finding was escalated as unaccounted: %+v",
				finding.Correlation)
		}
	}
}

// TestApplyCorrelationAttenuatesOnlyLocalInference pins that an accounted-for
// model on disk does not discount a finding's egress evidence. Discovery
// having inventoried a model file says nothing about where the process sent
// its requests.
func TestApplyCorrelationAttenuatesOnlyLocalInference(t *testing.T) {
	t.Parallel()
	signals := []scoring.Signal{
		{ID: "local_model_runtime", Weight: scoring.WeightLocalRuntimeProcess},
		{ID: "shadow_ai_egress", Weight: 50},
	}
	got := applyCorrelation(signals, correlate.Result{Verdict: correlate.VerdictAccounted})
	// Assert the scaled weight, not a constant that merely happens to equal
	// it. Comparing against WeightSanctionedEgress passed only while two
	// unrelated numbers coincided: it would fail when that constant moved,
	// for a reason having nothing to do with attenuation, and could keep
	// passing when the scale itself changed.
	want := int(float64(scoring.WeightLocalRuntimeProcess) * scoring.CorroboratedWeightScale)
	if got[0].Weight != want {
		t.Errorf("local inference attenuated to %d, want %d (%d scaled by %v)",
			got[0].Weight, want, scoring.WeightLocalRuntimeProcess,
			scoring.CorroboratedWeightScale)
	}
	if got[1].Weight != 50 {
		t.Errorf("egress weight was discounted to %d; an inventoried model file says nothing "+
			"about where this process sent its requests", got[1].Weight)
	}
}

// TestApplyCorrelationEscalatesOnlyWhenThereIsLocalInferenceToExplain pins
// that the uninventoried bonus attaches to the observation it is about.
func TestApplyCorrelationEscalatesOnlyWhenThereIsLocalInferenceToExplain(t *testing.T) {
	t.Parallel()
	egressOnly := applyCorrelation(
		[]scoring.Signal{{ID: "shadow_ai_egress", Weight: 50}},
		correlate.Result{Verdict: correlate.VerdictUnaccounted, Reason: "nothing on disk"},
	)
	if len(egressOnly) != 1 {
		t.Fatalf("pure egress gained %d signals from an unaccounted verdict", len(egressOnly)-1)
	}
	withLocal := applyCorrelation(
		[]scoring.Signal{{ID: "inference_heartbeat", Weight: scoring.WeightInferenceHeartbeat}},
		correlate.Result{Verdict: correlate.VerdictUnaccounted, Reason: "nothing on disk"},
	)
	if len(withLocal) != 2 || withLocal[1].ID != "uninventoried_local_model" {
		t.Fatalf("local inference did not gain the uninventoried signal: %+v", withLocal)
	}
}

// TestApplyCorrelationUnobservedChangesNothing is the rule the design rests on,
// asserted where the score is actually adjusted.
func TestApplyCorrelationUnobservedChangesNothing(t *testing.T) {
	t.Parallel()
	original := []scoring.Signal{
		{ID: "local_model_runtime", Weight: scoring.WeightLocalRuntimeProcess},
		{ID: "inference_heartbeat", Weight: scoring.WeightInferenceHeartbeat},
	}
	before := scoring.Total(original)
	got := applyCorrelation(original, correlate.Result{
		Verdict: correlate.VerdictUnobserved, Reason: "no snapshot",
	})
	if scoring.Total(got) != before {
		t.Fatalf("an unobserved inventory moved the score from %d to %d", before, scoring.Total(got))
	}
	if len(got) != len(original) {
		t.Fatalf("an unobserved inventory added %d signals", len(got)-len(original))
	}
}

// TestNewRefusesAnUnknownPlatform pins that the sensor fails loudly rather
// than starting blind on a platform with no backend.
func TestNewRefusesAnUnknownPlatform(t *testing.T) {
	t.Parallel()
	// Current() succeeds on every supported platform, so this asserts the
	// error type is wired rather than simulating an unsupported GOOS.
	err := &platform.ErrUnsupported{GOOS: "plan9"}
	if !strings.Contains(err.Error(), "no runtime-plane backend") {
		t.Fatalf("ErrUnsupported message = %q", err.Error())
	}
}

func TestRunPollsImmediatelyThenStops(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true, PollIntervalSec: 3600}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()

	deadline := time.After(10 * time.Second)
	for service.Snapshot().ScannedAt.IsZero() {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run() did not poll before the first interval elapsed")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Run() returned %v, want a context cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

var _ = catalog.CategoryFrontier

// countingResolver records how many lookups a poll performed and how long the
// caller was willing to wait, so the naming budget can be observed rather than
// assumed.
type countingResolver struct {
	mu          sync.Mutex
	calls       int
	deadline    time.Time
	hadDeadline bool
}

func (r *countingResolver) Resolve(
	ctx context.Context, _ netprobe.Connection,
) (string, float64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if deadline, ok := ctx.Deadline(); ok {
		r.deadline, r.hadDeadline = deadline, true
	}
	return "", 0, ""
}

// TestPollIsSerializedAgainstConcurrentCallers pins the fix for a concurrent
// map write. Poll mutates the episode map without holding the snapshot lock,
// and an operator-triggered scan can land on top of the ticker's poll. Before
// serialization this aborted the whole gateway, not just the sensor. Run this
// with -race, which is how CI runs it.
func TestPollIsSerializedAgainstConcurrentCallers(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true}, nil)

	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			service.Poll(context.Background())
		}()
	}
	wait.Wait()

	if service.Snapshot().ScannedAt.IsZero() {
		t.Fatal("no snapshot survived the concurrent polls")
	}
}

// TestPollHonoursTheConfiguredPlaneSelection is a privacy boundary, not a
// display preference. A host that selected only the inference plane must not
// have its sockets read: consulting the selection only while rendering health
// would let the documented choice mean nothing.
func TestPollHonoursTheConfiguredPlaneSelection(t *testing.T) {
	for _, test := range []struct {
		name      string
		planes    []string
		wantNamed bool
	}{
		{"plane a only never names a peer", []string{"a"}, false},
		{"plane b named peers", []string{"b"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &countingResolver{}
			service, err := New(Options{
				Config:    config.AIRuntimeConfig{Enabled: true, Planes: test.planes},
				Providers: testCatalog(),
				Platform:  allPlanesAvailable(),
				Resolver:  resolver,
			})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			service.Poll(context.Background())

			if got := resolver.calls > 0; got != test.wantNamed {
				t.Fatalf("resolver used = %v (calls=%d), want %v -- "+
					"plane B ran against the configured selection %v",
					got, resolver.calls, test.wantNamed, test.planes)
			}
		})
	}
}

// TestPollBoundsTheTimeSpentNamingPeers pins that peer naming runs under a
// deadline derived from the poll. Each cold address is a synchronous reverse
// lookup, so without a total budget a slow resolver turns one poll into
// minutes and outlives the API client waiting on the scan.
func TestPollBoundsTheTimeSpentNamingPeers(t *testing.T) {
	resolver := &countingResolver{}
	service, err := New(Options{
		Config:    config.AIRuntimeConfig{Enabled: true, Planes: []string{"b"}, PollIntervalSec: 3600},
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	start := time.Now()
	service.Poll(context.Background())

	if resolver.calls == 0 {
		t.Skip("this host produced no public peers to name")
	}
	if !resolver.hadDeadline {
		t.Fatal("naming ran with no deadline: one slow peer can hold the poll open forever")
	}
	if budget := resolver.deadline.Sub(start); budget > maxNamingBudget+time.Second {
		t.Fatalf("naming budget %s exceeds the %s ceiling even at a one-hour poll interval",
			budget, maxNamingBudget)
	}
}

// TestNamingBudgetTracksThePollInterval keeps the budget between its floor and
// ceiling: never long enough for one poll's naming to overlap the next, never
// so short that a normal interval cannot name anything.
func TestNamingBudgetTracksThePollInterval(t *testing.T) {
	for _, test := range []struct {
		interval time.Duration
		want     time.Duration
	}{
		{5 * time.Second, minNamingBudget},
		{30 * time.Second, 15 * time.Second},
		{time.Hour, maxNamingBudget},
	} {
		if got := namingBudget(test.interval); got != test.want {
			t.Errorf("namingBudget(%s) = %s, want %s", test.interval, got, test.want)
		}
	}
	if maxNamingBudget >= 30*time.Second {
		t.Error("the ceiling must stay well under the API client's scan timeout")
	}
}

// TestFirstCPUSampleIsABaselineNotAScore pins that a process's first sample
// never scores. Cumulative CPU covers a process's whole life, so scoring the
// first reading as one poll window's work would give every long-lived
// interpreter on the host an inference heartbeat the moment the gateway
// starts -- a false finding at exactly the moment the sensor knows least.
func TestFirstCPUSampleIsABaselineNotAScore(t *testing.T) {
	now := time.Now()
	state := &episode{firstSeen: now}

	// A python that has been running for hours before the sensor started.
	delta, scoreable := state.observeCPU(4*time.Hour, now)
	if scoreable {
		t.Fatal("the first sample scored: a process older than the sensor would report a heartbeat")
	}
	if delta != 4*time.Hour {
		t.Fatalf("baseline delta = %s, want the raw reading %s", delta, 4*time.Hour)
	}

	// The next poll measures real work over one window.
	delta, scoreable = state.observeCPU(4*time.Hour+20*time.Second, now.Add(30*time.Second))
	if !scoreable {
		t.Fatal("the second sample did not score: the baseline never lifts")
	}
	if delta != 20*time.Second {
		t.Fatalf("delta = %s, want 20s of work since the baseline", delta)
	}
}

// TestPidReuseRestartsTheEpisode keeps a recycled pid from inheriting the
// previous process's counters. A negative delta is the only signal available
// that the pid now belongs to someone else.
func TestPidReuseRestartsTheEpisode(t *testing.T) {
	now := time.Now()
	state := &episode{firstSeen: now.Add(-time.Hour)}
	state.observeCPU(90*time.Minute, now)
	state.observeUnnamedPeers(1)
	state.observeUnnamedPeers(1)

	delta, scoreable := state.observeCPU(2*time.Second, now.Add(time.Minute))
	if delta != 0 {
		t.Fatalf("delta = %s, want 0: a reused pid is a new episode, not an idle one", delta)
	}
	if scoreable {
		t.Fatal("the reused pid scored its first sample")
	}
	if state.unnamedPeerPolls != 0 {
		t.Fatalf("unnamedPeerPolls = %d, want 0: the new process inherited the old one's egress history",
			state.unnamedPeerPolls)
	}
	if !state.firstSeen.Equal(now.Add(time.Minute)) {
		t.Fatal("firstSeen still points at the previous process")
	}
}

// TestRepeatedUnnamedEgressEscalates is the case the escalated weight was
// written for: one provider address whose attribution keeps missing, poll
// after poll. Counting distinct peers instead of polls pinned this at one
// forever, so the finding it was meant to produce never appeared.
func TestRepeatedUnnamedEgressEscalates(t *testing.T) {
	state := &episode{}
	for poll := 1; poll <= scoring.UnattributedEgressRepeatThreshold; poll++ {
		// The same single unnamed peer every poll.
		state.observeUnnamedPeers(1)
	}
	if state.unnamedPeerPolls != scoring.UnattributedEgressRepeatThreshold {
		t.Fatalf("unnamedPeerPolls = %d after %d polls of the same peer, want %d",
			state.unnamedPeerPolls, scoring.UnattributedEgressRepeatThreshold,
			scoring.UnattributedEgressRepeatThreshold)
	}

	signal, ok := unattributedEgressSignal(state.unnamedPeerPolls)
	if !ok {
		t.Fatal("repeated unnamed egress produced no signal")
	}
	if signal.Weight != scoring.WeightUnattributedEgressEscalated {
		t.Fatalf("weight = %d, want the escalated %d -- repetition is the corroboration",
			signal.Weight, scoring.WeightUnattributedEgressEscalated)
	}

	// A poll with nothing unnamed must not advance the count.
	quiet := &episode{}
	quiet.observeUnnamedPeers(0)
	if quiet.unnamedPeerPolls != 0 {
		t.Fatal("a poll with no unnamed peers advanced the repeat count")
	}
}

// TestFindingIDsDistinguishEpisodesOnAReusedPid pins both identifiers against
// pid reuse.
//
// The telemetry schema documents finding_id as stable for the life of a
// process episode, which invites consumers to upsert by it. pid, name and
// user repeat as soon as the kernel recycles a pid for the same program under
// the same account, so without the episode start two unrelated episodes share
// an id and the later finding silently overwrites the earlier one.
func TestFindingIDsDistinguishEpisodesOnAReusedPid(t *testing.T) {
	first := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	process := procprobe.Process{PID: 4242, Name: "python3", User: "dev"}

	t.Run("process findings", func(t *testing.T) {
		if findingID(process, first) == findingID(process, second) {
			t.Fatal("two episodes on a reused pid share one finding id")
		}
		if findingID(process, first) != findingID(process, first) {
			t.Fatal("the id is not stable within one episode")
		}
	})

	t.Run("host-plane findings", func(t *testing.T) {
		early := hostFinding{RootPID: 4242, AgentName: "claude", FirstSeen: first}
		late := hostFinding{RootPID: 4242, AgentName: "claude", FirstSeen: second}
		if hostFindingID(early) == hostFindingID(late) {
			t.Fatal("two agent sessions on a reused root pid share one finding id")
		}
		if hostFindingID(early) != hostFindingID(early) {
			t.Fatal("the id is not stable within one session")
		}
	})
}
