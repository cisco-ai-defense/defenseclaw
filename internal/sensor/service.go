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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// InventoryProvider supplies the discovery snapshot the join reads.
//
// An interface rather than a direct dependency on the scanner so the service
// can be exercised without one, and so a snapshot that is simply not available
// yet is expressible -- which is the case the join must treat as unobserved.
type InventoryProvider interface {
	CorrelationSnapshot() correlate.Snapshot
}

// Resolver names an egress peer.
type Resolver interface {
	// Resolve returns the hostname for a connection's peer, how confident the
	// naming is, and which source produced it. An empty hostname means the
	// peer could not be named, which is a counted observation rather than a
	// failure.
	Resolve(connection netprobe.Connection) (hostname string, confidence float64, source string)
}

// Options configure a Service.
type Options struct {
	Config    config.AIRuntimeConfig
	Inventory InventoryProvider
	Resolver  Resolver
	Providers *catalog.Catalog
	Platform  platform.Platform
	// Now is injectable so the poll loop is testable without sleeping.
	Now func() time.Time
}

// Service runs the runtime planes.
type Service struct {
	options Options

	mu       sync.RWMutex
	snapshot Snapshot

	tracker *agentchain.Tracker
	// episodes carries per-process state between polls: the previous CPU
	// reading, first-seen time, and how many distinct unnamed public peers the
	// process has reached. Escalation depends on that history, so it cannot be
	// derived from a single poll.
	episodes map[int]*episode
}

type episode struct {
	firstSeen        time.Time
	lastCPU          time.Duration
	lastSeen         time.Time
	unnamedPeerCount int
	unnamedPeers     map[string]bool
}

// New builds a service. It fails rather than defaulting when the host has no
// platform backend, because a detector that starts on an unknown platform and
// reports nothing is indistinguishable from one watching a quiet host.
func New(options Options) (*Service, error) {
	if options.Platform == nil {
		host, err := platform.Current()
		if err != nil {
			return nil, err
		}
		options.Platform = host
	}
	if options.Providers == nil {
		providers, err := catalog.Shared()
		if err != nil {
			return nil, fmt.Errorf("sensor: load provider catalog: %w", err)
		}
		options.Providers = providers
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Resolver == nil {
		options.Resolver = NewReverseResolver(options.Providers)
	}
	return &Service{
		options:  options,
		tracker:  agentchain.NewTracker(),
		episodes: make(map[int]*episode),
	}, nil
}

// Snapshot returns the most recent poll result.
func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

// Run polls until the context is cancelled.
//
// An error from one poll is recorded in the snapshot and the loop continues. A
// sensor that exits on a transient read failure would go silent, and silence is
// the one thing this subsystem must never produce without saying so.
func (s *Service) Run(ctx context.Context) error {
	interval := s.options.Config.EffectivePollInterval()
	// Poll once immediately so a freshly enabled sensor has a snapshot before
	// the first interval elapses, rather than reporting "no data" for a minute.
	s.Poll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.Poll(ctx)
		}
	}
}

// Poll runs one sampling cycle and replaces the snapshot.
func (s *Service) Poll(ctx context.Context) Snapshot {
	now := s.options.Now()
	interval := s.options.Config.EffectivePollInterval()

	processes, processSkipped, processErr := procprobe.Snapshot()
	connections, unattributed, connectionErr := netprobe.Snapshot()

	byPID := make(map[int][]netprobe.Connection, len(processes))
	for _, connection := range connections {
		if connection.PID > 0 {
			byPID[connection.PID] = append(byPID[connection.PID], connection)
		}
	}

	rows := make([]agentchain.ProcessRow, 0, len(processes))
	for _, process := range processes {
		rows = append(rows, agentchain.ProcessRow{
			PID: process.PID, PPID: process.PPID,
			Name: process.Name, Cmdline: process.Cmdline,
		})
	}
	s.tracker.ObserveProcessTable(rows)
	s.tracker.Reap()

	inventorySnapshot := correlate.Snapshot{}
	if s.options.Config.CorrelationEnabled() && s.options.Inventory != nil {
		inventorySnapshot = s.options.Inventory.CorrelationSnapshot()
	}
	correlator := correlate.New(inventorySnapshot)

	sanctioned := make(map[string]bool, len(s.options.Config.SanctionedEndpoints))
	for _, endpoint := range s.options.Config.SanctionedEndpoints {
		if trimmed := strings.ToLower(strings.TrimSpace(endpoint)); trimmed != "" {
			sanctioned[trimmed] = true
		}
	}

	minRisk := s.options.Config.EffectiveMinRisk()
	findings := make([]Finding, 0, 8)
	live := make(map[int]bool, len(processes))

	for _, process := range processes {
		live[process.PID] = true
		state := s.episodeFor(process.PID, now)
		cpuDelta := process.CPUTime - state.lastCPU
		if cpuDelta < 0 {
			// A pid was reused. Treat it as a new episode rather than as a
			// negative delta, which would otherwise read as an idle process.
			cpuDelta = 0
			state.firstSeen = now
		}
		state.lastCPU = process.CPUTime
		state.lastSeen = now

		signals := planeA(process, cpuDelta, interval)
		result := planeB(byPID[process.PID], s.options.Providers,
			s.options.Resolver.Resolve, sanctioned)
		signals = append(signals, result.signals...)

		for peer := range peersOf(byPID[process.PID], s.options.Resolver) {
			if !state.unnamedPeers[peer] {
				state.unnamedPeers[peer] = true
				state.unnamedPeerCount++
			}
		}
		if len(signals) > 0 || result.unattributedPublicPeers > 0 {
			if signal, ok := unattributedEgressSignal(state.unnamedPeerCount); ok &&
				isScriptable(process.Name) {
				signals = append(signals, signal)
			}
		}
		if len(signals) == 0 {
			continue
		}

		correlation := correlateFinding(correlator, process, result, s.tracker)
		signals = applyCorrelation(signals, correlation)

		score := scoring.Total(signals)
		if score < minRisk {
			continue
		}
		agentName := ""
		if attribution, ok := s.tracker.Attribute(process.PID); ok {
			agentName = attribution.AgentName
		}
		findings = append(findings, Finding{
			FindingID:   findingID(process),
			PID:         process.PID,
			Process:     process.Name,
			Cmdline:     process.Cmdline,
			User:        process.User,
			AgentName:   agentName,
			Score:       score,
			Severity:    scoring.SeverityFor(score),
			Signals:     signals,
			Providers:   result.providers,
			Correlation: correlation,
			FirstSeen:   state.firstSeen,
			LastSeen:    now,
		})
	}

	for pid := range s.episodes {
		if !live[pid] {
			delete(s.episodes, pid)
		}
	}
	sortFindings(findings)

	snapshot := Snapshot{
		ScannedAt:               now,
		Findings:                findings,
		Planes:                  s.planeHealth(now, processErr == nil, connectionErr == nil),
		ProcessesObserved:       len(processes),
		ProcessesSkipped:        processSkipped,
		ConnectionsObserved:     len(connections),
		ConnectionsUnattributed: unattributed,
	}
	if processErr != nil {
		snapshot.DegradedReasons = append(snapshot.DegradedReasons,
			"process table unreadable: "+processErr.Error())
	}
	if connectionErr != nil {
		snapshot.DegradedReasons = append(snapshot.DegradedReasons,
			"connection table unreadable: "+connectionErr.Error())
	}
	for _, health := range snapshot.Planes {
		if health.Available && !health.Running {
			snapshot.DegradedReasons = append(snapshot.DegradedReasons,
				health.Plane.Name()+" available but not running: "+planeIdleReason(health))
		}
		if !health.Available {
			snapshot.DegradedReasons = append(snapshot.DegradedReasons,
				health.Plane.Name()+" unavailable: "+health.Reason)
		}
	}
	snapshot.Degraded = len(snapshot.DegradedReasons) > 0

	s.mu.Lock()
	s.snapshot = snapshot
	s.mu.Unlock()
	return snapshot
}

func (s *Service) episodeFor(pid int, now time.Time) *episode {
	state, ok := s.episodes[pid]
	if !ok {
		state = &episode{firstSeen: now, unnamedPeers: make(map[string]bool, 4)}
		s.episodes[pid] = state
	}
	return state
}

// planeHealth reports every plane, always all three.
//
// Emitted on every tick including zero. If health were reported only while a
// plane was working, a subscription that died would leave no trace, and
// absence is the hardest thing to alert on.
func (s *Service) planeHealth(now time.Time, processOK, connectionOK bool) []PlaneHealth {
	capabilities := s.options.Platform.Capabilities()
	selected := make(map[string]bool, 3)
	for _, plane := range s.options.Config.EffectivePlanes() {
		selected[plane] = true
	}
	health := make([]PlaneHealth, 0, len(platform.Planes))
	for _, plane := range platform.Planes {
		capability := capabilities[plane]
		entry := PlaneHealth{
			Plane:     plane,
			Available: capability.Available,
			Mechanism: capability.Mechanism,
			Reason:    capability.Reason,
		}
		if !selected[string(plane)] {
			entry.Running = false
			if entry.Reason == "" {
				entry.Reason = "not selected in ai_discovery.runtime.planes"
			}
			health = append(health, entry)
			continue
		}
		switch plane {
		case platform.PlaneA:
			entry.Running = capability.Available && processOK
		case platform.PlaneB:
			entry.Running = capability.Available && connectionOK
		case platform.PlaneC:
			// Plane C has no acquisition wired yet; it reports available-but-
			// not-running rather than claiming coverage it does not have.
			entry.Running = false
			if entry.Reason == "" {
				entry.Reason = "kernel event acquisition is not started"
			}
		}
		if entry.Running {
			entry.ObservedAt = now
		}
		health = append(health, entry)
	}
	return health
}

// planeIdleReason explains a plane that could run and is not. Falls back to a
// plain statement rather than an empty string, because a degradation entry
// with no reason is the thing this subsystem refuses to emit.
func planeIdleReason(health PlaneHealth) string {
	if reason := strings.TrimSpace(health.Reason); reason != "" {
		return reason
	}
	return "not started"
}

// correlateFinding picks the join most specific to what was observed.
func correlateFinding(
	correlator *correlate.Correlator,
	process procprobe.Process,
	result planeBResult,
	tracker *agentchain.Tracker,
) correlate.Result {
	observation := correlate.Observation{PID: process.PID, ExeName: process.Name}
	if attribution, ok := tracker.Attribute(process.PID); ok {
		observation.AgentName = attribution.AgentName
	}
	if result.localInferenceClient || result.listeningModelPort != "" {
		observation.ModelHint = result.listeningModelPort
		return correlator.LocalModel(observation)
	}
	for _, provider := range result.providers {
		if provider.Category == "sanctioned" {
			continue
		}
		observation.ProviderDomain = provider.Hostname
		return correlator.ProviderDomain(observation)
	}
	return correlator.Connector(observation)
}

// applyCorrelation attenuates or escalates according to the verdict.
//
// Unobserved does neither, and the tag is still attached so the blindness is
// recorded rather than merely not scored.
func applyCorrelation(signals []scoring.Signal, result correlate.Result) []scoring.Signal {
	switch result.Verdict {
	case correlate.VerdictAccounted:
		for index := range signals {
			if !isLocalInferenceSignal(signals[index].ID) {
				continue
			}
			signals[index].Weight = int(float64(signals[index].Weight) * scoring.CorroboratedWeightScale)
		}
	case correlate.VerdictUnaccounted:
		if hasLocalInference(signals) {
			signals = append(signals, scoring.Signal{
				ID:     "uninventoried_local_model",
				Title:  "sustained local inference that discovery cannot account for",
				Detail: result.Reason,
				Weight: scoring.WeightUninventoriedLocalModel,
			})
		}
	}
	return signals
}

func isLocalInferenceSignal(id string) bool {
	switch id {
	case "local_model_runtime", "local_inference_client", "local_model_server_port",
		"inference_heartbeat", "model_resident_memory":
		return true
	}
	return false
}

func hasLocalInference(signals []scoring.Signal) bool {
	for _, signal := range signals {
		if isLocalInferenceSignal(signal.ID) {
			return true
		}
	}
	return false
}

func isScriptable(name string) bool { return scriptableRuntimes[strings.ToLower(name)] }

// peersOf returns the public peers of a process's connections that could not
// be named, keyed by address.
func peersOf(connections []netprobe.Connection, resolver Resolver) map[string]bool {
	peers := make(map[string]bool, len(connections))
	for _, connection := range connections {
		if !connection.Public() {
			continue
		}
		if hostname, _, _ := resolver.Resolve(connection); hostname != "" {
			continue
		}
		peers[connection.RemoteIP.String()] = true
	}
	return peers
}

// findingID is stable for a process episode so repeated emissions update
// rather than accumulate. The start-independent inputs are deliberate: a pid
// alone would collide after reuse, and including the score would make every
// re-scoring a new finding.
func findingID(process procprobe.Process) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", process.PID, process.Name, process.User)))
	return "run-" + hex.EncodeToString(digest[:8])
}

// SortedDegradedReasons is a stable rendering of the degradation list.
func SortedDegradedReasons(snapshot Snapshot) []string {
	reasons := append([]string(nil), snapshot.DegradedReasons...)
	sort.Strings(reasons)
	return reasons
}
