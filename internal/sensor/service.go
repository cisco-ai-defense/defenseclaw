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
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// minNamingBudget keeps a short poll interval from starving reverse DNS
	// entirely; maxNamingBudget keeps a long one from letting a stalled
	// resolver hold a poll open past the API client's scan timeout.
	minNamingBudget = 5 * time.Second
	maxNamingBudget = 20 * time.Second
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
	//
	// The context carries the poll's remaining naming budget. A resolver that
	// blocks past it must give up and report the peer unnamed: an unnamed peer
	// is a recorded observation, whereas a poll that never returns is a dead
	// sensor that still looks alive.
	Resolve(ctx context.Context, connection netprobe.Connection) (hostname string, confidence float64, source string)
}

// Options configure a Service.
type Options struct {
	Config    config.AIRuntimeConfig
	Inventory InventoryProvider
	Resolver  Resolver
	Providers *catalog.Catalog
	Platform  platform.Platform
	// HomeDirs are the user homes whose credential and agent-config paths the
	// host plane watches. Empty means the daemon's own $HOME, which under
	// launchd or a Windows service is not a real user's -- the caller should
	// pass AIDiscoveryConfig.HomeDirs, which managed deployments already
	// populate from the same eligible-users enumeration that renders
	// targets.yaml.
	HomeDirs []string
	// NewPlaneSource builds the Plane C acquisition. Injectable so the host
	// plane is testable without a kernel event source. When set it overrides
	// whatever the Acquirer would have supplied.
	NewPlaneSource func(homeDirs []string) plane.Source
	// Acquirer is where the privileged reads come from: directly from this
	// process, or brokered by a helper that holds the privilege the gateway
	// deliberately does not. Defaults to reading directly.
	Acquirer acquire.Acquirer
	// Now is injectable so the poll loop is testable without sleeping.
	Now func() time.Time
}

// Service runs the runtime planes.
type Service struct {
	options Options

	mu                sync.RWMutex
	snapshot          Snapshot
	hostPlaneStartErr string
	dnsCaptureErr     string

	tracker   *agentchain.Tracker
	hostPlane *hostPlane
	dnsCache  *dnscapture.Cache
	dnsCap    dnscapture.Capturer
	// pollMu serializes Poll. The ticker and an operator-triggered scan can
	// arrive together, and Poll mutates episodes and the lineage tracker
	// without holding mu -- concurrent polls would race the map and can
	// abort the gateway outright with a concurrent map write.
	pollMu sync.Mutex

	// planeAOn and planeBOn record the configured selection. Consulting it
	// only while rendering health would let a host configured for one plane
	// quietly run all of them, which is a privacy boundary, not a display
	// detail.
	planeAOn bool
	planeBOn bool

	// episodes carries per-process state between polls: the previous CPU
	// reading, first-seen time, and how many distinct unnamed public peers the
	// process has reached. Escalation depends on that history, so it cannot be
	// derived from a single poll.
	episodes map[int]*episode
}

type episode struct {
	firstSeen time.Time
	lastCPU   time.Duration
	lastSeen  time.Time
	// baselined is false until one poll has recorded lastCPU. A process's
	// first sample carries the CPU it burned over its whole lifetime, not
	// over one poll window, so scoring it would hand any long-lived but
	// currently idle interpreter an inference heartbeat the moment the
	// gateway starts. The first sample sets the baseline and scores nothing.
	baselined bool
	// unnamedPeerPolls counts polls in which this process showed at least one
	// unnamed public peer -- not the number of distinct such peers. The
	// escalation exists for a provider connection whose attribution keeps
	// missing poll after poll; counting distinct peers would leave exactly
	// that case pinned at one forever.
	unnamedPeerPolls int
}

// observeCPU folds one CPU sample into the episode and reports the delta plus
// whether it is safe to score.
//
// The first sample of an episode is a baseline and nothing else. A process's
// cumulative CPU time covers its whole life, so treating the first reading as
// one poll window's work would hand every long-lived interpreter on the host
// an inference heartbeat the instant the gateway starts -- the machine looks
// busiest exactly when the sensor knows least about it.
//
// A negative delta means the pid was reused, which restarts the episode for
// the same reason: the counter belongs to a different process now.
func (e *episode) observeCPU(cpuTime time.Duration, now time.Time) (time.Duration, bool) {
	delta := cpuTime - e.lastCPU
	reused := delta < 0
	if reused {
		delta = 0
		e.firstSeen = now
		e.baselined = false
		e.unnamedPeerPolls = 0
	}
	scoreable := e.baselined
	e.lastCPU = cpuTime
	e.lastSeen = now
	e.baselined = true
	return delta, scoreable
}

// observeUnnamedPeers records that this poll saw unnamed public peers for the
// process, counting polls rather than distinct addresses.
//
// The escalation exists for a provider connection whose attribution keeps
// missing: the same address, poll after poll. Counting distinct peers would
// pin exactly that case at one forever and never reach the threshold, which
// is the case the weight was written for.
func (e *episode) observeUnnamedPeers(count int) {
	if count > 0 {
		e.unnamedPeerPolls++
	}
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
	if options.Acquirer == nil {
		options.Acquirer = acquire.NewLocal()
	}
	var (
		dnsCache *dnscapture.Cache
		dnsCap   dnscapture.Capturer
	)
	if options.Config.DNSCapture {
		dnsCache = dnscapture.NewCache()
		dnsCap = options.Acquirer.DNSCapturer()
	}
	if options.Resolver == nil {
		reverse := NewReverseResolver(options.Providers)
		if dnsCache != nil {
			options.Resolver = NewCapturingResolver(dnsCache, reverse)
		} else {
			options.Resolver = reverse
		}
	}
	if options.NewPlaneSource == nil {
		options.NewPlaneSource = options.Acquirer.PlaneSource
	}
	service := &Service{
		options:  options,
		tracker:  agentchain.NewTracker(),
		episodes: make(map[int]*episode),
		dnsCache: dnsCache,
		dnsCap:   dnsCap,
	}
	for _, selected := range options.Config.EffectivePlanes() {
		switch selected {
		case "a":
			service.planeAOn = true
		case "b":
			service.planeBOn = true
		}
	}
	for _, selected := range options.Config.EffectivePlanes() {
		if selected != "c" {
			continue
		}
		service.hostPlane = newHostPlane(
			options.NewPlaneSource(options.HomeDirs),
			service.tracker,
			tactics.Indicators(),
			options.Config.EffectiveChainWindow(),
			scoring.KillChainMinStages,
		)
	}
	return service, nil
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
	if s.dnsCap != nil {
		// A capture that cannot start is degraded coverage, not fatal: the
		// reverse resolver still names peers, less confidently, and the reason
		// reaches the snapshot instead of the plane going quiet.
		if err := s.dnsCap.Start(ctx, s.dnsCache); err != nil {
			s.mu.Lock()
			s.dnsCaptureErr = err.Error()
			s.mu.Unlock()
		}
		defer func() { _ = s.dnsCap.Close() }()
	}
	if s.hostPlane != nil {
		// A host plane that cannot start is degraded coverage, not a fatal
		// error: planes A and B still work, and the reason reaches the
		// snapshot so an operator sees it rather than an empty row.
		if err := s.hostPlane.start(ctx); err != nil {
			s.mu.Lock()
			s.hostPlaneStartErr = err.Error()
			s.mu.Unlock()
		}
		defer func() { _ = s.hostPlane.close() }()
	}
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
	s.pollMu.Lock()
	defer s.pollMu.Unlock()

	now := s.options.Now()
	interval := s.options.Config.EffectivePollInterval()

	// Naming peers is the only unbounded work in a poll: each cold address is
	// a synchronous reverse lookup, so a slow resolver and a host with many
	// new peers turn one poll into minutes. Cap the whole naming phase and
	// let the poll's own cancellation reach it -- an unnamed peer is still a
	// recorded observation, a poll that never returns is not.
	nameCtx, cancelNaming := context.WithTimeout(ctx, namingBudget(interval))
	defer cancelNaming()

	processes, processSkipped, processErr := s.options.Acquirer.Processes(ctx)
	connections, unattributed, connectionErr := s.options.Acquirer.Connections(ctx)

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
		cpuDelta, scoreCPU := state.observeCPU(process.CPUTime, now)

		var signals []scoring.Signal
		if s.planeAOn && scoreCPU {
			signals = append(signals, planeA(process, cpuDelta, interval)...)
		}

		var result planeBResult
		if s.planeBOn {
			result = planeB(byPID[process.PID], process.Name, s.options.Providers,
				func(connection netprobe.Connection) (string, float64, string) {
					return s.options.Resolver.Resolve(nameCtx, connection)
				}, sanctioned)
			signals = append(signals, result.signals...)

			// planeB already resolved every public peer and counted the ones
			// it could not name. Walking them again here resolved each a
			// second time and, worse, duplicated the rule for what counts as
			// unnamed in two places that could drift apart.
			state.observeUnnamedPeers(result.unattributedPublicPeers)
			if len(signals) > 0 || result.unattributedPublicPeers > 0 {
				if signal, ok := unattributedEgressSignal(state.unnamedPeerPolls); ok &&
					isScriptable(process.Name) {
					signals = append(signals, signal)
				}
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
			FindingID:   findingID(process, state.firstSeen),
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
	findings = append(findings, s.hostPlaneFindings(now, minRisk, correlator)...)
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
	if s.hostPlane != nil {
		classified, gated, _, _ := s.hostPlane.stats()
		snapshot.HostPlaneObservations = classified
		snapshot.HostPlaneGated = gated
	}
	if processErr != nil {
		snapshot.DegradedReasons = append(snapshot.DegradedReasons,
			"process table unreadable: "+processErr.Error())
	}
	if connectionErr != nil {
		snapshot.DegradedReasons = append(snapshot.DegradedReasons,
			"connection table unreadable: "+connectionErr.Error())
	}
	snapshot.DegradedReasons = append(snapshot.DegradedReasons, degradedReasonsFor(snapshot)...)
	snapshot.Degraded = len(snapshot.DegradedReasons) > 0

	s.mu.Lock()
	s.snapshot = snapshot
	s.mu.Unlock()
	return snapshot
}

// degradedReasonsFor renders one operator-facing line per plane that is not
// delivering everything it could.
//
// Three states are distinguished because they need three different fixes:
// unavailable is a platform or grant problem, stopped is a runtime failure,
// and partially covered is a privilege gap that leaves the plane useful but
// incomplete.
func degradedReasonsFor(snapshot Snapshot) []string {
	reasons := make([]string, 0, len(snapshot.Planes))
	for _, health := range snapshot.Planes {
		switch {
		case !health.Available:
			reasons = append(reasons, health.Plane.Name()+" unavailable: "+planeIdleReason(health))
		case !health.Running:
			reasons = append(reasons,
				health.Plane.Name()+" available but not running: "+planeIdleReason(health))
		case health.Reason != "":
			// Running with a stated limitation is partial coverage, not full.
			// A plane delivering process events but not file events is missing
			// a whole tactic class, and a snapshot that called that complete
			// would let an operator read reduced coverage as a clean host.
			reasons = append(reasons, health.Plane.Name()+" partially covered: "+health.Reason)
		}
	}
	return reasons
}

// namingBudget caps how long one poll may spend naming peers.
//
// Half the poll interval, so naming can never make polls overlap, floored so
// a short interval still gets a usable window and ceilinged well under the
// API client's scan timeout -- an operator-triggered scan has to answer.
func namingBudget(interval time.Duration) time.Duration {
	budget := interval / 2
	if budget < minNamingBudget {
		budget = minNamingBudget
	}
	if budget > maxNamingBudget {
		budget = maxNamingBudget
	}
	return budget
}

func (s *Service) episodeFor(pid int, now time.Time) *episode {
	state, ok := s.episodes[pid]
	if !ok {
		state = &episode{firstSeen: now}
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
			var limits []string
			if !s.options.Platform.WideCoverage() {
				// Without machine-wide privilege the connection table is not
				// the host's, it is this process's own. On macOS that is the
				// dangerous shape: unprivileged lsof simply omits other
				// users' sockets rather than listing them unattributed, so
				// the unattributed count stays near zero and a blinded plane
				// is indistinguishable from a host with no egress. Coverage
				// is reported, never implied.
				limits = append(limits,
					"egress attribution is limited to this process's own sockets; "+
						"run the gateway elevated for machine-wide coverage")
			}
			if reason := s.dnsCaptureStatus(); reason != "" {
				// The plane still runs on reverse DNS; naming is just less
				// direct, and saying so beats silently downgrading confidence.
				limits = append(limits, reason)
			}
			if len(limits) > 0 {
				entry.Reason = strings.Join(limits, "; ")
			}
		case platform.PlaneC:
			entry.Running, entry.Mechanism, entry.Reason = s.hostPlaneHealth(capability)
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

// dnsCaptureStatus reports what DNS capture is or is not contributing.
//
// Returns "" when capture is off and was never asked for, because an operator
// who did not enable it does not need to be told it is not running.
func (s *Service) dnsCaptureStatus() string {
	if !s.options.Config.DNSCapture {
		return ""
	}
	s.mu.RLock()
	captureErr := s.dnsCaptureErr
	s.mu.RUnlock()
	if captureErr != "" {
		return "dns capture unavailable, peers named by reverse DNS only: " + captureErr
	}
	if s.dnsCache != nil && s.dnsCache.Observed() == 0 {
		return "dns capture running but has observed no answers yet"
	}
	return ""
}

// hostPlaneHealth reports Plane C from the running source rather than from the
// platform capability alone.
//
// The capability says what this host could do; this says what it is actually
// doing, and the two differ in exactly the cases worth reporting -- a source
// that failed to start, or one running with only part of its coverage.
func (s *Service) hostPlaneHealth(capability platform.Capability) (running bool, mechanism, reason string) {
	if s.hostPlane == nil {
		return false, capability.Mechanism, "plane c is not selected in ai_discovery.runtime.planes"
	}
	s.mu.RLock()
	startErr := s.hostPlaneStartErr
	s.mu.RUnlock()
	if startErr != "" {
		return false, capability.Mechanism, startErr
	}
	_, _, up, coverage := s.hostPlane.stats()
	if !up {
		return false, capability.Mechanism, "the kernel event source stopped delivering"
	}
	// Partial coverage is running, with the gap named. Reporting it as fully
	// up would hide a whole missing event class; reporting it as down would
	// discard the half that works.
	if !coverage.Complete() {
		return true, coverage.Mechanism, strings.Join(coverage.Limitations, "; ")
	}
	return true, coverage.Mechanism, ""
}

// hostPlaneFindings scores the accumulated agent sessions.
//
// A host-plane finding is per agent session rather than per process: the whole
// point is that five separate per-process findings for one credential-read-to-
// exfiltration sequence would be five alerts nobody joins up.
func (s *Service) hostPlaneFindings(
	now time.Time, minRisk int, correlator *correlate.Correlator,
) []Finding {
	if s.hostPlane == nil {
		return nil
	}
	harvested := s.hostPlane.harvest(now, minRisk)
	findings := make([]Finding, 0, len(harvested))
	for _, session := range harvested {
		correlation := correlator.Connector(correlate.Observation{
			PID: session.RootPID, AgentName: session.AgentName, ExeName: session.AgentName,
		})
		findings = append(findings, Finding{
			FindingID:   hostFindingID(session),
			PID:         session.RootPID,
			Process:     session.AgentName,
			AgentName:   session.AgentName,
			Score:       session.Score,
			Severity:    scoring.SeverityFor(session.Score),
			Signals:     session.Signals,
			Correlation: correlation,
			FirstSeen:   session.FirstSeen,
			LastSeen:    session.LastSeen,
		})
	}
	return findings
}

// hostFindingID is stable for an agent session so repeated emissions update
// rather than accumulate.
func hostFindingID(session hostFinding) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("host|%d|%s|%d",
		session.RootPID, session.AgentName, session.FirstSeen.UnixNano())))
	return "chain-" + hex.EncodeToString(digest[:8])
}

// correlateFinding picks the join most specific to what was observed.
func correlateFinding(
	correlator *correlate.Correlator,
	process procprobe.Process,
	result planeBResult,
	tracker *agentchain.Tracker,
) correlate.Result {
	observation := correlate.Observation{
		PID: process.PID, ExeName: process.Name, StartedAt: process.StartedAt,
	}
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

// findingID is stable for a process episode so repeated emissions update
// rather than accumulate.
//
// The episode start is part of the digest, and has to be: pid, name and user
// alone all repeat after the kernel recycles a pid for the same program under
// the same account, which on a busy host is ordinary rather than exotic. Two
// distinct episodes then share an id, and a consumer that upserts by
// finding_id -- which the telemetry schema says it may, because the id is
// documented as stable for the life of an episode -- overwrites the earlier
// finding with the later one instead of recording both.
//
// The score is deliberately not an input: including it would make every
// re-scoring of the same episode a new finding, which is the opposite
// failure.
func findingID(process procprobe.Process, episodeStart time.Time) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%d",
		process.PID, process.Name, process.User, episodeStart.UnixNano())))
	return "run-" + hex.EncodeToString(digest[:8])
}

// SortedDegradedReasons is a stable rendering of the degradation list.
func SortedDegradedReasons(snapshot Snapshot) []string {
	reasons := append([]string(nil), snapshot.DegradedReasons...)
	sort.Strings(reasons)
	return reasons
}
