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

package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
)

// aiDiscoveryPartialResult is the summary value the inventory scanner writes
// when a scan could not complete.
const aiDiscoveryPartialResult = "partial"

// aiRuntimeHealthInterval is how often the health record is refreshed while
// the planes run. It is independent of the poll interval so a long poll
// interval does not make the subsystem look stalled.
const aiRuntimeHealthInterval = 10 * time.Second

// aiRuntimeShutdownGrace bounds how long shutdown waits for a poll already in
// flight. Longer than any healthy acquisition, short enough that a stuck one
// does not hold the whole gateway open.
const aiRuntimeShutdownGrace = 15 * time.Second

// discoveryCorrelationSource adapts the continuous discovery service to the
// join's snapshot interface.
//
// It reports staleness and completeness rather than only the signals, because
// "the scanner has not produced a snapshot yet" and "the scanner ran and found
// nothing" are the two readings the join must never confuse.
type discoveryCorrelationSource struct{ sidecar *Sidecar }

// CorrelationSnapshot implements sensor.InventoryProvider.
func (d discoveryCorrelationSource) CorrelationSnapshot() correlate.Snapshot {
	service := d.sidecar.aiDiscoverySnapshot()
	if service == nil {
		// Discovery is disabled or has not started. An empty snapshot with no
		// scan time is exactly the unobserved case, which changes no score in
		// either direction.
		return correlate.Snapshot{}
	}
	report := service.Snapshot()
	// A partial scan hit a traversal budget or a permission error, so it cannot
	// conclude that anything is absent. The join treats that as unobserved
	// rather than as disagreement.
	return correlate.Snapshot{
		Signals:  report.Signals,
		ScanTime: report.Summary.ScannedAt,
		Complete: report.Summary.Result != aiDiscoveryPartialResult,
	}
}

// detachAIRuntime drops the runtime service from both the sidecar and the API
// server, so nothing can reach a stopped set of planes.
//
// Turning the feature off has to remove the capability, not just the label.
// A stale pointer here means POST /runtime/scan still reads argv and sockets
// on a host whose operator disabled exactly that.
func (s *Sidecar) detachAIRuntime() {
	s.aiRuntimeMu.Lock()
	s.aiRuntime = nil
	s.aiRuntimeMu.Unlock()
	s.apiSnapshot().SetAIRuntimeService(nil)
}

// runAIRuntime starts the AI Discovery runtime planes when enabled.
func (s *Sidecar) runAIRuntime(ctx context.Context) error {
	// One snapshot, read twice. currentConfig() reads atomically each call, so
	// taking it again below could hand the sensor the home list of one config
	// and the plane settings of another if a reload lands between the two --
	// and the health details would describe only the first.
	activeConfig := s.currentConfig()
	runtimeConfig := activeConfig.AIDiscovery.Runtime
	if !runtimeConfig.Enabled {
		// Detach before parking. On a hot reload from enabled to disabled the
		// old poll loop stops, but the service pointer would otherwise stay
		// reachable: GET would keep reporting the planes enabled and POST
		// /runtime/scan would keep polling it -- reading argv and sockets
		// after the operator switched the feature off.
		s.detachAIRuntime()
		s.health.SetAIRuntime(StateDisabled, "", nil)
		<-ctx.Done()
		return ctx.Err()
	}

	service, err := sensor.New(sensor.Options{
		Config:    runtimeConfig,
		Inventory: discoveryCorrelationSource{sidecar: s},
		// The same home list the inventory scanner walks. Under launchd or a
		// Windows service the daemon's own $HOME is not a real user's, so the
		// host plane would watch the wrong paths without this; in
		// managed_enterprise the hook-enumerator already populates it from the
		// eligible-users enumeration that renders targets.yaml.
		HomeDirs: activeConfig.AIDiscovery.HomeDirs,
	})
	if err != nil {
		// A platform with no backend is a hard stop rather than a degraded
		// start: a detector that reports nothing on an unknown platform is
		// indistinguishable from one watching a quiet host.
		s.health.SetAIRuntime(StateError, err.Error(), nil)
		return fmt.Errorf("ai runtime: %w", err)
	}
	s.aiRuntimeMu.Lock()
	s.aiRuntime = service
	s.aiRuntimeMu.Unlock()
	// The API server is constructed in its own goroutine and wires whatever
	// services exist at that moment. This one is created here, asynchronously,
	// so it has to push itself in rather than wait to be collected -- otherwise
	// the endpoint reports the planes disabled for as long as the process
	// lives, which is indistinguishable from an operator having turned them
	// off. runAPI's own wiring covers the reverse order.
	s.apiSnapshot().SetAIRuntimeService(service)

	s.health.SetAIRuntime(StateStarting, "", map[string]interface{}{
		"planes":             runtimeConfig.EffectivePlanes(),
		"poll_interval_s":    int(runtimeConfig.EffectivePollInterval().Seconds()),
		"min_risk_to_report": runtimeConfig.EffectiveMinRisk(),
		"host_plane":         runtimeConfig.EnableHostPlane,
		"dns_capture":        runtimeConfig.DNSCapture,
		"correlate":          runtimeConfig.CorrelationEnabled(),
	})

	errCh := make(chan error, 1)
	go func() { errCh <- service.Run(ctx) }()

	ticker := time.NewTicker(aiRuntimeHealthInterval)
	defer ticker.Stop()
	// The scan time of the last snapshot whose findings were emitted.
	var lastEmitted time.Time
	for {
		select {
		case err := <-errCh:
			if err != nil && ctx.Err() == nil && !isContextTermination(err) {
				s.health.SetAIRuntime(StateError, err.Error(), nil)
				return err
			}
			s.health.SetAIRuntime(StateStopped, "", nil)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		case <-ticker.C:
			snapshot := service.Snapshot()
			// Health refreshes on every tick: a subsystem that stops saying
			// anything must not be mistaken for one with nothing to say.
			s.publishAIRuntimeHealth(snapshot)
			// Findings do not. This ticker is deliberately faster than the
			// poll interval, so emitting the snapshot every tick would
			// re-send the same unchanged findings -- 360 times per poll at a
			// one-hour interval -- and the dashboard counts records with
			// count_over_time. Emit once per completed poll instead.
			if !shouldEmitAIRuntimeSnapshot(snapshot.ScannedAt, lastEmitted) {
				continue
			}
			lastEmitted = snapshot.ScannedAt
			// Emission is best-effort and never blocks the planes. A
			// destination being unreachable must not stop the sensor from
			// observing; the snapshot the API serves is unaffected either way.
			if adapter := newAIRuntimeV8Adapter(s.observabilityV8Emitter()); adapter != nil {
				_ = adapter.EmitSnapshot(ctx, snapshot)
			}
		case <-ctx.Done():
			// Bounded, not indefinite. Poll does not thread its context into
			// process and socket acquisition on every platform, so a poll that
			// is mid-read when cancellation arrives can outlast it. Waiting
			// forever here would hold the sidecar's WaitGroup open and turn a
			// slow probe into a gateway that will not shut down.
			select {
			case err := <-errCh:
				if err != nil && !isContextTermination(err) {
					s.health.SetAIRuntime(StateError, err.Error(), nil)
					return err
				}
				s.health.SetAIRuntime(StateStopped, "", nil)
			case <-time.After(aiRuntimeShutdownGrace):
				// Say so rather than exiting quietly: a plane still reading
				// after shutdown is a fact an operator should see, and
				// "stopped" would be a claim this code cannot make.
				s.health.SetAIRuntime(StateError,
					"runtime planes did not stop within "+aiRuntimeShutdownGrace.String()+
						"; a plane was still acquiring when shutdown began", nil)
			}
			return ctx.Err()
		}
	}
}

// shouldEmitAIRuntimeSnapshot reports whether this snapshot's findings have
// already been sent.
//
// The health ticker is deliberately faster than the poll interval so a long
// interval does not make the subsystem look stalled. Emitting findings on that
// cadence would re-send an unchanged snapshot every tick -- 360 times per poll
// at a one-hour interval -- and each emission takes a fresh occurrence id, so
// the packaged dashboard's count_over_time multiplies one finding into
// hundreds. Findings follow the poll; only health follows the ticker.
func shouldEmitAIRuntimeSnapshot(scannedAt, lastEmitted time.Time) bool {
	if scannedAt.IsZero() {
		// No poll has completed yet. There is nothing to report, and a zero
		// time must not be mistaken for a very old one.
		return false
	}
	return scannedAt.After(lastEmitted)
}

// publishAIRuntimeHealth records the current coverage.
//
// Every plane appears, running or not, and a degraded run says why. Reporting
// only the healthy planes would make a dead subscription look identical to a
// clean host.
func (s *Sidecar) publishAIRuntimeHealth(snapshot sensor.Snapshot) {
	planes := make(map[string]interface{}, len(snapshot.Planes))
	for _, health := range snapshot.Planes {
		entry := map[string]interface{}{
			"available": health.Available,
			"running":   health.Running,
		}
		if health.Mechanism != "" {
			entry["mechanism"] = health.Mechanism
		}
		if health.Reason != "" {
			entry["reason"] = health.Reason
		}
		planes[string(health.Plane)] = entry
	}
	details := map[string]interface{}{
		"findings":                 len(snapshot.Findings),
		"processes_observed":       snapshot.ProcessesObserved,
		"processes_skipped":        snapshot.ProcessesSkipped,
		"connections_observed":     snapshot.ConnectionsObserved,
		"connections_unattributed": snapshot.ConnectionsUnattributed,
		"planes":                   planes,
		"degraded":                 snapshot.Degraded,
	}
	if !snapshot.ScannedAt.IsZero() {
		// Omitted before the first poll rather than published as the zero
		// time. 0001-01-01T00:00:00Z is a valid-looking timestamp for a poll
		// that never happened, and a dashboard or an alert reading last_poll
		// has no way to tell the difference.
		details["last_poll"] = snapshot.ScannedAt.Format(time.RFC3339)
	}
	if snapshot.Degraded {
		details["degraded_reasons"] = sensor.SortedDegradedReasons(snapshot)
	}
	state := StateRunning
	if snapshot.ScannedAt.IsZero() {
		state = StateStarting
	}
	s.health.SetAIRuntime(state, "", details)
}

// aiRuntimeSnapshot returns the running service, or nil when the planes are
// disabled or have not started.
func (s *Sidecar) aiRuntimeSnapshot() *sensor.Service {
	if s == nil {
		return nil
	}
	s.aiRuntimeMu.RLock()
	defer s.aiRuntimeMu.RUnlock()
	return s.aiRuntime
}
