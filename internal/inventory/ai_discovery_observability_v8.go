// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// AIDiscoveryV8ScanStart contains only facts known before a real scan starts.
// The gateway adapter translates it to the generated family vocabulary; this
// package never owns routing, resource, sampling, or provenance.
type AIDiscoveryV8ScanStart struct {
	ScanID      string
	Source      string
	PrivacyMode string
	StartedAt   time.Time
}

// AIDiscoveryV8DetectorStart contains the source-backed identity and start
// time of one detector actually invoked by the scan.
type AIDiscoveryV8DetectorStart struct {
	ScanID    string
	Detector  string
	StartedAt time.Time
}

// AIDiscoveryV8DetectorResult is the bounded terminal observation for one
// detector. Failed is deliberately separate from an error value so arbitrary
// detector diagnostics never cross the telemetry adapter boundary.
type AIDiscoveryV8DetectorResult struct {
	EndedAt      time.Time
	DurationMs   int64
	SignalsTotal int64
	FilesScanned int64
	Failed       bool
}

// AIDiscoveryV8ComponentObservation is the source-backed component rollup used
// by the generated confidence-change log and the existing dashboard metrics.
// ComponentID is a deterministic digest of the exact normalized grouping key;
// it does not invent an external asset identity.
type AIDiscoveryV8ComponentObservation struct {
	ComponentID        string
	ComponentType      string
	HasLifecycleChange bool
	Metrics            telemetry.AIComponentConfidenceAttrs
}

type AIDiscoveryV8DetectorTrace interface {
	End(AIDiscoveryV8DetectorResult) error
	Abort()
}

// AIDiscoveryV8ScanTrace is the inventory-facing capability for one generated
// scan root. A nil child is normal collection/sampling admission.
type AIDiscoveryV8ScanTrace interface {
	StartDetector(AIDiscoveryV8DetectorStart) (AIDiscoveryV8DetectorTrace, error)
	End(AIDiscoveryReport) error
	Abort()
}

// AIDiscoveryObservabilityV8 is implemented by the gateway's process-owned v8
// runtime adapter. EmitReport owns generated log/metric construction and must
// never fall back to legacy OTel after accepting an occurrence.
type AIDiscoveryObservabilityV8 interface {
	StartScan(context.Context, AIDiscoveryV8ScanStart) (context.Context, AIDiscoveryV8ScanTrace, error)
	EmitReport(context.Context, AIDiscoveryReport, []AIDiscoveryV8ComponentObservation) error
}

// BindObservabilityV8 publishes or detaches the process-owned adapter. Adapter
// absence suppresses telemetry; it never selects a second provider path.
func (s *ContinuousDiscoveryService) BindObservabilityV8(observer AIDiscoveryObservabilityV8) {
	if s == nil {
		return
	}
	s.observabilityV8Mu.Lock()
	s.observabilityV8 = observer
	s.observabilityV8Mu.Unlock()
	if s.invStore != nil {
		sqliteObserver, _ := observer.(SQLiteBusyObservabilityV8)
		s.invStore.bindSQLiteBusyObservabilityV8(sqliteObserver)
	}
}

func (s *ContinuousDiscoveryService) observabilityV8Snapshot() AIDiscoveryObservabilityV8 {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.RLock()
	observer := s.observabilityV8
	s.observabilityV8Mu.RUnlock()
	return observer
}

type aiDiscoveryScanObservation struct {
	generated AIDiscoveryV8ScanTrace
}

func (s *ContinuousDiscoveryService) startScanObservation(
	ctx context.Context,
	start AIDiscoveryV8ScanStart,
) (context.Context, *aiDiscoveryScanObservation) {
	observer := s.observabilityV8Snapshot()
	observation := &aiDiscoveryScanObservation{}
	if observer == nil {
		return ctx, observation
	}
	startedContext, generated, err := observer.StartScan(ctx, start)
	if err != nil {
		return ctx, observation
	}
	observation.generated = generated
	return startedContext, observation
}

func (observation *aiDiscoveryScanObservation) startDetector(
	ctx context.Context,
	s *ContinuousDiscoveryService,
	start AIDiscoveryV8DetectorStart,
) *aiDiscoveryDetectorObservation {
	detector := &aiDiscoveryDetectorObservation{}
	if observation == nil {
		return detector
	}
	if observation.generated == nil {
		return detector
	}
	generated, err := observation.generated.StartDetector(start)
	if err == nil {
		detector.generated = generated
	}
	return detector
}

type aiDiscoveryDetectorObservation struct {
	generated AIDiscoveryV8DetectorTrace
}

func (observation *aiDiscoveryDetectorObservation) end(result AIDiscoveryV8DetectorResult) {
	if observation == nil {
		return
	}
	if observation.generated != nil {
		_ = observation.generated.End(result)
	}
}

func (observation *aiDiscoveryScanObservation) end(report AIDiscoveryReport) {
	if observation == nil {
		return
	}
	if observation.generated != nil {
		_ = observation.generated.End(report)
	}
}

func (observation *aiDiscoveryScanObservation) abort() {
	if observation == nil {
		return
	}
	if observation.generated != nil {
		observation.generated.Abort()
	}
}
