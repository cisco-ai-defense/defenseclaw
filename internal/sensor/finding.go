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

// Package sensor runs the AI Discovery runtime planes: it samples the host,
// classifies what it sees, scores the result, and joins it against the
// inventory snapshot.
//
// Where internal/inventory answers "what AI is present on this host", this
// answers "what actually ran, and where did it send data".
package sensor

import (
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// Finding is one scored runtime observation about one process.
type Finding struct {
	// FindingID is stable for the life of a process episode, so repeated
	// emissions about the same process update rather than accumulate.
	FindingID string
	PID       int
	// Process is the executable basename.
	Process string
	// Cmdline is argv. It is a content-class field on the wire.
	Cmdline string
	User    string
	// AgentName is the lineage-attributed agent, when one was found.
	AgentName string
	Score     int
	Severity  scoring.Severity
	Signals   []scoring.Signal
	// Providers are the egress peers attributed to this process.
	Providers []ProviderReach
	// Correlation is what the inventory had to say. Always populated,
	// including when it had nothing to say and why.
	Correlation correlate.Result
	FirstSeen   time.Time
	LastSeen    time.Time
}

// ProviderReach is one attributed egress peer.
type ProviderReach struct {
	Hostname string
	Address  string
	Port     int
	Category string
	// Confidence is how the peer was named: a captured DNS answer is a direct
	// observation, a catalog address match or a PTR record is an inference.
	Confidence float64
	// AttributionSource records which of those it was, so a reviewer can weigh
	// the finding without re-deriving it.
	AttributionSource string
}

// Attribution confidences, ordered by how directly the peer was observed.
const (
	// ConfidenceDNSAnswer is a captured answer to a lookup this process made.
	// It is an observation of what the process actually resolved.
	ConfidenceDNSAnswer = 0.95
	// ConfidenceCatalogAddress is a hit in the address index. Real evidence,
	// but a shared or stale address can point at the wrong provider.
	ConfidenceCatalogAddress = 0.75
	// ConfidenceReverseDNS is a PTR record, which the address owner controls
	// and which frequently names infrastructure rather than the service.
	ConfidenceReverseDNS = 0.6
)

// PlaneHealth is one plane's current state.
//
// It is emitted on every tick including zero. If it were emitted only while
// healthy, a subscription that died would leave no trace at all, and absence
// is the hardest thing to alert on.
type PlaneHealth struct {
	Plane     platform.Plane
	Available bool
	// Running distinguishes "this platform can do it" from "it is doing it
	// right now". A plane that was available and has stopped is the case this
	// field exists for.
	Running bool
	// Mechanism or Reason, whichever applies, copied from the capability so a
	// dashboard row is self-describing.
	Mechanism string
	Reason    string
	// ObservedAt is when the plane last produced anything.
	ObservedAt time.Time
}

// Snapshot is the current state of the runtime planes, as served to the API,
// the CLI, and the TUI.
type Snapshot struct {
	// ScannedAt is when the most recent poll completed.
	ScannedAt time.Time
	// Findings are the findings at or above the reporting floor.
	Findings []Finding
	// Planes is every plane, always all three, healthy or not.
	Planes []PlaneHealth
	// ProcessesObserved and ProcessesSkipped describe process-table coverage.
	ProcessesObserved int
	ProcessesSkipped  int
	// ConnectionsObserved and ConnectionsUnattributed describe socket
	// coverage. On an unprivileged POSIX host the second number is how much of
	// the machine's egress this run cannot name an owner for, which is the
	// difference between a quiet host and a blind sensor.
	ConnectionsObserved     int
	ConnectionsUnattributed int
	// Degraded is true when any plane the platform supports is not running.
	Degraded bool
	// DegradedReasons lists why, one entry per affected plane.
	DegradedReasons []string
}

// sortFindings orders findings for display: most severe first, then by process
// so the order is stable between polls that score the same.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		if findings[i].Process != findings[j].Process {
			return findings[i].Process < findings[j].Process
		}
		return findings[i].PID < findings[j].PID
	})
}
