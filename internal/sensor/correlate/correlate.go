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

// Package correlate joins what the runtime planes observed against what
// continuous discovery inventoried, in process.
//
// # Why this is not a file poll
//
// Before absorption this ran as a separate product reading
// ~/.defenseclaw/ai_discovery_state.json on a timer. That boundary forced two
// limits: matching could only use categories where both sides observed the
// same artifact, and it could not use paths at all, because anything crossing
// the boundary was HMAC'd. In process, the join reads the live snapshot and
// neither limit applies.
//
// # The rule the design rests on
//
// Unobserved is never spent as evidence or as exoneration. An absent, stale,
// or unreadable inventory changes nothing: neither the attenuation nor the
// escalation applies, and findings score exactly as they do with correlation
// switched off. A detector whose numbers fall because another subsystem
// crashed is reporting "quiet" for "blind", and the blindness is still
// recorded -- not scoring on it is not the same as not saying so.
package correlate

import (
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// Verdict is what the inventory had to say about a runtime observation.
type Verdict string

const (
	// VerdictAccounted means the inventory independently observed the same
	// subject. Attenuates.
	VerdictAccounted Verdict = "accounted"
	// VerdictUnaccounted means a fresh, complete inventory observed nothing
	// that explains this. Escalates -- it is the more interesting reading.
	VerdictUnaccounted Verdict = "unaccounted"
	// VerdictUnobserved means there was no usable inventory to consult.
	// Changes nothing in either direction, and says so.
	VerdictUnobserved Verdict = "unobserved"
)

// RuntimeState is stamped onto a discovery signal by the join, so an operator
// reading the inventory can see presence and behaviour in one place.
type RuntimeState string

const (
	// RuntimePresentOnly is dormant attack surface: inventoried, never
	// observed running. Only discovery sees this.
	RuntimePresentOnly RuntimeState = "present_only"
	// RuntimeRan means both sides agree.
	RuntimeRan RuntimeState = "ran"
	// RuntimeRanNotPresent is an agent that arrived by a path the inventory
	// does not cover. Only the runtime planes see this.
	RuntimeRanNotPresent RuntimeState = "ran_not_present"
	// RuntimeUnobserved means the runtime planes could not look.
	RuntimeUnobserved RuntimeState = "unobserved"
)

// Snapshot is the inventory side of the join.
//
// Freshness is explicit rather than inferred from the data, because "the
// scanner has not run yet" and "the scanner ran and found nothing" are the two
// readings this package must never confuse.
type Snapshot struct {
	Signals  []inventory.AISignal
	ScanTime time.Time
	// Complete is false when the scan hit a traversal budget or a permission
	// error. An incomplete scan cannot conclude that something is absent, so
	// it never produces VerdictUnaccounted.
	Complete bool
}

// MaxSnapshotAge is how old an inventory may be and still count as observed. A
// snapshot older than this is treated as unobserved rather than as evidence,
// because it describes a host that may no longer exist.
const MaxSnapshotAge = 15 * time.Minute

// Observation is the runtime side of the join.
type Observation struct {
	// PID of the process the runtime planes attributed this to, when known.
	PID int
	// ExeName is the process basename.
	ExeName string
	// ModelHint is a model identity recovered from a local inference client or
	// runtime, when the runtime plane could name one.
	ModelHint string
	// MCPName is the MCP server identity, for agent_local_mcp_server.
	MCPName string
	// ProviderDomain is the peer hostname Plane B attributed, when named.
	ProviderDomain string
	// AgentName is the lineage-attributed agent, for host-plane observations.
	AgentName string
}

// Result carries the verdict plus the evidence behind it.
type Result struct {
	Verdict Verdict
	// Reason is always populated, including for VerdictUnobserved, so the
	// blindness is recorded rather than merely not scored.
	Reason string
	// MatchedSignalIDs are the discovery signals that accounted for this.
	MatchedSignalIDs []string
	// Categories are the discovery categories those matches came from.
	Categories []string
}

// Tag renders the verdict for a finding's evidence list.
func (r Result) Tag() string { return "correlation:" + string(r.Verdict) }

// Correlator joins runtime observations against an inventory snapshot.
type Correlator struct {
	snapshot Snapshot
	now      func() time.Time
}

// New returns a correlator over one snapshot.
func New(snapshot Snapshot) *Correlator { return &Correlator{snapshot: snapshot, now: time.Now} }

// usable reports whether the snapshot may be spent as evidence at all, and why
// not when it may not.
func (c *Correlator) usable() (bool, string) {
	if len(c.snapshot.Signals) == 0 && c.snapshot.ScanTime.IsZero() {
		return false, "no discovery snapshot has been produced yet"
	}
	if c.snapshot.ScanTime.IsZero() {
		return false, "discovery snapshot carries no scan time"
	}
	if age := c.now().Sub(c.snapshot.ScanTime); age > MaxSnapshotAge {
		return false, "discovery snapshot is stale (" + age.Truncate(time.Second).String() + " old)"
	}
	return true, ""
}

// LocalModel correlates a Plane A local-inference observation against the
// inventory's local_model and local_ai_endpoint signals.
func (c *Correlator) LocalModel(observation Observation) Result {
	return c.correlate(observation, []string{
		inventory.SignalLocalModel,
		inventory.SignalLocalAIEndpoint,
	}, c.matchesLocalModel)
}

// MCPServer correlates an observed local MCP server against the inventory's
// declared ones.
func (c *Correlator) MCPServer(observation Observation) Result {
	return c.correlate(observation, []string{inventory.SignalMCPServer}, c.matchesMCP)
}

// Connector correlates a host-plane observation against the named connector
// the lineage attributed it to.
//
// This match was impossible across the old product boundary. It is what turns
// "some agent read a credential" into "Claude Code, which this host has
// inventoried, read a credential".
func (c *Correlator) Connector(observation Observation) Result {
	return c.correlate(observation, []string{
		inventory.SignalSupportedConnector,
		inventory.SignalAICLI,
		inventory.SignalActiveProcess,
	}, c.matchesConnector)
}

// ProviderDomain correlates a Plane B per-process egress peer against the
// inventory's host-wide provider_domain signals.
//
// Also impossible before: provider_domain is host-wide DNS with no pid, so
// pairing it with per-process attribution promotes a host fact to a process
// fact.
func (c *Correlator) ProviderDomain(observation Observation) Result {
	return c.correlate(observation, []string{inventory.SignalProviderDomain}, c.matchesDomain)
}

func (c *Correlator) correlate(
	observation Observation,
	categories []string,
	matches func(Observation, inventory.AISignal) bool,
) Result {
	if ok, reason := c.usable(); !ok {
		return Result{Verdict: VerdictUnobserved, Reason: reason}
	}
	wanted := make(map[string]bool, len(categories))
	for _, category := range categories {
		wanted[category] = true
	}
	var (
		matchedIDs     []string
		matchedCats    []string
		consideredAny  bool
		seenCategories = map[string]bool{}
	)
	for _, signal := range c.snapshot.Signals {
		if !wanted[signal.Category] {
			continue
		}
		// Discovery collects this category and looked at it. That is true even
		// for a gone signal, which is why this is set before the gone check:
		// "the model was removed" is an observation of absence, not a failure
		// to observe, and must reach VerdictUnaccounted rather than
		// VerdictUnobserved.
		consideredAny = true
		// A gone signal is a past observation, not a current one. Counting it
		// as accounting-for would let a removed model excuse a live process.
		if signal.State == inventory.AIStateGone {
			continue
		}
		if !matches(observation, signal) {
			continue
		}
		matchedIDs = append(matchedIDs, signal.SignalID)
		if !seenCategories[signal.Category] {
			seenCategories[signal.Category] = true
			matchedCats = append(matchedCats, signal.Category)
		}
	}
	if len(matchedIDs) > 0 {
		return Result{
			Verdict:          VerdictAccounted,
			Reason:           "discovery independently observed the same subject",
			MatchedSignalIDs: matchedIDs,
			Categories:       matchedCats,
		}
	}
	if !c.snapshot.Complete {
		// An incomplete scan cannot conclude absence. This is the same rule as
		// staleness: not scoring on it is not the same as not saying so.
		return Result{
			Verdict: VerdictUnobserved,
			Reason:  "discovery scan was incomplete, so absence is not evidence",
		}
	}
	if !consideredAny {
		return Result{
			Verdict: VerdictUnobserved,
			Reason:  "discovery reported no signals in the categories this could match",
		}
	}
	return Result{
		Verdict: VerdictUnaccounted,
		Reason:  "a complete discovery scan accounts for none of this",
	}
}

func (c *Correlator) matchesLocalModel(observation Observation, signal inventory.AISignal) bool {
	if observation.ModelHint != "" && signal.Model != nil &&
		equalFold(observation.ModelHint, signal.Model.ID) {
		return true
	}
	// A runtime pid the inventory also saw is the strongest match available:
	// it is the same process, not merely the same product.
	if observation.PID > 0 && signal.Runtime != nil && signal.Runtime.PID == observation.PID {
		return true
	}
	if observation.ExeName == "" {
		return false
	}
	if signal.Runtime != nil && equalFold(observation.ExeName, signal.Runtime.Comm) {
		return true
	}
	return equalFold(observation.ExeName, signal.Product) ||
		matchesAnyBasename(observation.ExeName, signal.Basenames)
}

func (c *Correlator) matchesMCP(observation Observation, signal inventory.AISignal) bool {
	if observation.MCPName == "" {
		return false
	}
	return equalFold(observation.MCPName, signal.Name) ||
		matchesAnyBasename(observation.MCPName, signal.Basenames)
}

func (c *Correlator) matchesConnector(observation Observation, signal inventory.AISignal) bool {
	if observation.PID > 0 && signal.Runtime != nil && signal.Runtime.PID == observation.PID {
		return true
	}
	for _, candidate := range []string{observation.AgentName, observation.ExeName} {
		if candidate == "" {
			continue
		}
		if equalFold(candidate, signal.Product) ||
			equalFold(candidate, signal.SupportedConnector) ||
			equalFold(candidate, signal.Name) ||
			matchesAnyBasename(candidate, signal.Basenames) {
			return true
		}
	}
	return false
}

func (c *Correlator) matchesDomain(observation Observation, signal inventory.AISignal) bool {
	if observation.ProviderDomain == "" {
		return false
	}
	domain := strings.ToLower(strings.TrimSuffix(observation.ProviderDomain, "."))
	if equalFold(domain, signal.Name) || equalFold(domain, signal.Product) {
		return true
	}
	for _, basename := range signal.Basenames {
		candidate := strings.ToLower(strings.TrimSuffix(basename, "."))
		if candidate == "" {
			continue
		}
		if domain == candidate || strings.HasSuffix(domain, "."+candidate) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func matchesAnyBasename(value string, basenames []string) bool {
	for _, basename := range basenames {
		if equalFold(value, basename) {
			return true
		}
	}
	return false
}
