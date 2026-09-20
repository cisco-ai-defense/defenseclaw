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

// Package tactics classifies a kernel event or a command line into one
// ATT&CK-shaped tactic, and orders those tactics into a kill chain.
//
// Everything here is a pure function over already-acquired observations. It
// performs no I/O and reads no configuration, so the same input classifies
// identically on every platform and every classification is testable from a
// fixture.
//
// # Why the sequence matters more than the step
//
// Not one of these tactics is worth paging on alone. Each has an ordinary
// explanation for an agent doing the job it was asked to do, and a detector
// that alerts on a single credential read is turned off within a week. Reading
// a credential is a lead; reading a credential, then minting an identity, then
// uploading to a paste site is an incident. That is what ChainStage exists to
// measure.
package tactics

// Tactic is one classified agent behaviour.
type Tactic string

const (
	CredentialAccess    Tactic = "credential_access"
	IdentityCreation    Tactic = "identity_creation"
	PrivilegeEscalation Tactic = "privilege_escalation"
	Persistence         Tactic = "persistence"
	Exfiltration        Tactic = "exfiltration"
	LocalInference      Tactic = "local_inference"
)

// ChainOrder is the order a real intrusion tends to walk. It decides whether a
// set of observations is a chain -- movement through the stages -- or merely
// several unrelated things that happened to the same process.
var ChainOrder = [...]Tactic{
	LocalInference,
	CredentialAccess,
	IdentityCreation,
	PrivilegeEscalation,
	Persistence,
	Exfiltration,
}

// attackTechnique is the MITRE ATT&CK technique per tactic. It is carried on
// every emitted record so downstream dashboards and Splunk searches can pivot
// on a vocabulary a SOC already uses.
var attackTechnique = map[Tactic]string{
	CredentialAccess:    "T1552", // Unsecured Credentials
	IdentityCreation:    "T1136", // Create Account
	PrivilegeEscalation: "T1548", // Abuse Elevation Control Mechanism
	Persistence:         "T1543", // Create or Modify System Process
	Exfiltration:        "T1567", // Exfiltration Over Web Service
	LocalInference:      "T1059", // Command and Scripting Interpreter
}

// Technique is the ATT&CK technique id for a tactic, or "" when it has none.
func (t Tactic) Technique() string { return attackTechnique[t] }

// Valid reports whether t is one of the known tactics.
func (t Tactic) Valid() bool {
	_, ok := attackTechnique[t]
	return ok
}

// signalTactics maps each emitted signal to its tactic. It lets the telemetry
// layer enrich a finding with tactic and technique without importing the
// correlator, and keeps one definition of the mapping.
var signalTactics = map[string]Tactic{
	"agent_credential_access":    CredentialAccess,
	"agent_identity_creation":    IdentityCreation,
	"agent_privilege_escalation": PrivilegeEscalation,
	"agent_persistence":          Persistence,
	"agent_config_persistence":   Persistence,
	"agent_encoded_payload":      Exfiltration,
	"agent_public_exfil_surface": Exfiltration,
	"agent_local_mcp_server":     LocalInference,
}

// ForSignal returns the tactic a signal id belongs to.
func ForSignal(signalID string) (Tactic, bool) {
	tactic, ok := signalTactics[signalID]
	return tactic, ok
}

// ChainStage is the position of a tactic in the kill chain, or -1 when it is
// not part of one.
func ChainStage(t Tactic) int {
	for index, candidate := range ChainOrder {
		if candidate == t {
			return index
		}
	}
	return -1
}

// ForSignals returns the distinct tactics a set of signal ids represents, in
// chain order.
func ForSignals(signalIDs []string) []Tactic {
	present := make(map[Tactic]bool, len(signalIDs))
	for _, id := range signalIDs {
		if tactic, ok := signalTactics[id]; ok {
			present[tactic] = true
		}
	}
	ordered := make([]Tactic, 0, len(present))
	for _, tactic := range ChainOrder {
		if present[tactic] {
			ordered = append(ordered, tactic)
		}
	}
	return ordered
}

// Match is one classified observation.
type Match struct {
	Tactic   Tactic
	SignalID string
	Title    string
	Detail   string
	// Confidence scales the signal weight in exactly the way attribution
	// confidence does for egress. A polled observation that cannot name the
	// writing process is graded down here rather than discarded.
	Confidence float64
}

// Technique is the ATT&CK technique for the match's tactic.
func (m Match) Technique() string { return m.Tactic.Technique() }
