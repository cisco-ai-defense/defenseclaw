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

	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
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

	// The fields below are set on host-plane findings only.

	// Exe is the agent root's resolved executable path, when the backend
	// reported one.
	Exe string
	// UID and AUID are the agent root's kernel uid and audit login uid; nil
	// is "not observed". A record's user.id is the uid, never the login uid.
	UID  *int
	AUID *int
	// Connector is the CLI connector the agent root is ("claudecode"), ""
	// for a root recognised only by heuristics or hosted in an IDE.
	Connector string
	// NotEnforcedReason is why no kernel control can ever anchor this root:
	// tactics.RootIDEHosted or tactics.RootHeuristic. It is "" for a CLI
	// connector, whose enforcing scope the sensor helper decides from
	// enrollment; the attribution itself is the same either way.
	NotEnforcedReason string
	// Activities is the per-tactic detail of the session, in chain order.
	Activities []RuntimeActivity
}

// RuntimeActivity is what the host plane knows about one tactic of an agent
// session beyond its score: which backend saw it, which process identity did
// it, what a DefenseClaw kernel control did about it, and whether a managed
// hook decision covered the tool call it came from.
type RuntimeActivity struct {
	Tactic tactics.Tactic
	// Source is the backend of the latest observation (tetragon, cn_proc,
	// fanotify, ...); "" when the backend does not say.
	Source plane.EventSource
	// UID, AUID and User are the observed process's, from its latest
	// observation.
	UID  *int
	AUID *int
	User string
	// Outcome is the strongest kernel outcome seen for the tactic (blocked,
	// then would_block, then observed); "" when no DefenseClaw kernel policy
	// reported it. Control is the control of that outcome.
	Outcome plane.KernelOutcome
	Control string
	// Hook is the hook join of the tool call the activity came from. nil
	// when it does not apply: not a managed host, the agent root acting
	// itself, or a tool call that started before the gateway was watching.
	Hook *HookJoin
}

// Hook-join confidences.
const (
	// HookJoinExact is a tool call whose shell command hashed equal to the
	// command of a managed hook decision for the same agent.
	HookJoinExact = "exact"
	// HookJoinTemporal is a tool call matched to a decision of the same agent
	// by time only.
	HookJoinTemporal = "temporal"
)

// HookJoin labels a tool call with the managed hook decision that covered
// it. The join only labels; it never blocks.
type HookJoin struct {
	// Seen is false when no hook decision matched: agent activity without a
	// hook decision (Claude's ! mode, a nohup job, an MCP server).
	Seen bool
	// Confidence is HookJoinExact or HookJoinTemporal when Seen.
	Confidence string
	// Connector, SessionID and ToolInvocationID are the joined decision's.
	Connector        string
	SessionID        string
	ToolInvocationID string
	// Action is the joined decision's verdict (allow, or alert for one that
	// let the tool run with a finding) and RuleIDs its first rule ids (at
	// most MaxHookRuleIDs), so a record can say the hook allowed a tool call
	// (rule X alerted) that a kernel policy then denied.
	Action  string
	RuleIDs []string
}

// MaxHookRuleIDs bounds the rule ids a hook join carries.
const MaxHookRuleIDs = 3

// Kernel control rule ids: the guardrail rules each built-in kernel control
// enforces at the kernel, so a kernel denial joins the hook record of the
// same intent.
var kernelControlRules = map[string]string{
	"kernel.ssh_private_key_read": "PATH-SSH-KEY",
	"kernel.persistence_write":    "persistence.shell_profile_write",
}

// KernelControlRuleID is the guardrail rule id of a kernel control, or "".
func KernelControlRuleID(control string) string { return kernelControlRules[control] }

// KernelEvent is one access a DefenseClaw kernel control decided: denied
// (blocked) or, with its policy in monitor mode, counted (would_block).
// Container processes are never in a control's scope and never appear.
type KernelEvent struct {
	At      time.Time
	Outcome plane.KernelOutcome
	Control string
	// RuleID is KernelControlRuleID(Control).
	RuleID string
	// Policy is the Tetragon policy name.
	Policy string
	Kind   plane.Kind
	// Path is the file the process opened.
	Path    string
	PID     int
	ExecID  string
	Process string
	Exe     string
	UID     *int
	AUID    *int
	User    string
	// AgentName, RootPID and Connector are the gateway's attribution of the
	// process; empty when its lineage reaches no agent the gateway knows
	// (the helper's anchors decide the kernel's scope, not this).
	AgentName string
	RootPID   int
	Connector string
	Hook      *HookJoin
}

// KernelState is what the managed Linux sensor helper last said about its
// kernel policies (the kernel_status op).
type KernelState struct {
	// Status is the helper's last answer.
	Status acquire.KernelStatus
	// FetchedAt is when Status was read.
	FetchedAt time.Time
	// Reachable is false when the latest read failed. Status is then the
	// last good answer, kept so a stopped helper still shows what it left
	// loaded; UnreachableSince says since when.
	Reachable        bool
	UnreachableSince time.Time
	// Error is the latest read's failure, content-free.
	Error string
	// WouldBlockLastHour and BlockedLastHour are the would-block hits and
	// denials of DefenseClaw's kernel controls in the hour before FetchedAt,
	// for every user on the host: the growth of the helper's
	// would_block_total and blocked_total across the reads of that hour (a
	// total that went down, a restarted helper, counts from zero). In the
	// gateway's first hour they cover only the time since it started.
	WouldBlockLastHour int64
	BlockedLastHour    int64
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
	// Backend is Plane C's process backend on the managed Linux sensor
	// helper (Tetragon, or the native one and why); nil everywhere else.
	Backend *plane.Backend
	// ContainerEvents is how many Plane C events this cycle came from
	// container processes: counted, and never joined to a host session.
	ContainerEvents int64
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
	// KernelConnectsDropped counts the kernel connects (Tetragon, observe
	// and enforce) since the previous poll that did not fit the per-poll
	// bound; the ones that did are scored as connections of their process.
	KernelConnectsDropped int64
	// HostPlaneObservations is how many kernel observations the host plane
	// classified into a tactic, and HostPlaneGated how many it discarded for
	// having no AI agent above them.
	//
	// Reported because the lineage gate is the primary false-positive control,
	// and a control nobody can measure is a control nobody can trust. A gated
	// count that stays zero while the classified count also stays zero means
	// the plane is delivering nothing, which is a different problem from a
	// quiet host.
	HostPlaneObservations int64
	HostPlaneGated        int64
	// HostPlaneContainerEvents is how many host-plane events came from
	// container processes since the plane started. They are routed to this
	// count and never join a host agent session.
	HostPlaneContainerEvents int64
	// HostPlaneHookUnexpected is how many processes started under a
	// verified DefenseClaw hook that are not the hook's own tools
	// (hook_subtree_unexpected). They are forwarded and scored like any
	// other process; this only counts them.
	HostPlaneHookUnexpected int64
	// KernelEvents are the kernel control outcomes since the previous poll,
	// at most maxKernelEventsPerPoll; KernelEventsDropped counts the rest.
	KernelEvents        []KernelEvent
	KernelEventsDropped int64
	// CustomerKernelEvents are the attributed events of the host's own
	// Tetragon policies since the previous poll, at most
	// maxCustomerRecordsPerPoll; CustomerKernelEventsDropped counts the rest.
	// They are records of their own: never a finding, never scored.
	CustomerKernelEvents        []CustomerKernelEvent
	CustomerKernelEventsDropped int64
	// RecentCustomerKernelEvents are the latest attributed ones (at most
	// maxCustomerRecent, oldest first), as Service.Snapshot reads them for
	// the runtime API; empty in a poll's own result.
	RecentCustomerKernelEvents []CustomerKernelEvent
	// Kernel is the sensor helper's kernel-policy state; nil when the
	// acquirer is not a helper that reports one.
	Kernel *KernelState
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
