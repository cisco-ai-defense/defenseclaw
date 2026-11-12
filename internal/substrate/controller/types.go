// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package controller

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// Attestation is what the controller needs to know about a template's
// images: whether DefenseClaw attested them, and the connector and kit
// version the attestation names.
type Attestation struct {
	Attested   bool
	Digest     string
	Connector  string
	KitVersion string
	// Reason says why a template is not attested (no attestation, bad
	// signature, digest mismatch...).
	Reason string
	// Retryable marks a refusal whose cause may pass (the registry is
	// unreachable): the controller keeps a recent good verdict meanwhile
	// (GAP-0127).
	Retryable bool
	// ValidUntil is when the verdict must be checked again (the earliest
	// attest.Verified.ValidUntil of the template's images); zero = the
	// controller's own TTL only.
	ValidUntil time.Time
}

// Attestor verifies a template's DefenseClaw attestation (lane A9
// implements it over in-toto; controllerfake.Attestor is the test fake).
type Attestor interface {
	Attest(ctx context.Context, tmpl *ateapi.ActorTemplate) (Attestation, error)
}

// ActivitySource reports what an actor did, keyed by actor UID. The
// gateway (hooks, model calls, relay) and the callout (egress) feed it
// (lane A2); controllerfake.Activity is the test fake.
type ActivitySource interface {
	// LastActivity is the last hook, model, relay or egress activity.
	LastActivity(uid string) (time.Time, bool)
	// PendingAsk reports an ask waiting for an answer.
	PendingAsk(uid string) bool
}

// CPUSource reports an actor's recent CPU use in cores and when it was
// sampled. UsageCPU computes it from Substrate's per-actor usage records
// (ate.actor.usage_sampled); controllerfake.Activity is the test fake.
type CPUSource interface {
	CPU(uid string) (cores float64, sampledAt time.Time, ok bool)
}

// Attribution sources of a Registration.
const (
	SourceLauncher = "launcher" // created by the DefenseClaw launcher for a verified person or workload
	SourceAtespace = "atespace" // created elsewhere; attributed to its atespace (D3)
	SourceFork     = "fork"     // adopted fork, attributed to its parent
)

// Forked-by values.
const (
	ForkedByDefenseClaw = "defenseclaw"
	ForkedByUnknown     = "unknown"
)

// Registration is who an actor belongs to, keyed by actor UID. The launcher
// writes it at create; the controller writes it for adopted forks and for
// actors attributed to their atespace.
type Registration struct {
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	// Template is the actor's template, "<atespace>/<name>" (the controller
	// sets it from the actor on every pass).
	Template string `json:"template,omitempty"`
	// Person is the verified OIDC subject; Workload a verified workload
	// principal. Both empty for atespace attribution.
	Person   string `json:"person,omitempty"`
	Workload string `json:"workload,omitempty"`
	// Profile is the DefenseClaw profile the launcher resolved; empty lets
	// the ProfileResolver pick by atespace.
	Profile string `json:"profile,omitempty"`
	// Task marks an unattended --task or --batch run; IdleSuspendTask is
	// set when its profile allows idle suspend anyway.
	Task            bool     `json:"task,omitempty"`
	IdleSuspendTask bool     `json:"idle_suspend_task,omitempty"`
	BatchID         string   `json:"batch_id,omitempty"`
	ParentUID       string   `json:"parent_uid,omitempty"`
	ForkedBy        string   `json:"forked_by,omitempty"`
	Approved        []string `json:"approved,omitempty"`
	Source          string   `json:"source"`
}

// Registry stores registrations. The shipped controller uses
// LeaderRegistry, the gateway leader's store the launcher writes to
// (GAP-0125); NewMemoryRegistry is for tests. A Get error means "unknown
// right now": the controller holds and changes no policy.
type Registry interface {
	Get(ctx context.Context, atespace, uid string) (Registration, bool, error)
	Put(ctx context.Context, r Registration) error
}

// Resolution is the profile an actor gets.
type Resolution struct {
	// Managed false means DefenseClaw does not manage the atespace: the
	// actor is inventoried only and no policy is written or removed.
	Managed bool
	Profile render.Profile
	// Refuse, when set, means the profile does not allow the actor
	// (sandboxes not allowed for the subject); it gets no policy.
	Refuse string
	// Warnings are shown as events (for example a glob on a foreign
	// atespace, E3).
	Warnings []string
	// DenyOnly, when set, is why the actor keeps only the DefenseClaw rule
	// (a managed install whose bundle no longer verifies, D8).
	DenyOnly string
}

// ProfileResolver picks an actor's profile.
type ProfileResolver interface {
	Resolve(reg Registration, launcher bool) (Resolution, error)
}

// AtespaceLister is implemented by a resolver that knows the atespaces it
// manages by name. Without the global viewer role the controller lists only
// these (and the launcher atespaces).
type AtespaceLister interface {
	ManagedAtespaces() []string
}

// Sink receives controller events (audit, telemetry, discovery).
type Sink interface {
	Emit(Event)
}

// Event types.
const (
	EventInventory          = "sandbox.inventory"
	EventDeleted            = "sandbox.deleted"
	EventRecreatedSameName  = "sandbox.actor.recreated_same_name"
	EventPolicyWritten      = "sandbox.policy.written"
	EventPolicyRemoved      = "sandbox.policy.removed"
	EventPolicyWriteFailed  = "sandbox.policy.write_failed"
	EventForeignRule        = "sandbox.policy.foreign_rule"
	EventPolicyConflict     = "sandbox.policy_conflict"
	EventConflictCleared    = "sandbox.policy_conflict.cleared"
	EventConflictReset      = "sandbox.policy_conflict.reset"
	EventResumeRecheck      = "sandbox.resume_recheck"
	EventTemplateUnverified = "sandbox.template_unverified"
	EventKitRefused         = "sandbox.kit_refused"
	EventForeignActor       = "sandbox.foreign_actor"
	EventProfileRefused     = "sandbox.profile_refused"
	EventFork               = "sandbox.fork"
	EventIdleSuspend        = "sandbox.idle_suspend"
	EventWarning            = "sandbox.warning"
)

// Severities.
const (
	SeverityInfo  = "info"
	SeverityWarn  = "warning"
	SeverityAlert = "alert"
)

// Event is one controller record. It never carries a credential value:
// policies hold references only, and Detail is built from names.
type Event struct {
	Type     string         `json:"type"`
	Time     time.Time      `json:"time"`
	Severity string         `json:"severity"`
	Atespace string         `json:"atespace,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	ActorUID string         `json:"actor_uid,omitempty"`
	Message  string         `json:"message"`
	Detail   map[string]any `json:"detail,omitempty"`
	// Signal is set for discovery (shadow AI) findings.
	Signal *Signal `json:"signal,omitempty"`
}

// Signal is a discovery finding in the inventory ai_signals shape
// (inventory.AISignal), with the sandbox fields naming the actor.
type Signal struct {
	Fingerprint string    `json:"fingerprint"`
	SignalID    string    `json:"signal_id"`
	SignatureID string    `json:"signature_id"`
	Name        string    `json:"name"`
	Vendor      string    `json:"vendor"`
	Product     string    `json:"product"`
	Category    string    `json:"category"`
	Confidence  float64   `json:"confidence"`
	State       string    `json:"state"`
	Detector    string    `json:"detector"`
	Source      string    `json:"source"`
	Version     string    `json:"version,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SandboxID   string    `json:"sandbox_id,omitempty"`
	SandboxName string    `json:"sandbox_name,omitempty"`
}

// Shadow AI signal ids.
const (
	SignalUnattestedTemplate = "substrate.unattested_template"
	SignalForeignActor       = "substrate.foreign_actor"
	SignalPolicyConflict     = "substrate.policy_conflict"
	SignalOldKit             = "substrate.old_kit"
)
