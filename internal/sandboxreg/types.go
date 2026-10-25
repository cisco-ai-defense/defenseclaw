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

// Package sandboxreg holds the managed gateway's sandbox registrations and
// saved decisions: one record per sandbox a user's daemon registered, the
// per-uid stores that keep them and the floor check of a decision.
//
// Stores are scoped to the caller's uid: another uid's registration id
// behaves exactly like an unknown one.
package sandboxreg

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// RecordVersion is the "v" of a Registration and a Decision.
const RecordVersion = 1

// Registration ids are IDPrefix followed by IDRandomChars lowercase base32
// characters (128 random bits).
const (
	IDPrefix      = "reg-"
	IDRandomChars = 26
)

// Registration states.
const (
	StatePending = "pending"
	StateLive    = "live"
	// StateStopped is a bound registration whose daemon reported its
	// sandbox not running, or has not reported it running for LiveLease
	// (EffectiveState). It still answers policy/current, so the sandbox can
	// start again under it, and it authorizes no relayed call.
	StateStopped = "stopped"
	StateRevoked = "revoked"
)

// StateExpired is what EffectiveState names a pending registration past
// PendingTTL. It is never stored: a late bind is told "expired".
const StateExpired = "expired"

// Profile match kinds (Registration.ProfileMatch).
const (
	MatchAgent               = "agent"
	MatchUser                = "user"
	MatchGroup               = "group"
	MatchConnector           = "connector"
	MatchDefault             = "default"
	MatchDefaultUnverified   = "default_unverified"
	MatchDefaultLookupFailed = "default_lookup_failed"
	MatchNone                = "none"
)

// DigestPrefix prefixes SubjectKey and FactsDigest.
const DigestPrefix = "hmac-sha256:"

// SubjectKeyVersion is the first field of the subject key's input
// "v1|uid|account|sid".
const SubjectKeyVersion = "v1"

// Store limits and lifetimes.
const (
	// PendingTTL is how long a registration may stay pending: from the
	// policy resolve to the bind that follows the sandbox create. A first
	// start prepares the image and the MicroVM disk in between, which takes
	// about seven minutes on a cold computer (GAP-0636); a pending
	// registration authorizes nothing, so the margin costs no exposure.
	PendingTTL = 30 * time.Minute
	// LiveLease is how long a bound registration authorizes relayed calls
	// after its daemon last reported the sandbox running (at bind, then
	// every policy poll, 60 s). A registration whose daemon stopped
	// reporting counts as stopped.
	LiveLease = 5 * time.Minute
	// RevokedTelemetryWindow keeps a policy-revoked registration available
	// for the daemon's final lifecycle records after it reports deletion.
	RevokedTelemetryWindow = 10 * time.Minute
	// MaxEntriesPerUID caps one uid's registrations; the oldest tombstones
	// are evicted first, never a live entry.
	MaxEntriesPerUID = 1024
)

// Registration is one sandbox a user's daemon registered with the managed
// gateway, kept under <DataDir>/sandbox/registrations/<uid>.json.
type Registration struct {
	V  int    `json:"v"`
	ID string `json:"id"`
	// UID and UserName are the peer's at registration (HostUser).
	UID      int    `json:"uid"`
	UserName string `json:"user_name"`
	// SubjectKey is DigestPrefix + HMAC over "v1|uid|account|sid": kernel
	// and account-database facts only, keyed like the redaction
	// identifiers. A differing key (recycled uid, renamed account) revokes
	// the registration.
	SubjectKey string `json:"subject_key"`
	// FactsDigest is DigestPrefix + HMAC over the directory facts the
	// profile match used (principal, directory, tenant, groups, verified or
	// provisional). A change triggers a re-match, never a refusal.
	FactsDigest string `json:"facts_digest"`
	// Profile is the matched guardrail profile; "" = openshell.admin alone.
	Profile string `json:"profile"`
	// CreateProfile is the profile the sandbox was created under (the
	// verified match at resolve). A re-match to another profile runs the
	// sandbox under that profile's floor tightened by this one's, so a
	// profile-assignment change tightens a running sandbox and never
	// loosens it (GAP-0242). Nil for a registration made before 1.0.3 or
	// under a provisional match: the next verified re-match sets it.
	CreateProfile *string `json:"create_profile,omitempty"`
	// The member names make hashed meet profiles resolvable after a restart.
	// CreateProfileMembers is pinned with CreateProfile; ProfileMembers moves
	// with Profile on a verified re-match. Empty for a single profile.
	CreateProfileMembers []string `json:"create_profile_members,omitempty"`
	ProfileMembers       []string `json:"profile_members,omitempty"`
	ProfileMatch         string   `json:"profile_match"`
	MatchedGroup         string   `json:"matched_group,omitempty"`
	ProfileDigest        string   `json:"profile_digest"`
	// Generation is the host config generation at resolve (admin-only).
	Generation uint64 `json:"generation"`
	// EffectiveDigest is packs.Effective.Digest(), the digest users see.
	EffectiveDigest string `json:"effective_digest"`
	Provisional     bool   `json:"provisional"`
	Connector       string `json:"connector"`
	Harness         string `json:"harness"`
	HarnessVersion  string `json:"harness_version"`
	HookContract    string `json:"hook_contract"`
	TamperTier      string `json:"tamper_tier"`
	// MCPKept and MCPSkipped are the user's MCP servers the resolve brought
	// along and left out, with the reason (organization_block or
	// asset_policy), so an administrator can see what a sandbox got
	// (GAP-0554). Names only; no server definition is kept.
	MCPKept    []string               `json:"mcp_kept,omitempty"`
	MCPSkipped []sandboxrelay.MCPSkip `json:"mcp_skipped,omitempty"`
	// WorkdirMode is always copy on managed hosts in v1.
	WorkdirMode string `json:"workdir_mode"`
	ProjectReal string `json:"project_real"`
	Driver      string `json:"driver"`
	// DriverReason is why the sandbox runs on Driver (openshell.DriverReason*:
	// configured, kvm_available, or the KVM probe's reason when the docker
	// fallback replaced the MicroVM driver).
	DriverReason  string    `json:"driver_reason,omitempty"`
	OpenShell     string    `json:"openshell_version"`
	InstallMode   string    `json:"install_mode"`
	SandboxID     string    `json:"sandbox_id,omitempty"`
	SandboxName   string    `json:"sandbox_name,omitempty"`
	BindingID     string    `json:"binding_id,omitempty"`
	State         string    `json:"state"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	// PolicyAt is when a re-match last changed the registration's policy
	// (match, effective digest or floor); zero until one does, and then the
	// policy is the one resolved at CreatedAt (PolicyUpdatedAt).
	PolicyAt time.Time `json:"policy_at,omitzero"`
	BoundAt  time.Time `json:"bound_at,omitzero"`
	// GuestWatch marks registrations bound by this build. Registrations bound
	// before the upgrade to 1.0.2 (for example by 1.0.1) are not watched;
	// re-create those sandboxes after the upgrade to bring them under the
	// signal. Root-owned attestation in a later release replaces this signal.
	GuestWatch bool `json:"guest_watch,omitempty"`
	// GuestSeenAt is the gateway receipt time of the first accepted lifecycle
	// or egress record after bind. It ends this registration's watch.
	GuestSeenAt time.Time `json:"guest_seen_at,omitzero"`
	// SeenAt is when the daemon last reported the sandbox running; the
	// LiveLease counts from it (from BoundAt before the first report).
	SeenAt    time.Time `json:"seen_at,omitzero"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	// SessionAt is when the sandbox last started a new session: the running
	// report that followed a stop (Report). Zero while it runs the session
	// it was bound in (SessionStart).
	SessionAt time.Time `json:"session_at,omitzero"`
}

// Decision is one saved decision, kept under
// <DataDir>/sandbox/decisions/<uid>.json. Saved decisions are capped by the
// floor at every resolve.
type Decision struct {
	V            int           `json:"v"`
	ID           string        `json:"id"`
	Registration string        `json:"registration"`
	Kind         string        `json:"kind"`
	Host         string        `json:"host"`
	Scope        string        `json:"scope"`
	Actor        DecisionActor `json:"actor"`
	CreatedAt    time.Time     `json:"created_at"`
}

// DecisionActor is the person who made a decision.
type DecisionActor struct {
	UID           int    `json:"uid"`
	PrincipalHash string `json:"principal_hash,omitempty"`
}

// DecisionRefusedError is a decision the floor does not allow: Rule names
// the floor key that refuses it, Message is the user text.
type DecisionRefusedError struct {
	Rule    string
	Message string
}

func (e *DecisionRefusedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "sandbox decision refused by " + e.Rule + ": " + e.Message
}
