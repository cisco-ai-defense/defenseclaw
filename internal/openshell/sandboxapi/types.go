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

package sandboxapi

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// REST paths, all on the daemon's main API port.
const (
	PathPrefix        = "/api/v1/sandbox/"
	PathStatus        = "/api/v1/sandbox/status"
	PathSandboxes     = "/api/v1/sandbox/sandboxes"
	PathApprovals     = "/api/v1/sandbox/approvals"
	PathActivity      = "/api/v1/sandbox/activity"
	PathEgressUnblock = "/api/v1/sandbox/egress/unblock"
	PathPolicyExplain = "/api/v1/sandbox/policy/explain"
)

// ClientHeader is the CSRF header every mutating request carries, and
// ClientName the value the DefenseClaw CLI sends.
const (
	ClientHeader = "X-DefenseClaw-Client"
	ClientName   = "defenseclaw-sandbox"
)

// Status is GET /api/v1/sandbox/status: the sandbox subsystem as a whole.
type Status struct {
	// Enabled mirrors openshell.enabled.
	Enabled bool `json:"enabled"`
	// Available reports that the daemon is connected to a supported local
	// OpenShell gateway; Reason says why not.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Gateway describes the OpenShell gateway the daemon drives.
	Gateway *Gateway `json:"gateway,omitempty"`
	// IngressAddr and EgressAddr are the DefenseClaw listeners sandboxes
	// reach through host.openshell.internal.
	IngressAddr string `json:"ingress_addr,omitempty"`
	EgressAddr  string `json:"egress_addr,omitempty"`
	// Pack and Profile are the configured defaults (no run flags).
	Pack    string      `json:"pack,omitempty"`
	Profile string      `json:"profile,omitempty"`
	Admin   AdminStatus `json:"admin"`
	// Sandboxes counts the DefenseClaw sandboxes; Running those Ready.
	Sandboxes        int       `json:"sandboxes"`
	Running          int       `json:"running"`
	PendingApprovals int       `json:"pending_approvals"`
	LastReconcile    time.Time `json:"last_reconcile,omitzero"`
}

// Gateway is the OpenShell gateway the daemon is connected to.
type Gateway struct {
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	Workspace string `json:"workspace"`
	Version   string `json:"version,omitempty"`
	Healthy   bool   `json:"healthy"`
}

// AdminStatus says whether openshell.admin constrains sandboxes and how far
// it binds the user.
type AdminStatus struct {
	Configured bool `json:"configured"`
	// Authority is "authoritative" (managed_enterprise) or "advisory".
	Authority string `json:"authority"`
	Detail    string `json:"detail,omitempty"`
}

// CreateRequest is POST /api/v1/sandbox/sandboxes. Secret values (LLM and
// --credential values) are handed to OpenShell as provider credentials and
// never stored or echoed by the daemon.
type CreateRequest struct {
	// Name is the sandbox name; empty generates dc-<harness>-<repo>-<rand4>.
	Name string `json:"name,omitempty"`
	// Harness is the connector to run (claudecode, codex).
	Harness string `json:"harness"`
	// Project is the absolute host path of the launch folder. In mount mode
	// the daemon validates and mounts it; in copy mode it only labels the
	// sandbox (the CLI stages and uploads the copy after create).
	Project string `json:"project"`
	// Run flags that take part in policy resolution (see packs.Flags).
	Pack      string   `json:"pack,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Copy      bool     `json:"copy,omitempty"`
	Safe      bool     `json:"safe,omitempty"`
	Yolo      bool     `json:"yolo,omitempty"`
	Context   []string `json:"context,omitempty"`
	Unmask    []string `json:"unmask,omitempty"`
	HostPorts []int    `json:"host_ports,omitempty"`
	NoMCP     bool     `json:"no_mcp,omitempty"`
	Learn     bool     `json:"learn,omitempty"`
	CPU       string   `json:"cpu,omitempty"`
	Memory    string   `json:"memory,omitempty"`
	// NoSnapshot skips the pre-session snapshot of a mounted project, which
	// also disables undo for this session.
	NoSnapshot bool `json:"no_snapshot,omitempty"`
	// NoBuild refuses to build a missing overlay image instead of building
	// (and hook-verifying) it inside the request.
	NoBuild bool `json:"no_build,omitempty"`
	// LLM is the harness model credential the user consented to share.
	LLM *LLMCredential `json:"llm,omitempty"`
	// Credentials are --credential NAME=host bindings.
	Credentials []CredentialBinding `json:"credentials,omitempty"`
	// Env adds non-secret environment variables. DefenseClaw, proxy and
	// loader variables are refused.
	Env map[string]string `json:"env,omitempty"`
}

// LLMCredential selects one of the harness's provider profiles and carries
// its secret values keyed by the profile's environment variable names.
type LLMCredential struct {
	// Profile is a provider profile ID the harness supports, for example
	// defenseclaw-anthropic.
	Profile string `json:"profile"`
	// Credentials maps the profile's env var names to secret values.
	Credentials   map[string]string `json:"credentials"`
	BedrockRegion string            `json:"bedrock_region,omitempty"`
}

// CredentialBinding is `--credential NAME=host[:port]`: the sandbox gets a
// placeholder in NAME that OpenShell substitutes (in headers and query
// strings) only on requests to Host:Port.
type CredentialBinding struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Host  string `json:"host"`
	// Port defaults to 443.
	Port int `json:"port,omitempty"`
}

// Sandbox is one DefenseClaw sandbox as the daemon sees it.
type Sandbox struct {
	Name string `json:"name"`
	// ID is the OpenShell sandbox id.
	ID      string `json:"id,omitempty"`
	Harness string `json:"harness"`
	// HarnessName is the display name (Claude Code).
	HarnessName string `json:"harness_name,omitempty"`
	// Phase is the OpenShell phase, lowercased (ready, stopped, ...), or
	// "missing" when DefenseClaw still holds state for a sandbox OpenShell
	// no longer has.
	Phase       string `json:"phase"`
	Pack        string `json:"pack,omitempty"`
	PackDigest  string `json:"pack_digest,omitempty"`
	Profile     string `json:"profile"`
	NetworkMode string `json:"network_mode,omitempty"`
	Approvals   string `json:"approvals,omitempty"`
	Yolo        bool   `json:"yolo"`
	// WorkdirMode is mount or copy.
	WorkdirMode string `json:"workdir_mode"`
	Project     string `json:"project,omitempty"`
	// Workdir is the project's path inside the sandbox.
	Workdir        string    `json:"workdir,omitempty"`
	Image          string    `json:"image,omitempty"`
	ImageID        string    `json:"image_id,omitempty"`
	HarnessVersion string    `json:"harness_version,omitempty"`
	HookContract   string    `json:"hook_contract,omitempty"`
	TamperTier     string    `json:"tamper_tier,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitzero"`
	// StartedAt is the last transition to ready seen by this daemon.
	StartedAt     time.Time `json:"started_at,omitzero"`
	UptimeSeconds int64     `json:"uptime_seconds,omitempty"`
	ExitCode      *int32    `json:"exit_code,omitempty"`
	// Launch is what the CLI needs to start the harness in the sandbox.
	Launch    Launch       `json:"launch"`
	Hooks     HookCoverage `json:"hooks"`
	Endpoints []Endpoint   `json:"endpoints,omitempty"`
	Egress    EgressStats  `json:"egress"`
	// PendingApprovals counts asks waiting for the user.
	PendingApprovals int `json:"pending_approvals"`
	// Workspace is the mount-mode banner view.
	Workspace *WorkspaceSummary `json:"workspace,omitempty"`
	// Snapshot says whether undo is available.
	Snapshot *SnapshotInfo `json:"snapshot,omitempty"`
	// Violations are the non-fatal policy clamps applied at create.
	Violations []Violation `json:"violations,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	// Orphaned marks an OpenShell sandbox with DefenseClaw labels but no
	// DefenseClaw binding; its hooks cannot authenticate.
	Orphaned bool `json:"orphaned,omitempty"`
}

// Launch carries the harness launch inputs (harness.LaunchOptions).
type Launch struct {
	Yolo              bool   `json:"yolo"`
	CredentialProfile string `json:"credential_profile,omitempty"`
	BedrockRegion     string `json:"bedrock_region,omitempty"`
}

// HookCoverage reports hook traffic from the sandbox.
type HookCoverage struct {
	LastHookAt time.Time `json:"last_hook_at,omitzero"`
	LastOTLPAt time.Time `json:"last_otlp_at,omitzero"`
	// HookRequests counts authenticated hook posts; ToolCalls the
	// pre-tool decisions among them, ToolBlocked those denied.
	HookRequests int64 `json:"hook_requests"`
	ToolCalls    int64 `json:"tool_calls"`
	ToolBlocked  int64 `json:"tool_blocked"`
	// LastBlocked is the reason of the most recent denied tool call.
	LastBlocked string `json:"last_blocked,omitempty"`
	// Silent is set while the harness is active without hook traffic.
	Silent      bool      `json:"silent,omitempty"`
	SilentSince time.Time `json:"silent_since,omitzero"`
}

// Endpoint is an OpenShell EndpointStatus: the last network result of a
// configured credentialed endpoint (a credential that never bound shows up
// here as credential_unavailable).
type Endpoint struct {
	Host       string   `json:"host"`
	Ports      []uint32 `json:"ports,omitempty"`
	Path       string   `json:"path,omitempty"`
	Result     string   `json:"result"`
	ReportedAt string   `json:"reported_at,omitempty"`
}

// EgressStats totals the proxy's view of one sandbox.
type EgressStats struct {
	Destinations int   `json:"destinations"`
	Blocked      int   `json:"blocked"`
	BytesUp      int64 `json:"bytes_up"`
	BytesDown    int64 `json:"bytes_down"`
}

// WorkspaceSummary is the launch-banner view of a mounted project.
type WorkspaceSummary struct {
	Project   string   `json:"project"`
	Hidden    []string `json:"hidden,omitempty"`
	Protected []string `json:"protected,omitempty"`
	Context   []string `json:"context,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// SnapshotInfo describes the pre-session snapshot.
type SnapshotInfo struct {
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UndoneAt  time.Time `json:"undone_at,omitzero"`
}

// Violation is a requested setting or action the sandbox policy refused or
// clamped (packs.Violation).
type Violation struct {
	Key        string `json:"key"`
	Source     string `json:"source"`
	Attempted  string `json:"attempted"`
	Enforced   string `json:"enforced,omitempty"`
	Constraint string `json:"constraint"`
	Fatal      bool   `json:"fatal,omitempty"`
	// Admin marks an openshell.admin constraint ("blocked by your
	// organization's DefenseClaw policy").
	Admin   bool   `json:"admin,omitempty"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// DeleteRequest is the optional body of DELETE /sandboxes/{name}.
type DeleteRequest struct {
	// KeepSnapshot keeps the pre-session snapshot (and so undo) after the
	// sandbox is gone.
	KeepSnapshot bool `json:"keep_snapshot,omitempty"`
}

// DeleteResponse reports what DELETE removed.
type DeleteResponse struct {
	Name      string   `json:"name"`
	Deleted   bool     `json:"deleted"`
	Providers []string `json:"providers,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// StartRequest is POST /sandboxes/{name}/start.
type StartRequest struct {
	// NoSnapshot keeps the previous snapshot instead of taking a fresh one
	// for the new session.
	NoSnapshot bool `json:"no_snapshot,omitempty"`
}

// UndoRequest is POST /sandboxes/{name}/undo. Undo needs the sandbox
// stopped: Stop stops a running one first, Restart starts it again after.
type UndoRequest struct {
	Preview  bool `json:"preview,omitempty"`
	KeepRefs bool `json:"keep_refs,omitempty"`
	Stop     bool `json:"stop,omitempty"`
	Restart  bool `json:"restart,omitempty"`
}

// UndoResponse carries the workspace result.
type UndoResponse struct {
	Name      string                  `json:"name"`
	Result    *workspace.UndoResult   `json:"result"`
	Stopped   bool                    `json:"stopped,omitempty"`
	Restarted bool                    `json:"restarted,omitempty"`
	Summary   string                  `json:"summary,omitempty"`
	Review    *workspace.ReviewReport `json:"review,omitempty"`
}

// ReviewRequest is POST /sandboxes/{name}/review.
type ReviewRequest struct {
	// Diff adds the unified diff of the session.
	Diff bool `json:"diff,omitempty"`
}

// ReviewResponse carries the end-of-session review.
type ReviewResponse struct {
	Name     string                  `json:"name"`
	Report   *workspace.ReviewReport `json:"report"`
	Summary  string                  `json:"summary"`
	RiskLine string                  `json:"risk_line,omitempty"`
	Diff     string                  `json:"diff,omitempty"`
}

// Workspace operations the CLI reports (the copy-mode steps it runs).
const (
	WorkspaceUpload = "upload"
	WorkspacePull   = "pull"
)

// WorkspaceReport is POST /sandboxes/{name}/workspace: a copy-mode
// workspace step the CLI ran (upload, or pull with apply/branch/patch), so
// the daemon records it with the sandbox's identity. Counts are optional.
type WorkspaceReport struct {
	Operation string `json:"operation"`
	// Result is applied, completed, failed, no_change, partial or skipped
	// (empty: the operation's default).
	Result       string `json:"result,omitempty"`
	FailureClass string `json:"failure_class,omitempty"`
	// PullMode is apply, branch or patch (pull only).
	PullMode     string   `json:"pull_mode,omitempty"`
	FileCount    *int64   `json:"file_count,omitempty"`
	LinesAdded   *int64   `json:"lines_added,omitempty"`
	LinesRemoved *int64   `json:"lines_removed,omitempty"`
	FlaggedCount *int64   `json:"flagged_count,omitempty"`
	ByteCount    *int64   `json:"byte_count,omitempty"`
	Paths        []string `json:"paths,omitempty"`
}

// Approval kinds and statuses.
const (
	ApprovalKindNetworkRule = "network_rule"
	ApprovalKindHostPort    = "host_port"

	ApprovalPending  = "pending"
	ApprovalQueued   = "queued"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalFailed   = "failed"
)

// Approval is one rare ask: an OpenShell draft proposal triage would not
// decide on its own.
type Approval struct {
	ID      string `json:"id"`
	Sandbox string `json:"sandbox"`
	ChunkID string `json:"chunk_id"`
	Kind    string `json:"kind"`
	// Host and Port name the endpoint that decided the ask; Endpoints are
	// all of them, and approving opens every one.
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	// Binary is the executable whose denied connection drafted the
	// proposal; Binaries are the executables the rule would apply to.
	Binary    string             `json:"binary,omitempty"`
	Binaries  []string           `json:"binaries,omitempty"`
	RuleName  string             `json:"rule_name,omitempty"`
	Endpoints []ApprovalEndpoint `json:"endpoints,omitempty"`
	// AllowedIPs are the addresses the destinations may resolve to. When
	// set, they replace OpenShell's own private-address check.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// Risky marks private, IP-literal or host-local reach.
	Risky bool `json:"risky,omitempty"`
	// Reason is the triage reason; Rationale and SecurityNotes come from
	// the OpenShell policy advisor.
	Reason        string    `json:"reason"`
	Rationale     string    `json:"rationale,omitempty"`
	SecurityNotes string    `json:"security_notes,omitempty"`
	HitCount      int       `json:"hit_count,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	ResolvedAt    time.Time `json:"resolved_at,omitzero"`
}

// ApprovalEndpoint is one destination of an ask.
type ApprovalEndpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Approval decisions.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

// ApprovalDecision is POST /approvals/{id}.
type ApprovalDecision struct {
	Decision string `json:"decision"`
	// Always keeps the decision for future sandboxes (approve: the hosts
	// join openshell.egress.allow; reject: openshell.egress.block).
	Always bool   `json:"always,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ApprovalResult is the outcome of a decision. Approvals are applied in
// batches at hook-quiescent moments, so an approval is usually "queued".
type ApprovalResult struct {
	Approval  Approval `json:"approval"`
	Persisted bool     `json:"persisted,omitempty"`
	Message   string   `json:"message,omitempty"`
}

// UnblockRequest is POST /egress/unblock.
type UnblockRequest struct {
	Host string `json:"host"`
	// Sandbox scopes the unblock to one sandbox; empty requires Always.
	Sandbox string `json:"sandbox,omitempty"`
	// Always keeps the unblock for every sandbox (openshell.egress.allow).
	Always bool `json:"always,omitempty"`
}

// UnblockResponse reports an applied unblock.
type UnblockResponse struct {
	Host    string `json:"host"`
	Sandbox string `json:"sandbox,omitempty"`
	// Scope is "sandbox" or "always".
	Scope     string `json:"scope"`
	Persisted bool   `json:"persisted"`
	Message   string `json:"message"`
}

// ExplainRequest is the query of GET /policy/explain: either Sandbox (the
// posture a sandbox runs with, against the current config) or run flags.
type ExplainRequest struct {
	Sandbox string   `json:"sandbox,omitempty"`
	Harness string   `json:"harness,omitempty"`
	Pack    string   `json:"pack,omitempty"`
	Profile string   `json:"profile,omitempty"`
	Project string   `json:"project,omitempty"`
	Copy    bool     `json:"copy,omitempty"`
	Safe    bool     `json:"safe,omitempty"`
	Yolo    bool     `json:"yolo,omitempty"`
	Unmask  []string `json:"unmask,omitempty"`
}

// Explain is the resolved sandbox posture with provenance.
type Explain struct {
	Pack        string      `json:"pack"`
	PackSource  string      `json:"pack_source"`
	PackDigest  string      `json:"pack_digest"`
	Profile     string      `json:"profile"`
	NetworkMode string      `json:"network_mode"`
	Approvals   string      `json:"approvals"`
	Admin       AdminStatus `json:"admin"`
	Settings    []Setting   `json:"settings"`
	Violations  []Violation `json:"violations,omitempty"`
}

// Setting is one resolved key and where its value came from.
type Setting struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	Origin    string `json:"origin"`
	Requested string `json:"requested,omitempty"`
}

// Activity kinds.
const (
	ActivityEgressAllowed     = "egress.allowed"
	ActivityEgressBlocked     = "egress.blocked"
	ActivityEgressLargeUpload = "egress.large_upload"
	ActivityEgressUnblocked   = "egress.unblocked"
	ActivityApprovalRequested = "approval.requested"
	ActivityApprovalResolved  = "approval.resolved"
	ActivityToolBlocked       = "tool.blocked"
	ActivityLifecycle         = "sandbox.lifecycle"
	ActivityFinding           = "finding"
	ActivityWorkspace         = "workspace"
	// ActivityDropped tells a slow subscriber that events were skipped.
	ActivityDropped = "dropped"
)

// Activity sources for egress events.
const (
	SourceProxy     = "dc-egress-proxy"
	SourceOpenShell = "openshell"
)

// ActivityEvent is one item of the live activity feed.
type ActivityEvent struct {
	// Seq increases by one per event; resume with ?since=<seq>.
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Sandbox string    `json:"sandbox,omitempty"`
	// Egress fields.
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Method      string `json:"method,omitempty"`
	Source      string `json:"source,omitempty"`
	Category    string `json:"category,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Unblockable bool   `json:"unblockable,omitempty"`
	BytesUp     int64  `json:"bytes_up,omitempty"`
	BytesDown   int64  `json:"bytes_down,omitempty"`
	// Approval and hook fields.
	ApprovalID string `json:"approval_id,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Event      string `json:"event,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Severity   string `json:"severity,omitempty"`
	// Reason is the machine-readable cause, Message the display line.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ActivityQuery selects the activity stream.
type ActivityQuery struct {
	Sandbox string
	// Since replays buffered events with a larger Seq first.
	Since uint64
	// Follow keeps the stream open (SSE); otherwise the buffered events
	// are returned as one JSON array.
	Follow bool
}
