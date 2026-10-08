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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	// PathPolicyTest is POST: what a sandbox's egress policy decides for
	// destinations (PolicyTestRequest).
	PathPolicyTest = "/api/v1/sandbox/policy/test"
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
	// StartedAt is when the daemon's sandbox subsystem started. Nothing
	// keeps the sandboxes' counters (HookCoverage, EgressStats) across a
	// restart: they count from then, so a session that began earlier knows
	// its counts cover only the time since.
	StartedAt time.Time `json:"started_at,omitzero"`
	// DaemonUID is the uid the daemon runs as (unset where there is none):
	// it drives the user's OpenShell gateway and mounts the user's files, so
	// the doctor checks it is the user's own.
	DaemonUID *int `json:"daemon_uid,omitempty"`
	// DockerGroupMissing reports that the daemon's user is in the docker
	// group but the daemon started before that, so it cannot reach Docker
	// until it restarts (Linux).
	DockerGroupMissing bool `json:"docker_group_missing,omitempty"`
	// TelemetryFailures counts the sandbox telemetry records the recorder
	// refused since the daemon started; TelemetryError is the last refusal.
	TelemetryFailures int64  `json:"telemetry_failures,omitempty"`
	TelemetryError    string `json:"telemetry_error,omitempty"`
}

// Gateway is the OpenShell gateway the daemon is connected to.
type Gateway struct {
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	Workspace string `json:"workspace"`
	Version   string `json:"version,omitempty"`
	Healthy   bool   `json:"healthy"`
	// Driver is the compute driver the gateway runs: "docker", or "vm"
	// (OpenShell's MicroVM driver, which mounts no host folders, so every
	// sandbox on it works on a copy). Empty from a daemon older than the
	// field, which drove docker only.
	Driver string `json:"driver,omitempty"`
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
	// Name is the sandbox name, at most openshell.MaxSandboxNameLen
	// characters; empty generates <repo>-<rand4>.
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
	// ProcessTree turns the process tree on for this sandbox (the pack's
	// observe.process_tree turns it on for every one).
	ProcessTree bool `json:"process_tree,omitempty"`
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
	// TimeZone is the IANA time zone of the machine the run starts on
	// ("America/New_York"); the sandbox's harnesses and shells run in it
	// where the image has its zone file (openshell.EnvHostTimeZone), and
	// on UTC without it.
	TimeZone string `json:"time_zone,omitempty"`
	// RepoPolicyDigest is the digest of the project's repository policy
	// (Explain.RepoPolicy) the client resolved the run with, NoRepoPolicy
	// when it had none. The daemon reads the file itself and refuses the
	// create when it changed since; empty skips the check.
	RepoPolicyDigest string `json:"repo_policy_digest,omitempty"`
}

// NoRepoPolicy is CreateRequest.RepoPolicyDigest for a project without a
// repository policy.
const NoRepoPolicy = "none"

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

// CredentialGrant is a --credential binding a sandbox holds: the
// placeholder's name and the host and port it resolves at (never the
// value).
type CredentialGrant struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

// Sandbox is one DefenseClaw sandbox as the daemon sees it.
type Sandbox struct {
	Name string `json:"name"`
	// ID is the OpenShell sandbox id.
	ID      string `json:"id,omitempty"`
	Harness string `json:"harness"`
	// HarnessName is the display name (Claude Code).
	HarnessName string `json:"harness_name,omitempty"`
	// Phase is the OpenShell phase, lowercased (ready, stopped, ...),
	// "missing" when DefenseClaw still holds state for a sandbox OpenShell
	// no longer has, or "deleted" for a sandbox that is gone but whose
	// pre-session snapshot is kept (delete --keep-snapshot, or deleted
	// outside DefenseClaw): only undo, review and delete apply to it.
	Phase string `json:"phase"`
	// PhaseReason is why the sandbox is in the error phase, in words (its
	// MicroVM's disk is full, what OpenShell says), when it is.
	PhaseReason string `json:"phase_reason,omitempty"`
	Pack        string `json:"pack,omitempty"`
	PackDigest  string `json:"pack_digest,omitempty"`
	Profile     string `json:"profile"`
	NetworkMode string `json:"network_mode,omitempty"`
	Approvals   string `json:"approvals,omitempty"`
	Yolo        bool   `json:"yolo"`
	// ProcessTree reports that the sandbox's processes are sampled while it
	// runs (GET /sandboxes/{name}/processes, `sandbox ps`).
	ProcessTree bool `json:"process_tree,omitempty"`
	// SessionYolo reports whether the session running now was launched in
	// skip-permissions mode: Launch.Yolo as it was when the sandbox last
	// became ready. Yolo and Launch.Yolo are what the next launch gets;
	// after a policy change (openshell.admin.allow_yolo: false, say) the
	// two differ until the session ends, and Warnings says so. False while
	// the sandbox is not running.
	SessionYolo bool `json:"session_yolo,omitempty"`
	// WorkdirMode is mount or copy.
	WorkdirMode string `json:"workdir_mode"`
	Project     string `json:"project,omitempty"`
	// Workdir is the project's path inside the sandbox.
	Workdir string `json:"workdir,omitempty"`
	Image   string `json:"image,omitempty"`
	ImageID string `json:"image_id,omitempty"`
	// RunImage and RunImageID are the image the sandbox runs when that is
	// not Image: on the MicroVM (vm) driver, the image its per-run harness
	// files are baked into, or an alias of Image under a name no registry
	// serves. Empty on the docker driver.
	RunImage       string    `json:"run_image,omitempty"`
	RunImageID     string    `json:"run_image_id,omitempty"`
	HarnessVersion string    `json:"harness_version,omitempty"`
	HookContract   string    `json:"hook_contract,omitempty"`
	TamperTier     string    `json:"tamper_tier,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitzero"`
	// StartedAt is the last transition to ready seen by this daemon.
	StartedAt time.Time `json:"started_at,omitzero"`
	// Session counts the sandbox's sessions: it goes up each time
	// DefenseClaw sees the sandbox become ready. An accept names the session
	// whose changes were reviewed (AcceptRequest.Session).
	Session       int    `json:"session,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	ExitCode      *int32 `json:"exit_code,omitempty"`
	// Launch is what the CLI needs to start the harness in the sandbox.
	Launch Launch `json:"launch"`
	// Credentials are the sandbox's --credential bindings (--github-write's
	// among them), and HostPorts the host loopback ports it may ask to
	// reach: grants it was created with, which it keeps when resumed.
	Credentials []CredentialGrant `json:"credentials,omitempty"`
	HostPorts   []int             `json:"host_ports,omitempty"`
	Hooks       HookCoverage      `json:"hooks"`
	Endpoints   []Endpoint        `json:"endpoints,omitempty"`
	Egress      EgressStats       `json:"egress"`
	// PendingApprovals counts asks waiting for the user.
	PendingApprovals int `json:"pending_approvals"`
	// Workspace is the mount-mode banner view.
	Workspace *WorkspaceSummary `json:"workspace,omitempty"`
	// MCP is the banner view of the sandbox's MCP servers.
	MCP *MCPSummary `json:"mcp,omitempty"`
	// Snapshot says whether undo is available.
	Snapshot *SnapshotInfo `json:"snapshot,omitempty"`
	// Violations are the non-fatal policy clamps applied at create.
	Violations []Violation `json:"violations,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	// Orphaned marks an OpenShell sandbox with DefenseClaw labels but no
	// DefenseClaw binding; its hooks cannot authenticate.
	Orphaned bool `json:"orphaned,omitempty"`
	// NestedRepos are the git repositories the nested-repository guard
	// found in a mounted project during the current session.
	NestedRepos []NestedRepo `json:"nested_repos,omitempty"`
}

// NestedRepo is one repository that appeared inside a mounted project while
// the sandbox ran: a .git entry (quarantined by renaming it) or a gitlink
// added to the project's index (reported only).
type NestedRepo struct {
	// Kind is "repository" or "gitlink".
	Kind string `json:"kind"`
	// Path is the project-relative .git entry or gitlink.
	Path string `json:"path"`
	// Quarantined is the project-relative name the .git entry was renamed
	// to; empty for gitlinks and failed quarantines.
	Quarantined string `json:"quarantined,omitempty"`
	// Also are the further names the same repository creation was
	// quarantined under (git init recreating the .git the guard renamed
	// while it wrote it): one creation is one entry.
	Also  []string  `json:"also,omitempty"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
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
	// pre-tool decisions among them, ToolBlocked those denied, ToolAsked
	// those DefenseClaw asked the user to confirm in the harness.
	HookRequests int64 `json:"hook_requests"`
	ToolCalls    int64 `json:"tool_calls"`
	ToolBlocked  int64 `json:"tool_blocked"`
	ToolAsked    int64 `json:"tool_asked,omitempty"`
	// PromptBlocked counts the submitted prompts DefenseClaw blocked
	// (UserPromptSubmit and each harness's spelling of it).
	PromptBlocked int64 `json:"prompt_blocked,omitempty"`
	// Events counts the hook verdicts per hook event, under the name the
	// harness sends (PreToolUse, preToolUse, tool.execute.before, ...).
	// Their sum can be below HookRequests: a post refused before a verdict
	// (malformed, outside the hook contract) or answered again from a
	// retried post's first answer has no event. The names come from the
	// workload, so a sandbox keeps at most MaxHookEvents of them; verdicts
	// for further names count in OtherEvents.
	Events      map[string]int64 `json:"events,omitempty"`
	OtherEvents int64            `json:"other_events,omitempty"`
	// LastBlocked is the plain reason of the most recent denied tool call
	// (rule ID, title and what to do instead; never matched content).
	LastBlocked string `json:"last_blocked,omitempty"`
	// Tampered counts tool calls that ran without a DefenseClaw verdict: a
	// post-tool event (PostToolUse, ...) whose pre-tool event was denied or
	// never arrived.
	Tampered     int64     `json:"tampered,omitempty"`
	LastTamperAt time.Time `json:"last_tamper_at,omitzero"`
	// Silent is set while the harness is active without hook traffic.
	Silent      bool      `json:"silent,omitempty"`
	SilentSince time.Time `json:"silent_since,omitzero"`
	// OnSilence is what DefenseClaw does once the harness has worked for
	// SilenceAfter ("10m") without hook traffic: "stop" stops the sandbox
	// (a user-tier harness under the pack's hooks.on_silence: stop), "alert"
	// raises a finding and leaves it running. While the sandbox's policy is
	// not resolved, a user-tier harness gets the fail-closed "stop" after
	// "10m".
	OnSilence    string `json:"on_silence,omitempty"`
	SilenceAfter string `json:"silence_after,omitempty"`
	// HookFailed counts the authenticated hook posts DefenseClaw answered
	// with an error status (a refused route, the rate limit, a malformed
	// request). The hooks fail closed, so the harness did not do what each
	// of them was about. LastHookFailure is how the last one was answered,
	// for example "HTTP 429 Too Many Requests".
	HookFailed        int64     `json:"hook_failed,omitempty"`
	LastHookFailure   string    `json:"last_hook_failure,omitempty"`
	LastHookFailureAt time.Time `json:"last_hook_failure_at,omitzero"`
	// ModelKeyRejected says the model API rejected the sandbox's model
	// credential (Claude Code's StopFailure hook reported it) and how to
	// hand the sandbox a fresh key, until a turn ends normally or a start
	// hands it a new key. ModelKeyRejectedAt is the last rejection.
	ModelKeyRejected   string    `json:"model_key_rejected,omitempty"`
	ModelKeyRejectedAt time.Time `json:"model_key_rejected_at,omitzero"`
	// IngressRefused counts the hook connections and requests to the
	// DefenseClaw ingress that OpenShell refused (the sandbox's network
	// policy does not allow its port or path).
	IngressRefused       int64     `json:"ingress_refused,omitempty"`
	LastIngressRefusedAt time.Time `json:"last_ingress_refused_at,omitzero"`
	// Unreachable is set while the current session's hooks do not reach
	// DefenseClaw: they fail closed, so the harness can do nothing.
	// UnreachableReason says why DefenseClaw concluded that.
	Unreachable       bool      `json:"unreachable,omitempty"`
	UnreachableSince  time.Time `json:"unreachable_since,omitzero"`
	UnreachableReason string    `json:"unreachable_reason,omitempty"`
	// NoHookYet is set with Unreachable when the harness called its model
	// but DefenseClaw saw no hook request of the session at all, not even
	// a refused or unanswered one: no tool call is known to have been
	// blocked yet, so the warning opens with HooksNotReachedYetWarning
	// rather than HooksUnreachableWarning.
	NoHookYet bool `json:"no_hook_yet,omitempty"`
}

// MaxHookEvents bounds the hook event names HookCoverage.Events keeps for
// one sandbox. Every harness's hook contract has fewer events (Claude
// Code's, the largest, has 29).
const MaxHookEvents = 48

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

// EgressStats totals one sandbox's egress since the daemon started. Its
// counts are destinations, as the activity feed names them: Destinations
// those the sandbox reached, Blocked those refused at least once (by
// DefenseClaw's proxy, invalid destinations included, or by OpenShell), so
// a sandbox whose feed shows two ✗ destinations reports Blocked 2 however
// often each was tried. BlockedRequests counts the refused requests.
type EgressStats struct {
	Destinations    int `json:"destinations"`
	Blocked         int `json:"blocked"`
	BlockedRequests int `json:"blocked_requests"`
	// UpstreamFailed counts the allowed tunnels and requests the egress
	// proxy could not complete upstream (DestinationRow.Failed).
	UpstreamFailed int   `json:"upstream_failed,omitempty"`
	BytesUp        int64 `json:"bytes_up"`
	BytesDown      int64 `json:"bytes_down"`
	// ModelAPIs and ShadowAI count the AI destinations of the sandbox's
	// destinations view (GET /sandboxes/{name}/destinations): its model
	// provider and its harness's vendor, and the other AI APIs and
	// inference-shaped hosts it reached or tried to reach.
	ModelAPIs int `json:"model_apis,omitempty"`
	ShadowAI  int `json:"shadow_ai,omitempty"`
}

// Destination kinds (DestinationRow.Kind), in the order they are told apart.
// A row that is none of the AI kinds takes the egress category the proxy
// gave it (a feed category such as package_registry), else blocked or other.
const (
	// DestinationModelProvider: reached under the provider rule of the
	// sandbox's model provider (its model endpoint).
	DestinationModelProvider = "model_provider"
	// DestinationCredential: reached under the provider rule of one of the
	// sandbox's --credential bindings, its endpoint. The user bound a
	// credential there, so it is no shadow AI either.
	DestinationCredential = "credential"
	// DestinationHarnessVendor: an AI API of the harness's own vendor.
	DestinationHarnessVendor = "harness_vendor"
	// DestinationOtherAI: another catalogued AI provider (shadow AI).
	DestinationOtherAI = "other_ai_api"
	// DestinationUnknownAI: a host shaped like an inference endpoint the
	// catalog does not know (shadow AI).
	DestinationUnknownAI = "unknown_ai"
	// DestinationBlocked: only ever refused.
	DestinationBlocked = "blocked"
	// DestinationOther: anything else.
	DestinationOther = "other"
)

// ShadowAIKind reports whether a destination kind is shadow AI.
func ShadowAIKind(kind string) bool {
	return kind == DestinationOtherAI || kind == DestinationUnknownAI
}

// MaxDestinations bounds the rows a sandbox's destinations view keeps.
const MaxDestinations = 512

// Destinations is GET /sandboxes/{name}/destinations: every destination the
// sandbox reached or tried to reach, through DefenseClaw's egress proxy or
// OpenShell's own network boundary, since it was created (it survives daemon
// restarts and stops; a delete drops it), and the model calls OpenShell's
// inference route reported.
type Destinations struct {
	Name         string           `json:"name"`
	Harness      string           `json:"harness,omitempty"`
	Destinations []DestinationRow `json:"destinations"`
	Models       []ModelUse       `json:"models,omitempty"`
	// Dropped counts the destinations left out over MaxDestinations.
	Dropped int `json:"dropped,omitempty"`
}

// DestinationRow is one destination host of a sandbox.
type DestinationRow struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports,omitempty"`
	// Kind is a Destination* kind or an egress category.
	Kind string `json:"kind"`
	// Provider and Vendor name the AI provider the catalog matched (or
	// the OpenShell provider rule's), Category the egress proxy's category.
	Provider string `json:"provider,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Category string `json:"category,omitempty"`
	// Rule is the OpenShell policy rule that last allowed it.
	Rule string `json:"rule,omitempty"`
	// Sources are the boundaries that saw it: dc-egress-proxy, openshell.
	Sources []string `json:"sources"`
	// Connections counts the connections and requests OpenShell allowed,
	// Tunnels those the DefenseClaw proxy relayed; Refused and Blocked the
	// refusals of each. ModelTurns counts the model calls among OpenShell's
	// requests.
	Connections int64 `json:"connections,omitempty"`
	Tunnels     int64 `json:"tunnels,omitempty"`
	Refused     int64 `json:"refused,omitempty"`
	Blocked     int64 `json:"blocked,omitempty"`
	// Failed counts the tunnels and requests the proxy allowed and could
	// not complete upstream (the host refused or dropped the connection,
	// did not answer, or did not resolve); Tunnels does not count them.
	Failed     int64 `json:"failed,omitempty"`
	ModelTurns int64 `json:"model_turns,omitempty"`
	// BytesUp and BytesDown are what the proxy relayed.
	BytesUp   int64 `json:"bytes_up,omitempty"`
	BytesDown int64 `json:"bytes_down,omitempty"`
	// Binaries are the executables OpenShell named making the
	// connections (the last few), PID the last one's process. Both are what
	// the workload claims.
	Binaries []string `json:"binaries,omitempty"`
	PID      int      `json:"pid,omitempty"`
	// Lineage is PID's process and its parents, from the opt-in process
	// tree (observe.process_tree), when it knows the process.
	Lineage   []DestinationProcess `json:"lineage,omitempty"`
	FirstSeen time.Time            `json:"first_seen"`
	LastSeen  time.Time            `json:"last_seen"`
}

// DestinationProcess is one process of a destination's lineage.
type DestinationProcess struct {
	PID   int       `json:"pid"`
	PPID  int       `json:"ppid,omitempty"`
	Exe   string    `json:"exe,omitempty"`
	Comm  string    `json:"comm,omitempty"`
	Start time.Time `json:"start,omitzero"`
}

// ModelUse is a provider and model OpenShell's inference route reported
// model calls to.
type ModelUse struct {
	Provider string    `json:"provider,omitempty"`
	Model    string    `json:"model,omitempty"`
	Calls    int64     `json:"calls"`
	Failed   int64     `json:"failed,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// WorkspaceSummary is the launch-banner view of a mounted project.
type WorkspaceSummary struct {
	Project   string   `json:"project"`
	Hidden    []string `json:"hidden,omitempty"`
	Protected []string `json:"protected,omitempty"`
	Context   []string `json:"context,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// MCPSummary is the launch-banner view of a sandbox's MCP servers.
type MCPSummary struct {
	// Imported are the user's servers the run brought along.
	Imported []string `json:"imported,omitempty"`
	// LeftBehind are the user's servers that stayed out, with the reason.
	LeftBehind []MCPLeftBehind `json:"left_behind,omitempty"`
	// ProjectServers is the pack's mcp.project_servers: "block" (the
	// repository's own servers do not start) or "allow".
	ProjectServers string `json:"project_servers"`
	// Project are the servers the repository defines (.mcp.json,
	// .codex/config.toml).
	Project []string `json:"project,omitempty"`
}

// MCPLeftBehind is a server a run did not bring along.
type MCPLeftBehind struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// SnapshotInfo describes the pre-session snapshot.
type SnapshotInfo struct {
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UndoneAt  time.Time `json:"undone_at,omitzero"`
	// AcceptedAt is when the user kept the changes made on top of this
	// snapshot (POST /sandboxes/{name}/accept): the next start takes a new
	// snapshot, so an accepted session is the base of the next one. Zero
	// while nobody accepted them.
	AcceptedAt time.Time `json:"accepted_at,omitzero"`
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
	// sandbox is gone: the sandbox stays listed with phase "deleted" for
	// undo, review and a later delete, which drops the snapshot.
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
	// for the new session. Without it a start takes a fresh one only when
	// nothing would be lost: no snapshot yet, the last one was undone, the
	// folder did not change since it, or the user accepted the changes on
	// top of it (POST /sandboxes/{name}/accept); otherwise the snapshot of
	// the earlier session is kept, so undo still reverts its changes.
	NoSnapshot bool `json:"no_snapshot,omitempty"`
	// NewSnapshot takes a fresh snapshot even though the folder still holds
	// an earlier session's changes: they are accepted, and undo no longer
	// reverts them.
	NewSnapshot bool `json:"new_snapshot,omitempty"`
	// LLM is the model credential as the caller's environment holds it now
	// (secret values): when it is of the profile the sandbox was created
	// with and differs from the one its provider holds (a rotated or
	// renewed key), the start gives the provider the new one.
	LLM *LLMCredential `json:"llm,omitempty"`
}

// AcceptRequest is POST /sandboxes/{name}/accept: the user kept the changes
// a session made on top of a stopped mounted sandbox's snapshot (the
// end-of-session "Keep changes?" answered yes, --yes, or on_exit: keep), so
// the next start takes a new snapshot instead of keeping this one for undo.
type AcceptRequest struct {
	// Snapshot is the created_at of the snapshot the changes were reviewed
	// against: the daemon refuses with 409 conflict when the sandbox's
	// snapshot is another one by now. Zero accepts the current one.
	Snapshot time.Time `json:"snapshot_created_at,omitzero"`
	// Session is the sandbox's Session when the changes were reviewed: the
	// daemon refuses with 409 conflict when the sandbox was started again
	// since, which keeps the snapshot with that session's unreviewed
	// changes on top. Zero skips the check.
	Session int `json:"session,omitempty"`
}

// RunState is how a sandbox's latest detached run (`sandbox run --detach`)
// stands. A kept run log (RunLog.State) is RunExited or RunInterrupted.
type RunState string

const (
	// RunNone: the sandbox has no detached run.
	RunNone RunState = "none"
	// RunRunning: the run is still going.
	RunRunning RunState = "running"
	// RunExited: the run had ended on its own before the stop; RunLog.Exit
	// is its exit status.
	RunExited RunState = "exited"
	// RunInterrupted: the stop ended the run (or the sandbox had stopped
	// under it before).
	RunInterrupted RunState = "interrupted"
)

// MaxRunLogBytes bounds the log of a detached run the daemon keeps at a
// stop: the end of the run's output.
const MaxRunLogBytes = 1 << 20

// RunLog is GET /sandboxes/{name}/logs: the log of the sandbox's latest
// detached run (`sandbox run --detach`), which the daemon keeps on this
// machine whenever it stops the sandbox (`sandbox stop`, the TUI, the macOS
// app, undo, a tamper stop), so it can be read while the sandbox is
// stopped. 404 not_found when no log was kept.
type RunLog struct {
	Name string `json:"name"`
	// State is RunExited or RunInterrupted.
	State RunState `json:"state"`
	// Exit is the exit status of an exited run.
	Exit string `json:"exit,omitempty"`
	// StartedAt is when the run started (zero: unknown), KeptAt when the
	// stop kept its log.
	StartedAt time.Time `json:"started_at,omitzero"`
	KeptAt    time.Time `json:"kept_at"`
	// Log is the end of the run's output: at most MaxRunLogBytes, or its
	// last ?lines=N lines when asked. Bytes that are not UTF-8 are
	// replaced.
	Log string `json:"log"`
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
	// Apply is the result of undoing a copy-mode sandbox's last
	// `pull --apply`, which the CLI runs itself (Result is nil then).
	Apply *workspace.UndoApplyResult `json:"apply,omitempty"`
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
	// UnmaskedSecrets are the project's files that look like secrets and
	// that the sandbox's masks (fixed when it was created) leave visible:
	// its next start refuses while they stay in the project.
	UnmaskedSecrets []string `json:"unmasked_secrets,omitempty"`
}

// Workspace operations the CLI reports (the copy-mode steps it runs).
const (
	WorkspaceUpload = "upload"
	WorkspacePull   = "pull"
	// WorkspaceUndo is the revert of the last `pull --apply`.
	WorkspaceUndo = "undo"
)

// WorkspaceReport is POST /sandboxes/{name}/workspace: a copy-mode
// workspace step the CLI ran (upload, pull with apply/branch/patch, or the
// undo of an apply), so the daemon records it with the sandbox's identity.
// Counts are optional.
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

// Who approved an ask: the Reason of the approval.resolved event of an
// approval that was applied (ApprovalApplied).
const (
	ApprovedAutomatically = "automatic"
	ApprovedByOperator    = "operator"
	ApprovedByPolicy      = "policy"
)

// ApprovalApplied reports an approval.resolved event whose rule was
// applied: the destination it names is open from then on.
func ApprovalApplied(ev ActivityEvent) bool {
	if ev.Kind != ActivityApprovalResolved {
		return false
	}
	switch ev.Reason {
	case ApprovedAutomatically, ApprovedByOperator, ApprovedByPolicy:
		return true
	}
	return false
}

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
	// join openshell.egress.unblocked; reject: openshell.egress.block).
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
	// Run, for a new sandbox, is what of its create request its run files
	// depend on, which a MicroVM gateway bakes into a run image, so
	// Explain.VMFirstBoot does too. Without it the daemon takes the newest
	// sandbox of the harness's.
	Run *ExplainRun `json:"run,omitempty"`
}

// ExplainRun is what of a create request the run files of the sandbox
// depend on. It carries no secret: the names of the credentials, never
// their values.
type ExplainRun struct {
	// Env holds the variables of CreateRequest.Env that the harness's run
	// files read (connector.SandboxRunEnvReader), except those whose name
	// looks like a secret's and those whose value is a URL carrying a
	// credential.
	Env map[string]string `json:"env,omitempty"`
	// EnvWithheld names the variables of CreateRequest.Env that the run
	// files read but whose values Env leaves out, because the name looks
	// like a secret's or the value is a URL carrying a credential. The
	// daemon cannot render the files without them, so it takes the sandbox
	// to boot a new run image.
	EnvWithheld []string `json:"env_withheld,omitempty"`
	// Credentials names the variables the sandbox gets as credential
	// placeholders: those of CreateRequest.LLM.Credentials and of
	// CreateRequest.Credentials.
	Credentials []string `json:"credentials,omitempty"`
	// LLMProfile and BedrockRegion are CreateRequest.LLM's Profile and
	// BedrockRegion.
	LLMProfile    string `json:"llm_profile,omitempty"`
	BedrockRegion string `json:"bedrock_region,omitempty"`
}

// Explain is the resolved sandbox posture with provenance.
type Explain struct {
	Pack       string `json:"pack"`
	PackSource string `json:"pack_source"`
	PackDigest string `json:"pack_digest"`
	// PackChain are the packs the pack extends, parent first.
	PackChain []PackLink `json:"pack_chain,omitempty"`
	// RepoPolicy is the project's repository policy
	// (.defenseclaw/sandbox.yaml) the posture includes, if any.
	RepoPolicy  *RepoPolicy `json:"repo_policy,omitempty"`
	Profile     string      `json:"profile"`
	NetworkMode string      `json:"network_mode"`
	Approvals   string      `json:"approvals"`
	Admin       AdminStatus `json:"admin"`
	Settings    []Setting   `json:"settings"`
	Violations  []Violation `json:"violations,omitempty"`
	// VMFirstBoot says the sandbox would boot an image the gateway's
	// MicroVM (vm) driver has not prepared yet: the first start of each
	// image prepares its MicroVM disk, which takes about a minute. Always
	// false on the docker driver.
	VMFirstBoot bool `json:"vm_first_boot,omitempty"`
}

// MaxPolicyChecks bounds the destinations of one policy test.
const MaxPolicyChecks = 1024

// PolicyTestRequest is POST /policy/test: the destinations to judge with a
// sandbox's egress policy, its unblocks included.
type PolicyTestRequest struct {
	Sandbox string        `json:"sandbox"`
	Checks  []PolicyCheck `json:"checks"`
}

// PolicyCheck is one destination of a policy test. Port 0 judges the host
// on any port the policy carries; Binary names the program, which the
// egress proxy does not tell apart (every program in the sandbox reaches
// the web through it).
type PolicyCheck struct {
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// PolicyTestResult is a policy test's answer.
type PolicyTestResult struct {
	Sandbox     string           `json:"sandbox,omitempty"`
	Pack        string           `json:"pack"`
	Profile     string           `json:"profile"`
	NetworkMode string           `json:"network_mode"`
	Decisions   []PolicyDecision `json:"decisions"`
}

// PolicyDecision is what the egress policy decides for one destination,
// walking the egress proxy's order: Rule is the step that decided (a
// packs.EgressRule), Match the pattern, feed entry or port, and Source the
// setting that holds it.
type PolicyDecision struct {
	PolicyCheck
	Allowed     bool   `json:"allowed"`
	Rule        string `json:"rule"`
	Match       string `json:"match,omitempty"`
	Source      string `json:"source"`
	Reason      string `json:"reason,omitempty"`
	Unblockable bool   `json:"unblockable"`
	// Direct names a provider of the sandbox (its --llm model endpoint, a
	// --credential binding) whose OpenShell rule opens the destination to
	// that provider's programs around the egress proxy.
	Direct string `json:"direct,omitempty"`
}

// PackLink is one pack of an extends chain.
type PackLink struct {
	Name    string `json:"name"`
	Builtin bool   `json:"builtin"`
	Source  string `json:"source"`
	Digest  string `json:"digest"`
}

// RepoPolicy is a project's repository sandbox policy as a run read it: it
// may only tighten the posture. Content is the file as read (at most
// packs.MaxRepoPolicyBytes), so a client resolves exactly what the daemon
// resolved.
type RepoPolicy struct {
	// Path is the file read (<project>/.defenseclaw/sandbox.yaml).
	Path   string `json:"path"`
	Digest string `json:"digest"`
	// Tightened are the settings it made stricter for this run.
	Tightened []string `json:"tightened,omitempty"`
	Content   []byte   `json:"content,omitempty"`
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
	// ActivityToolAsked is a tool call DefenseClaw asked the user to
	// confirm; the harness asks in its own UI.
	ActivityToolAsked = "tool.asked"
	// ActivityHookBlocked is a hook event other than a tool call that
	// DefenseClaw blocked, such as a submitted prompt.
	ActivityHookBlocked = "hook.blocked"
	ActivityLifecycle   = "sandbox.lifecycle"
	ActivityFinding     = "finding"
	ActivityWorkspace   = "workspace"
	// ActivityHookFailed reports hook posts DefenseClaw answered with an
	// error status (HookCoverage.HookFailed).
	ActivityHookFailed = "hook.failed"
	// ActivityDropped tells a slow subscriber that events were skipped.
	ActivityDropped = "dropped"
)

// CategoryLargeUpload is the Category of the egress.blocked events of the
// large-upload block (egress.block_large_uploads): the upload that crossed
// the threshold, which the block cut, and later requests to the destination,
// which it refused. An unblock of the destination lifts the block.
const CategoryLargeUpload = "large_upload"

// The Category of a block-list refusal whose entry is the pack's, the
// repository policy's (.defenseclaw/sandbox.yaml) or the host egress
// firewall's deny rules; the user's own openshell.egress.block keeps the
// proxy's operator_block.
const (
	CategoryPackBlock       = "pack_block"
	CategoryRepoPolicyBlock = "repo_policy_block"
	CategoryFirewallBlock   = "firewall_block"
)

// LargeUploadBlockedText is how the feed words an egress.blocked event of
// category large_upload, whose Reason is the egress proxy's sentence
// ("This sandbox tried to send more than 25 MiB to a destination it had
// not contacted before."): "large upload blocked: this sandbox tried to
// send more than 25 MiB to …". The large-upload block
// (egress.block_large_uploads) stopped the upload before it crossed the
// threshold, or refused a later one to the destination.
func LargeUploadBlockedText(reason string) string {
	if why := LargeUploadReason(reason); why != "" {
		return "large upload blocked: " + why
	}
	return "large upload blocked"
}

// LargeUploadReason is the proxy's large-upload sentence as a clause: "this
// sandbox tried to send more than 25 MiB to a destination it had not
// contacted before". Empty for an empty reason.
func LargeUploadReason(reason string) string {
	reason = strings.TrimSuffix(strings.TrimSpace(reason), ".")
	if reason == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(reason)
	return string(unicode.ToLower(r)) + reason[n:]
}

// ReasonNestedRepo is the Reason of the finding events the nested-repository
// guard publishes.
const ReasonNestedRepo = "nested_repo"

// ReasonHostPortClosed is the Reason of the egress.blocked event of a
// connection to a port on this machine the sandbox may not reach: the run
// did not declare it with --host-port, or the policy does not open host
// ports. Its Message is the plain line with the way on (the flag to run
// with), and Host is host.openshell.internal.
const ReasonHostPortClosed = "host_port_closed"

// ReasonShadowAI is the Reason of the finding event of a shadow AI
// destination (DestinationOtherAI, DestinationUnknownAI): Host names it.
const ReasonShadowAI = "shadow_ai"

// ReasonHookFinding is the Reason of the finding event of a hook verdict
// that let a tool call run but flagged it (an alert); Severity is the
// verdict's.
const ReasonHookFinding = "hook_finding"

// ReasonPolicyChanged is the Reason of the sandbox.lifecycle event a
// sandbox gets when a configuration change moves the policy it runs under
// (its pack, profile, network mode, approvals, skip-permissions or the
// organization's egress lists); the Message says what changed.
const ReasonPolicyChanged = "policy_changed"

// ReasonEgressOff is the Reason of the sandbox.lifecycle event a sandbox
// gets when its policy turns its web egress off while it runs (the deny
// network mode, as an organization's required strict pack sets); its
// Message says why. The egress proxy answers the sandbox's requests with a
// 403 that says so too, each an egress.blocked event with category
// egress_off.
const ReasonEgressOff = "egress_off"

// ReasonHooksUnreachable is the Reason of the finding event a session gets
// when its hooks do not reach DefenseClaw; ReasonHooksRestored follows once
// an authenticated hook arrives after all.
const (
	ReasonHooksUnreachable = "hooks_unreachable"
	ReasonHooksRestored    = "hooks_restored"
)

// ReasonUpstreamFailed is the Reason of the (INFO) finding event the feed
// gets the first time the egress proxy could not complete an allowed
// connection to a host upstream: an outage, not a policy block.
const ReasonUpstreamFailed = "upstream_failed"

// ReasonModelKeyRejected is the Reason of the finding event a sandbox gets
// when the model API rejected its model credential (HookCoverage.ModelKeyRejected).
const ReasonModelKeyRejected = "model_credential_rejected"

// HooksUnreachableWarning opens every warning about hooks that do not
// reach DefenseClaw; HooksDoctorHint closes it.
const (
	HooksUnreachableWarning = "DefenseClaw hooks are not reaching the daemon; every tool call is being blocked"
	HooksDoctorHint         = "Run: defenseclaw sandbox doctor"
)

// HooksNotReachedYetWarning opens the warning about a session whose harness
// called its model while not one hook request reached DefenseClaw
// (HookCoverage.NoHookYet); HooksDoctorHint closes it too.
const HooksNotReachedYetWarning = "no hook has reached DefenseClaw yet"

// Activity sources for egress events.
const (
	SourceProxy     = "dc-egress-proxy"
	SourceOpenShell = "openshell"
)

// ActivityEvent is one item of the live activity feed.
type ActivityEvent struct {
	// Seq increases by one per event; resume with ?since=<seq>.
	Seq uint64 `json:"seq"`
	// Epoch names the feed that numbered Seq. The feed lives in the
	// daemon's memory, so a daemon that restarted numbers its events from
	// one again under another epoch: a client that sees the epoch change
	// reads the new feed from its start instead of resuming after its old
	// Seq.
	Epoch   string    `json:"epoch,omitempty"`
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
	// Threshold is the large-upload threshold an egress.large_upload
	// report crossed. The proxy reports the upload as it crosses, before
	// it ends: BytesUp is what had been sent then, and the upload sent
	// more than Threshold.
	Threshold int64 `json:"threshold,omitempty"`
	// Approval and hook fields.
	ApprovalID string `json:"approval_id,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Event      string `json:"event,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Severity   string `json:"severity,omitempty"`
	// Reason is the machine-readable cause, Message the display line.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	// Replayed marks an OpenShell record from before the daemon started,
	// which OpenShell's stream replays when DefenseClaw starts again: it
	// arrives after newer events.
	Replayed bool `json:"replayed,omitempty"`
}

// HostPort is a destination as the feed names it: the host, with its port
// unless that is 443 (HTTPS, which nearly every request uses) or unknown.
// A plain-HTTP request reads host:80, so an HTTPS and an HTTP request to
// one host (the egress proxy refuses them one by one) do not read as one
// line twice. An IPv6 literal with its port is bracketed, as
// net.JoinHostPort does: "[fd00:ec2::254]:80", not "fd00:ec2::254:80",
// which is another address.
func HostPort(host string, port int) string {
	if port == 0 || port == 443 {
		return host
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
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
