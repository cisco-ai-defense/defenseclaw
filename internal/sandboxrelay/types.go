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

// Package sandboxrelay holds the wire contract between a managed host's
// per-user sandbox daemon and the managed gateway's hook socket: the JSON
// bodies of the sandbox routes, the relay's header names and allowlist, the
// verdict trailer of a relayed hook call, the refusal reasons and the
// client interface the daemon uses.
//
// The routes are served only on the standalone hook socket mux, never on
// the TCP API. Every JSON body this package defines carries "v": 1;
// relayed hook, notify and inspect bodies are the harness's own bytes and
// carry no version.
package sandboxrelay

import (
	"encoding/json"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// WireVersion is the "v" of every JSON body this package defines.
const WireVersion = 1

// Hook-socket routes. Each answers only on the managed gateway's hook
// socket; uid 0 is refused on all of them.
const (
	PathPrefix          = "/api/v1/sandbox/"
	PathSettings        = "/api/v1/sandbox/settings"
	PathPolicyResolve   = "/api/v1/sandbox/policy/resolve"
	PathRegistrations   = "/api/v1/sandbox/registrations/" // + {id}/bind, {id}/state, {id}/restart, {id}/deleted
	PathPolicyCurrent   = "/api/v1/sandbox/policy/current" // ?registration=ID
	PathPolicyExplain   = "/api/v1/sandbox/policy/explain"
	PathPolicyTest      = "/api/v1/sandbox/policy/test"
	PathPolicyPacks     = "/api/v1/sandbox/policy/packs" // [/{name}]
	PathDecisions       = "/api/v1/sandbox/decisions"    // POST; GET ?registration=ID
	PathEvents          = "/api/v1/sandbox/events"
	PathHookPrefix      = "/api/v1/sandbox/hook/"    // + {connector}
	PathNotifyPrefix    = "/api/v1/sandbox/notify/"  // + {connector}; only codex
	PathInspectPrefix   = "/api/v1/sandbox/inspect/" // + tool|request|response|tool-response
	PathOTLPPrefix      = "/api/v1/sandbox/otlp/"    // + logs|metrics|traces
	RegistrationBindSub = "/bind"
	RegistrationDelSub  = "/deleted"
	// RegistrationStateSub is POST registrations/{id}/state: a StateReport
	// answered with the CurrentPolicy policy/current gives.
	RegistrationStateSub = "/state"
	// RegistrationRestartSub is POST registrations/{id}/restart: the
	// stopped sandbox of a bound registration starts again under a new
	// registration, answered with its RegistrationView. A state report
	// never revives a registration whose sandbox was reported stopped.
	RegistrationRestartSub = "/restart"
	RegistrationQuery      = "registration"
)

// Header names and the values the relay sets.
const (
	// RegistrationHeader names the registration of a relayed call, an OTLP
	// post and every route whose body has no registration field.
	RegistrationHeader = "X-DefenseClaw-Sandbox-Registration"
	// ClientHeader is the hook-socket mux's CSRF header; the relay always
	// sends ClientHeaderValue.
	ClientHeader      = "X-DefenseClaw-Client"
	ClientHeaderValue = "sandbox-relay"
	// AgentSurfaceHeader is set by the relay to AgentSurfaceValue; the
	// sandbox's own value is dropped.
	AgentSurfaceHeader = "X-DefenseClaw-Agent-Surface"
	AgentSurfaceValue  = "cli"
	// ConnectorHeader carries the connector claim of policy/resolve and
	// settings; the registration then pins it. Never forwarded on a
	// relayed call.
	ConnectorHeader = "X-DefenseClaw-Connector"
	// ProfileHeader (the caller's own profile name) and GenerationHeader
	// are set by the gateway on relayed-call responses.
	ProfileHeader    = "X-DefenseClaw-Sandbox-Profile"
	GenerationHeader = "X-DefenseClaw-Policy-Generation"
	// DecisionTrailer carries the HookDecision JSON of a relayed call.
	DecisionTrailer = "X-DefenseClaw-Sandbox-Decision"
	// FilesHeader is reserved for mount-mode file bytes. v1 never sends
	// it; the gateway refuses a relayed call carrying it with
	// ReasonRelayFilesUnsupported.
	FilesHeader = "X-DefenseClaw-Sandbox-Files"
	// SandboxHeaderPrefix: every header the sandbox sends with this prefix
	// is dropped by the relay.
	SandboxHeaderPrefix = "X-DefenseClaw-Sandbox-"
	// DaemonContractHeader carries the DaemonContract of the daemon on
	// every call it makes, relayed calls included (the sandbox's own value
	// is dropped with the rest of SandboxHeaderPrefix).
	DaemonContractHeader = "X-DefenseClaw-Sandbox-Daemon-Contract"
)

// DaemonContract is what the daemon does with a CurrentPolicy, as
// DaemonContractHeader states it. A daemon that sends no header (1.0.2 and
// earlier) adopts only the live fields of the floor and marks the
// registration confirmed; contract 2 adopts the complete Floor and
// RequiredPack and refuses an answer without them. The managed gateway
// refuses new sandboxes, renewals and policy confirmations to a daemon
// below this contract with ReasonDaemonOutdated (GAP-0182).
const DaemonContract = 2

// ForwardHeaders is the allowlist of request headers the relay copies from
// the sandbox's request to the gateway (canonical MIME form). Nothing else
// is copied; the relay then sets RegistrationHeader, ClientHeader and
// AgentSurfaceHeader itself.
var ForwardHeaders = [...]string{
	"Content-Type",
	"Idempotency-Key",
	"X-Defenseclaw-Hook-Event",
	"X-Defenseclaw-Hook-Contract",
	"X-Defenseclaw-Antigravity-Event",
	"X-Defenseclaw-Copilot-Event",
	"X-Defenseclaw-Hook-Dialect",
	"X-Defenseclaw-Kiro-Surface",
	"X-Defenseclaw-Hook-Refusal",
	"X-Defenseclaw-Asset-Facts",
}

// DroppedHeaders lists request headers that must never leave the daemon on
// a relayed call (canonical MIME form). The allowlist already excludes
// them; the list exists so tests can assert each one, together with every
// header under SandboxHeaderPrefix.
var DroppedHeaders = [...]string{
	"Traceparent",
	"Tracestate",
	"Authorization",
	"X-Defenseclaw-Token",
	"X-Dc-Auth",
	"Cookie",
	"X-Defenseclaw-Connector",
	"X-Defenseclaw-User-Id",
	"X-Defenseclaw-User-Name",
	"X-Defenseclaw-Session-Facts",
	"X-Defenseclaw-Client-Refusal",
	"X-Defenseclaw-Client",
	"X-Defenseclaw-Agent-Surface",
	"X-Defenseclaw-Request-Id",
	"X-Request-Id",
	"X-Correlation-Id",
}

// ResponseHeaders are the only relayed-call response headers the daemon
// copies back to the sandbox (canonical MIME form).
var ResponseHeaders = [...]string{
	"Content-Type",
	"X-Defenseclaw-Sandbox-Profile",
	"X-Defenseclaw-Policy-Generation",
}

// Size limits of the relay.
const (
	// MaxForwardHeaderBytes bounds the allowlisted headers of one relayed
	// call in total; the daemon answers 400 before forwarding when larger.
	MaxForwardHeaderBytes = 4 << 10
	// MaxResolveBytes bounds a policy/resolve body.
	MaxResolveBytes = 256 << 10
	// MaxRepoOverlayBytes bounds ResolveRequest.RepoOverlay.
	MaxRepoOverlayBytes = 16 << 10
	// MaxUserPackBytes bounds ResolveRequest.UserPack.
	MaxUserPackBytes = 64 << 10
	// MaxHookDecisionBytes bounds the DecisionTrailer JSON.
	MaxHookDecisionBytes = 2 << 10
	// MaxHookDecisionReasonBytes and MaxHookDecisionStringBytes bound the
	// trailer's strings (truncated, never refused).
	MaxHookDecisionReasonBytes = 256
	MaxHookDecisionStringBytes = 128
	// MaxEventBatchRecords and MaxEventBatchBytes bound one EventBatch.
	MaxEventBatchRecords = 256
	MaxEventBatchBytes   = 256 << 10
	// MaxUnregisteredEventRecords bounds a batch without a registration
	// (the daemon keeps at most as many records for the managed gateway).
	MaxUnregisteredEventRecords = 64
	// MaxTelemetryBatchRecords bounds a batch that carries sandbox
	// telemetry records (EventTelemetry): the daemon posts at most this many
	// per batch, and the managed gateway refuses a larger one.
	MaxTelemetryBatchRecords = 128
	// MaxOTLPBodyBytes bounds one relayed OTLP post.
	MaxOTLPBodyBytes = 4 << 20
	// MaxRequestAccessBytes bounds request_access text.
	MaxRequestAccessBytes = 512
)

// ResolveIdentityWait is how long policy/resolve waits for the identity
// lookup before it answers provisional.
const ResolveIdentityWait = 10 * time.Second

// PolicyPollInterval is the daemon's policy/current poll per live
// registration.
const PolicyPollInterval = 60 * time.Second

// Tamper tiers of a harness (ResolveRequest.TamperTier).
const (
	TamperTierManaged = "managed"
	TamperTierUser    = "user"
)

// ResolveRequest is POST policy/resolve: what the daemon knows about the
// run it is about to create. Every field is a claim the gateway judges.
type ResolveRequest struct {
	V              int    `json:"v"`
	Harness        string `json:"harness"`
	Connector      string `json:"connector"`
	HarnessVersion string `json:"harness_version"`
	HookContract   string `json:"hook_contract"`
	TamperTier     string `json:"tamper_tier"`
	// Flags are the run flags as the user typed them.
	Flags RunFlags `json:"flags"`
	// RepoOverlay is the project's .defenseclaw/sandbox.yaml, at most
	// MaxRepoOverlayBytes.
	RepoOverlay []byte `json:"repo_overlay,omitempty"`
	// ProjectReal is the project path after the daemon's EvalSymlinks.
	ProjectReal string `json:"project_real"`
	// UserPack is the --pack file the daemon read as the user, at most
	// MaxUserPackBytes.
	UserPack  []byte           `json:"user_pack,omitempty"`
	Resources Resources        `json:"resources"`
	MCP       []MCPServerClaim `json:"mcp"`
	// Driver is the compute driver the daemon chose for the run (docker or
	// vm) at sandbox start from the user's KVM probe, and DriverReason why
	// (openshell.DriverReason*: configured, kvm_available, or the probe's
	// reason when the docker fallback replaced the MicroVM driver). The
	// gateway checks the choice against enterprise.openshell and the
	// caller's floor and records both on the registration.
	Driver       string         `json:"driver"`
	DriverReason string         `json:"driver_reason,omitempty"`
	OpenShell    OpenShellFacts `json:"openshell"`
}

// RunFlags are the `sandbox run` flags that take part in policy resolution.
type RunFlags struct {
	Pack        string   `json:"pack,omitempty"`
	Profile     string   `json:"profile,omitempty"`
	Copy        bool     `json:"copy,omitempty"`
	Safe        bool     `json:"safe,omitempty"`
	Yolo        bool     `json:"yolo,omitempty"`
	Unmask      []string `json:"unmask,omitempty"`
	HostPorts   []int    `json:"host_ports,omitempty"`
	NoMCP       bool     `json:"no_mcp,omitempty"`
	Learn       bool     `json:"learn,omitempty"`
	ProcessTree bool     `json:"process_tree,omitempty"`
	CPU         string   `json:"cpu,omitempty"`
	Memory      string   `json:"memory,omitempty"`
}

// Resources is a CPU and memory request or limit (OpenShell quantities).
type Resources struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// MCPServerClaim is one MCP server the run would import, as the daemon
// read it from the user's harness configuration (a claim).
type MCPServerClaim struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport,omitempty"`
	URL       string   `json:"url,omitempty"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
}

// Bounds of the MCP server claims of one request (ResolveRequest.MCP,
// ExplainRequest.MCP). The managed gateway refuses a request whose claims
// break them, so the daemon claims only what fits (ValidMCPServerClaim,
// MCPServerClaim.Size) and leaves the rest behind.
const (
	MaxMCPClaims         = 256
	MaxMCPClaimBytes     = 64 << 10
	MaxMCPClaimArgs      = 64
	maxMCPClaimName      = 128
	maxMCPClaimField     = 4096
	maxMCPClaimURL       = 2048
	maxMCPClaimTransport = 32
)

// ValidMCPServerClaim reports a claim the managed gateway accepts: a
// printable ASCII name of at most 128 bytes and bounded fields.
func ValidMCPServerClaim(c MCPServerClaim) bool {
	if c.Name == "" || len(c.Name) > maxMCPClaimName || !printableASCII(c.Name) || len(c.Transport) > maxMCPClaimTransport ||
		len(c.URL) > maxMCPClaimURL || len(c.Command) > maxMCPClaimField || len(c.Args) > MaxMCPClaimArgs {
		return false
	}
	for _, arg := range c.Args {
		if len(arg) > maxMCPClaimField {
			return false
		}
	}
	return true
}

// Size is the claim's byte count toward MaxMCPClaimBytes.
func (c MCPServerClaim) Size() int {
	n := len(c.Name) + len(c.Transport) + len(c.URL) + len(c.Command)
	for _, arg := range c.Args {
		n += len(arg)
	}
	return n
}

func printableASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// OpenShellFacts is what the daemon found of the user's OpenShell: the
// gateway compares it with enterprise.openshell (drift input).
type OpenShellFacts struct {
	Version        string `json:"version,omitempty"`
	InstallMode    string `json:"install_mode,omitempty"`
	SettingsDigest string `json:"settings_digest,omitempty"`
}

// ResolveResponse answers policy/resolve. Refusal is set instead of
// Registration when the run is refused.
type ResolveResponse struct {
	V            int              `json:"v"`
	Registration RegistrationView `json:"registration"`
	// Effective is the packs.Effective wire form, pack content included.
	Effective json.RawMessage `json:"effective,omitempty"`
	// RequiredPack is the floor's required pack (a packs.Pack) when the run
	// uses a stricter pack in its place, which Effective then carries; the
	// daemon cannot read the administrator's pack folder (GAP-0563).
	RequiredPack json.RawMessage     `json:"required_pack,omitempty"`
	Operational  OperationalSettings `json:"operational"`
	MCPKept      []string            `json:"mcp_kept"`
	MCPSkipped   []MCPSkip           `json:"mcp_skipped"`
	Banner       BannerView          `json:"banner"`
	Generation   uint64              `json:"generation"`
	Refusal      *Refusal            `json:"refusal,omitempty"`
}

// RegistrationView is what the caller sees of its own registration. V is
// set (1) when the view is a top-level body (the bind answer) and left 0
// when it is nested in a ResolveResponse.
type RegistrationView struct {
	V           int       `json:"v,omitempty"`
	ID          string    `json:"id"`
	State       string    `json:"state,omitempty"`
	Provisional bool      `json:"provisional,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	BoundAt     time.Time `json:"bound_at,omitzero"`
	SandboxID   string    `json:"sandbox_id,omitempty"`
	SandboxName string    `json:"sandbox_name,omitempty"`
	BindingID   string    `json:"binding_id,omitempty"`
}

// MCP skip reasons.
const (
	MCPSkipOrganizationBlock = "organization_block"
	MCPSkipAssetPolicy       = "asset_policy"
)

// MCPSkip is one claimed MCP server the run leaves out, and why.
type MCPSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// BannerView is the banner's policy line.
type BannerView struct {
	Profile      string `json:"profile"`
	Description  string `json:"description,omitempty"`
	Provisional  bool   `json:"provisional,omitempty"`
	PolicyDigest string `json:"policy_digest"`
}

// Refusal is a refused request: reason (ReasonX), the user text and the
// caller's request-access contact.
type Refusal struct {
	Reason        string `json:"reason"`
	Message       string `json:"message"`
	RequestAccess string `json:"request_access,omitempty"`
}

// OperationalSettings is the openshell.* subset a managed daemon runs with
// (it has no config file). Policy-governed keys (pack, profile, yolo,
// workdir, egress, resources) arrive resolved in ResolveResponse.Effective
// instead.
type OperationalSettings struct {
	IngressPort       int               `json:"ingress_port"`
	EgressPort        int               `json:"egress_port"`
	GatewayName       string            `json:"gateway_name,omitempty"`
	GatewayWorkspace  string            `json:"gateway_workspace,omitempty"`
	Image             ImageSettings     `json:"image"`
	Approvals         ApprovalsSettings `json:"approvals"`
	MCP               MCPSettings       `json:"mcp"`
	Harnesses         []string          `json:"harnesses,omitempty"`
	Wrappers          []string          `json:"wrappers,omitempty"`
	TokenDelivery     string            `json:"token_delivery,omitempty"`
	Middleware        bool              `json:"middleware,omitempty"`
	LLM               string            `json:"llm,omitempty"`
	KeepHeadless      bool              `json:"keep_headless,omitempty"`
	UpstreamTelemetry bool              `json:"upstream_telemetry,omitempty"`
	// TrustedCAs is the normalized PEM of the administrator's
	// openshell.trusted_ca_bundle, read by the managed gateway (the
	// account cannot name a CA of its own); TrustedCAError says why the
	// gateway could not use the file, and the daemon then builds no image.
	TrustedCAs     string `json:"trusted_cas,omitempty"`
	TrustedCAError string `json:"trusted_ca_error,omitempty"`
}

// ImageSettings mirrors openshell.image.
type ImageSettings struct {
	Base            string            `json:"base,omitempty"`
	HarnessVersions map[string]string `json:"harness_versions,omitempty"`
}

// ApprovalsSettings mirrors openshell.approvals.
type ApprovalsSettings struct {
	DebounceMs     int   `json:"debounce_ms,omitempty"`
	AgentProposals *bool `json:"agent_proposals,omitempty"`
}

// MCPSettings mirrors openshell.mcp.
type MCPSettings struct {
	Import    *bool `json:"import,omitempty"`
	HostPorts []int `json:"host_ports,omitempty"`
}

// DaemonSettings answers GET settings: what the daemon needs at start and
// on every generation change.
type DaemonSettings struct {
	V         int  `json:"v"`
	Enabled   bool `json:"enabled"`
	Available bool `json:"available"`
	// Unavailable is the bare reason when Available is false ("OpenShell
	// is not installed"), not a sentence: the daemon's status and the
	// launcher frame it (sandboxapi.UnavailableSentence).
	Unavailable string              `json:"unavailable,omitempty"`
	Operational OperationalSettings `json:"operational"`
	Enterprise  EnterpriseOpenShell `json:"enterprise"`
	Generation  uint64              `json:"generation"`
	// RequestAccess is the caller's own request-access contact.
	RequestAccess string `json:"request_access"`
	// SelectedDriver and DriverReason are the compute driver the gateway's
	// view of the caller's account would give a sandbox now, and why
	// (openshell.DriverReason*; the gate's availability probe: /dev/kvm
	// modes and groups, CPU flags, the lifecycle's prerequisites). The
	// daemon probes again as the user at sandbox start, and that probe
	// decides. Not part of Enterprise: a change never restarts a daemon.
	SelectedDriver string `json:"selected_driver,omitempty"`
	DriverReason   string `json:"driver_reason,omitempty"`
	// ForeignSandboxes is the caller's own foreign_sandboxes (alert or
	// stop), which the daemon applies to sandboxes DefenseClaw did not start
	// while none of the caller's registrations names a floor yet (GAP-0058).
	ForeignSandboxes string `json:"foreign_sandboxes,omitempty"`
}

// EnterpriseOpenShell is enterprise.openshell plus the rendered OpenShell
// gateway configuration the daemon checks against.
type EnterpriseOpenShell struct {
	Install string `json:"install"`
	// Driver is the driver the organization wants on this host (docker, vm
	// or auto). DriverFallback is the caller's own fallback where the
	// MicroVM driver can't run (docker or none; "" where none applies):
	// enterprise.openshell.driver_fallback tightened by the caller's floor.
	Driver              string `json:"driver"`
	DriverFallback      string `json:"driver_fallback,omitempty"`
	Version             string `json:"version,omitempty"`
	GatewayPort         int    `json:"gateway_port"`
	E2fsprogsDir        string `json:"e2fsprogs_dir,omitempty"`
	GatewayConfigPath   string `json:"gateway_config_path,omitempty"`
	GatewayConfigDigest string `json:"gateway_config_digest,omitempty"`
}

// HookDecision is the verdict trailer DecisionTrailer of a relayed hook,
// notify or inspect call. JSON, at most MaxHookDecisionBytes; strings are
// truncated (Reason to MaxHookDecisionReasonBytes, every other string to
// MaxHookDecisionStringBytes).
type HookDecision struct {
	V         int    `json:"v"`
	Event     string `json:"event,omitempty"`
	Tool      string `json:"tool,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	// CallRef is manager.ContentRef(session, tool, tool input) computed by
	// the gateway; the tool input itself never crosses back.
	CallRef      string `json:"call_ref,omitempty"`
	ResultStatus string `json:"result_status,omitempty"`
	// Action is allow, block, alert or confirm.
	Action     string `json:"action"`
	WouldBlock bool   `json:"would_block,omitempty"`
	// FailedClosed reports a block caused by a hook evaluation failure.
	FailedClosed bool   `json:"failed_closed,omitempty"`
	Severity     string `json:"severity,omitempty"`
	// Reason is rule metadata only, as SandboxHookDecision.Reason.
	Reason      string `json:"reason,omitempty"`
	ModelError  string `json:"model_error,omitempty"`
	ModelStatus int    `json:"model_status,omitempty"`
	// AlertsLow reports that the guardrail profile which decided the call
	// alerts at LOW itself, so a LOW alert is a finding of the session.
	AlertsLow bool `json:"alerts_low,omitempty"`
	// EgressTold reports that the answer told the agent of the call's
	// EgressRefusalsHeader refusals; the daemon then marks them told.
	EgressTold bool `json:"egress_told,omitempty"`
}

// StateReport is POST registrations/{id}/state: whether the daemon sees the
// registration's sandbox running now. Only a running sandbox's registration
// authorizes relayed calls, for sandboxreg.LiveLease after the last report.
type StateReport struct {
	V       int  `json:"v"`
	Running bool `json:"running"`
}

// BindRequest is POST registrations/{id}/bind: the sandbox the pending
// registration became.
type BindRequest struct {
	V           int    `json:"v"`
	SandboxID   string `json:"sandbox_id"`
	SandboxName string `json:"sandbox_name"`
	BindingID   string `json:"binding_id"`
	// Driver is the compute driver the sandbox was created on; it must be
	// the registration's (a sandbox never switches driver). "" from a
	// daemon that does not say is not checked.
	Driver string `json:"driver,omitempty"`
}

// CurrentPolicy answers GET policy/current: the registration's complete
// policy floor now.
type CurrentPolicy struct {
	V             int    `json:"v"`
	Generation    uint64 `json:"generation"`
	Revoked       bool   `json:"revoked,omitempty"`
	RevokedReason string `json:"revoked_reason,omitempty"`
	// Floor is the complete gateway-owned policy floor. A managed daemon
	// adopts it after confirmation instead of its user-writable cache.
	Floor *config.OpenShellAdminConfig `json:"floor,omitempty"`
	// RequiredPack is the gateway-owned content of Floor.RequiredPack when
	// that pack is custom. A daemon must never install its user-owned cache.
	RequiredPack json.RawMessage `json:"required_pack,omitempty"`
	// Digest is the caller's effective sandbox policy digest.
	Digest string `json:"digest"`
	// Profile is the guardrail profile of the same match as Digest: after
	// a regroup re-matched the registration, status and refusals name it,
	// not the profile the sandbox was created under (#1199).
	Profile string `json:"profile,omitempty"`
	// MinProfile is the min_profile of the caller's floor now. It is not a
	// live field: a running sandbox keeps the profile it started with, and
	// a sandbox that starts again takes this one, never the looser one it
	// registered under (GAP-0224). nil is an answer without it.
	MinProfile *string `json:"min_profile,omitempty"`
	// Provisional is whether the same match is provisional (the directory
	// could not be asked, so the organization's default applies). Status
	// shows it next to Profile and Digest, so a sandbox created during an
	// outage stops saying the default applies once a re-match verified its
	// groups, and says so again if a later match is provisional (#1199). Nil,
	// from a gateway that does not say, leaves the daemon's flag as it is.
	Provisional *bool `json:"provisional,omitempty"`
	// UpdatedAt is when the registration's policy last changed
	// (sandboxreg.PolicyUpdatedAt), the age the daemon's status shows.
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Decision kinds and scopes (DecisionRequest).
const (
	DecisionEgressAllow = "egress_allow"
	DecisionEgressBlock = "egress_block"
	DecisionUnblock     = "unblock"

	DecisionScopeSession = "session"
	DecisionScopeAlways  = "always"
)

// DecisionRequest is POST decisions: an ask answer, an unblock or a user
// block for one host, re-checked against the caller's floor.
type DecisionRequest struct {
	V            int    `json:"v"`
	Registration string `json:"registration"`
	Kind         string `json:"kind"`
	Host         string `json:"host"`
	Scope        string `json:"scope"`
	ApprovalID   string `json:"approval_id,omitempty"`
	// Port is the destination port of a host-port ask, for the record of
	// the decision only; 0 names none.
	Port int `json:"port,omitempty"`
}

// DecisionResult answers POST decisions. Stored says the gateway kept the
// decision (an "always" allow, an unblock or a user block); a session-only
// decision is not stored.
type DecisionResult struct {
	V        int      `json:"v"`
	Stored   bool     `json:"stored"`
	Decision Decision `json:"decision"`
}

// Decision is one of the caller's saved decisions (GET decisions answers a
// JSON array of them).
type Decision struct {
	ID           string    `json:"id"`
	Registration string    `json:"registration"`
	Kind         string    `json:"kind"`
	Host         string    `json:"host"`
	Scope        string    `json:"scope"`
	CreatedAt    time.Time `json:"created_at"`
}

// Event kinds of an EventBatch.
const (
	EventForeignSandbox   = "foreign_sandbox"
	EventForeignRule      = "foreign_rule"
	EventForeignContainer = "foreign_container"
	EventSettingsDrift    = "settings_drift"
	EventAccessRefused    = "access_refused"
	// EventAccountBusy reports a run the caller's daemon refused because
	// another account holds the sandbox ports or the OpenShell gateway. The
	// refusal comes before any registration exists, and the payload names no
	// other account (GAP-0598).
	EventAccountBusy = "account_busy"
	// EventSandboxLifecycle and EventSandboxEgress carry the daemon's
	// sandbox telemetry: a phase change of one of the caller's sandboxes
	// (log.sandbox.lifecycle) and an egress decision or the end of an
	// allowed connection (log.egress.*). The daemon has no telemetry
	// destination of its own, so the managed gateway records them, stamped
	// with the registration's sandbox and the verified peer (GAP-0003).
	EventSandboxLifecycle = "sandbox_lifecycle"
	EventSandboxEgress    = "sandbox_egress"
	// EventSandboxAskDecision carries only decisions the manager resolves
	// without calling the gateway's decisions route: a rejection or a
	// policy-bounded approval attempt.
	EventSandboxAskDecision = "sandbox_ask_decision"
)

// EventTelemetry reports a kind that carries the daemon's sandbox
// telemetry (EventSandboxLifecycle, EventSandboxEgress). Such a record may
// describe a sandbox whose registration the daemon already reported
// deleted: the deleting and deleted phases are recorded just before.
func EventTelemetry(kind string) bool {
	return kind == EventSandboxLifecycle || kind == EventSandboxEgress
}

// EventWithoutRegistration reports a kind a batch may carry without a
// registration: the foreign sandboxes and containers a daemon finds belong to
// no registration of the caller (a person who only runs raw OpenShell
// sandboxes or plain containers has none), and a refused run has none yet.
func EventWithoutRegistration(kind string) bool {
	switch kind {
	case EventForeignSandbox, EventForeignContainer, EventAccountBusy:
		return true
	}
	return false
}

// EventBatch is POST events: daemon-side records the gateway stamps with
// the caller's identity and emits. At most MaxEventBatchRecords records and
// MaxEventBatchBytes. Registration is one of the caller's, or "" for a
// batch of only foreign sandbox and container records, which belong to no
// registration.
type EventBatch struct {
	V            int     `json:"v"`
	Registration string  `json:"registration"`
	Events       []Event `json:"events"`
}

// Event is one daemon-side record: a kind (EventX) and its payload.
type Event struct {
	Kind    string          `json:"kind"`
	Time    time.Time       `json:"time"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ExplainRequest is POST policy/explain: the posture of a registered
// sandbox, or of a run not created yet (Harness, Connector, Flags,
// ProjectReal).
type ExplainRequest struct {
	V            int       `json:"v"`
	Registration string    `json:"registration,omitempty"`
	Harness      string    `json:"harness,omitempty"`
	Connector    string    `json:"connector,omitempty"`
	Flags        *RunFlags `json:"flags,omitempty"`
	ProjectReal  string    `json:"project_real,omitempty"`
	// Sources asks for the source of each value (organization, profile,
	// pack, repo or flag).
	Sources bool `json:"sources,omitempty"`
	// RepoOverlay and UserPack are a new run's repository policy and
	// --pack file as the daemon read them as the user (at most
	// MaxRepoOverlayBytes and MaxUserPackBytes): the posture of the answer
	// resolves them as policy/resolve does.
	RepoOverlay []byte `json:"repo_overlay,omitempty"`
	UserPack    []byte `json:"user_pack,omitempty"`
	// MCP are the caller's own MCP servers the run would bring along; the
	// answer's MCPIncluded and MCPBlocked judge them as a resolve does.
	MCP []MCPServerClaim `json:"mcp,omitempty"`
}

// PolicyTestRequest is POST policy/test: the destinations to judge with the
// caller's own policy. With Registration (sent as RegistrationHeader) that
// is the policy of one of the caller's sandboxes; without one, the policy a
// new run of Connector (sent as ConnectorHeader) in ProjectReal with the
// repository policy RepoOverlay would get, resolved as policy/resolve
// resolves it (GAP-0438).
type PolicyTestRequest struct {
	V            int                      `json:"v"`
	Registration string                   `json:"-"`
	Connector    string                   `json:"-"`
	ProjectReal  string                   `json:"project_real,omitempty"`
	RepoOverlay  []byte                   `json:"repo_overlay,omitempty"`
	Checks       []sandboxapi.PolicyCheck `json:"checks"`
}

// PackView is one pack of the caller's effective chain (GET policy/packs
// answers a JSON array; policy/packs/{name} one view with Content).
type PackView struct {
	Name        string `json:"name"`
	Source      string `json:"source,omitempty"`
	Digest      string `json:"digest"`
	Description string `json:"description,omitempty"`
	Extends     string `json:"extends,omitempty"`
	Content     string `json:"content,omitempty"`
}
