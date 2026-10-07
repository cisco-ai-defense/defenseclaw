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

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

// SandboxTelemetry is the narrow v8 telemetry surface of the OpenShell sandbox
// integration. Every method emits exactly one generated log family (plus its
// companion metrics) carrying the correlation.sandbox attribute group; none of
// them accepts a family name, a builder, or free-form attributes. Callers hold
// this interface, never *Logger. *SandboxRecorder is the implementation.
type SandboxTelemetry interface {
	RecordSandboxLifecycle(context.Context, SandboxLifecycleEvent) error
	RecordSandboxEgress(context.Context, SandboxEgressEvent) error
	RecordSandboxApproval(context.Context, SandboxApprovalEvent) error
	RecordSandboxPolicy(context.Context, SandboxPolicyEvent) error
	RecordSandboxHealth(context.Context, SandboxHealthEvent) error
	RecordSandboxFinding(context.Context, SandboxFindingEvent) error
	RecordSandboxWorkspace(context.Context, SandboxWorkspaceEvent) error
	RecordSandboxActivity(context.Context, SandboxActivityEvent) error
	RecordSandboxProcess(context.Context, SandboxProcessEvent) error
}

// SandboxPhase is the defenseclaw.sandbox.phase vocabulary: the OpenShell
// SandboxPhase values plus two DefenseClaw-only bookends, creating (before the
// gateway has accepted the sandbox) and deleted (after it is gone).
type SandboxPhase string

const (
	SandboxPhaseCreating     SandboxPhase = "creating"
	SandboxPhaseProvisioning SandboxPhase = "provisioning"
	SandboxPhaseStarting     SandboxPhase = "starting"
	SandboxPhaseReady        SandboxPhase = "ready"
	SandboxPhaseStopping     SandboxPhase = "stopping"
	SandboxPhaseStopped      SandboxPhase = "stopped"
	SandboxPhaseCompleted    SandboxPhase = "completed"
	SandboxPhaseError        SandboxPhase = "error"
	SandboxPhaseDeleting     SandboxPhase = "deleting"
	SandboxPhaseDeleted      SandboxPhase = "deleted"
	SandboxPhaseUnknown      SandboxPhase = "unknown"
)

// Valid reports whether phase is a registered sandbox phase.
func (phase SandboxPhase) Valid() bool {
	switch phase {
	case SandboxPhaseCreating, SandboxPhaseProvisioning, SandboxPhaseStarting, SandboxPhaseReady,
		SandboxPhaseStopping, SandboxPhaseStopped, SandboxPhaseCompleted, SandboxPhaseError,
		SandboxPhaseDeleting, SandboxPhaseDeleted, SandboxPhaseUnknown:
		return true
	default:
		return false
	}
}

// Active reports whether a sandbox in this phase counts toward
// metric.defenseclaw.sandbox.active: it holds OpenShell resources and is
// neither stopped, finished, failed, nor being torn down.
func (phase SandboxPhase) Active() bool {
	switch phase {
	case SandboxPhaseProvisioning, SandboxPhaseStarting, SandboxPhaseReady, SandboxPhaseStopping:
		return true
	default:
		return false
	}
}

// Registered values of the enumerated correlation.sandbox attributes.
const (
	SandboxRuntimeOpenShell = "openshell"

	SandboxDriverDocker = "docker"
	SandboxDriverPodman = "podman"
	SandboxDriverVM     = "vm"
	SandboxDriverK8s    = "k8s"

	SandboxProfileOpen     = "open"
	SandboxProfileBalanced = "balanced"
	SandboxProfileStrict   = "strict"

	SandboxWorkdirMount = "mount"
	SandboxWorkdirCopy  = "copy"
)

// SandboxIdentity is the correlation.sandbox attribute group shared by every
// sandbox record. Empty fields are omitted, never inferred. Identity values
// are log attributes only; the registry forbids them as metric labels.
type SandboxIdentity struct {
	// ID is the OpenShell sandbox ID; empty until the gateway accepted it.
	ID string
	// Name is the DefenseClaw sandbox name (by default <folder>-<rand4>).
	// Every record except gateway-wide health requires it.
	Name string
	// Connector is the harness connector (claudecode, codex, ...). It becomes
	// the record connector and is the only identity-like label on sandbox
	// metrics (defenseclaw.connector.source).
	Connector string
	// Runtime is SandboxRuntimeOpenShell.
	Runtime string
	// Driver is the OpenShell compute driver (SandboxDriver*).
	Driver string
	// ImageDigest is the workload image digest, sha256:<64 hex>.
	ImageDigest string
	// PolicyVersion is the OpenShell policy revision in force; 0 is unknown.
	PolicyVersion uint32
	// Profile is the network profile (SandboxProfile*).
	Profile string
	// Pack is the policy pack name.
	Pack string
	// Phase is the current phase, when known.
	Phase SandboxPhase
	// WorkdirMode is SandboxWorkdirMount or SandboxWorkdirCopy.
	WorkdirMode string
	// BindingID is the DefenseClaw ingress binding the sandbox's hooks and
	// egress proxy credential authenticate with (never its token).
	BindingID string
}

// SandboxLifecycleTrigger is what caused a lifecycle transition.
type SandboxLifecycleTrigger string

const (
	SandboxTriggerCreate    SandboxLifecycleTrigger = "create"
	SandboxTriggerStart     SandboxLifecycleTrigger = "start"
	SandboxTriggerStop      SandboxLifecycleTrigger = "stop"
	SandboxTriggerDelete    SandboxLifecycleTrigger = "delete"
	SandboxTriggerReconcile SandboxLifecycleTrigger = "reconcile"
	SandboxTriggerWatch     SandboxLifecycleTrigger = "watch"
)

// SandboxCondition is the OpenShell SandboxCondition behind a transition.
// Gateway-owned tokens that do not fit the registered shape are dropped rather
// than failing the record; Message is truncated to its registered bound.
type SandboxCondition struct {
	Type    string
	Status  string
	Reason  string
	Message string
}

// SandboxLifecycleEvent is one observed or initiated phase change. The new
// phase is Sandbox.Phase (required). PreviousPhase defaults to the last phase
// this recorder recorded for the same sandbox name; it stays absent otherwise.
// A transition from an unknown phase is counted only when it enters
// SandboxPhaseCreating, so a restarted daemon reconciling existing sandboxes
// or a repeated deleted event does not count a sandbox twice.
type SandboxLifecycleEvent struct {
	Sandbox       SandboxIdentity
	PreviousPhase SandboxPhase
	Trigger       SandboxLifecycleTrigger
	// ExitCode is the normalized main-process exit code (128+signal), set once
	// the main process has exited.
	ExitCode  *int32
	Condition *SandboxCondition
	// Severity overrides the phase default (error HIGH, unknown MEDIUM, else INFO).
	Severity  string
	Timestamp time.Time
}

// SandboxEgressSource identifies which boundary observed an egress decision.
// It populates defenseclaw.network.source and the egress metric source label.
type SandboxEgressSource string

const (
	SandboxEgressSourceOpenShell SandboxEgressSource = "openshell"
	SandboxEgressSourceProxy     SandboxEgressSource = "dc-egress-proxy"
)

// SandboxEgressEnd says how an allowed connection or request ended.
type SandboxEgressEnd string

const (
	// SandboxEgressCompleted: the connection or request finished
	// (log.egress.completed), with its byte counts and duration.
	SandboxEgressCompleted SandboxEgressEnd = "completed"
	// SandboxEgressFailed: the destination was allowed but DNS, the connect,
	// TLS or the upstream failed (log.egress.failed).
	SandboxEgressFailed SandboxEgressEnd = "failed"
)

// SandboxEgressEvent is one sandbox egress decision or, with End, the end
// of an allowed connection. A decision emits log.egress.allowed or
// log.egress.blocked and increments metric.defenseclaw.egress.events; an end
// emits log.egress.completed or log.egress.failed and no metric (the
// decision counted it).
type SandboxEgressEvent struct {
	Sandbox SandboxIdentity
	Source  SandboxEgressSource
	// End is empty for a decision.
	End SandboxEgressEnd
	// TimedOut marks a failure the proxy timed out on (End failed only):
	// its outcome is timed_out rather than failed.
	TimedOut bool
	// Terminated marks a connection the proxy cut short (End failed only):
	// the large-upload block, the idle timeout, a refused TLS server name or
	// content, or a recheck. Its outcome is cancelled, and it keeps its
	// byte counts.
	Terminated bool
	// BytesUp and BytesDown are the payload bytes an ended connection sent
	// and received (completed, and cut short); Duration how long it took
	// (completed and failed).
	BytesUp   int64
	BytesDown int64
	Duration  time.Duration
	// PID and Executable are the process OpenShell reported making the
	// connection. The workload chooses both, so they are display text; an
	// out-of-range PID or an executable that is not UTF-8 is omitted.
	PID        int
	Executable string
	// ConversationID is the harness session the sandbox's hooks last named;
	// it wins over the envelope's session for gen_ai.conversation.id. Both
	// are agent-chosen and omitted when not a registered identifier.
	ConversationID string
	// Host is the destination the sandboxed agent named: a host name, an IP
	// literal, or a host:port authority. It is canonicalized (port split off,
	// lowercased, IDNA-encoded); a value that cannot be is recorded as
	// target_ref invalid-host with server.address absent, never rejected.
	Host string
	// Port is the destination port; 0 takes the port of a host:port Host.
	// A value outside 1-65535 is omitted.
	Port int
	// Scheme is http or https when known.
	Scheme string
	// Path is the origin-form path of an absolute-form HTTP request. The query
	// and fragment are stripped before telemetry construction.
	Path string
	// ResolvedIP is the peer address the proxy actually dialed.
	ResolvedIP string
	Blocked    bool
	// DecisionCode is a stable machine token, for example SANDBOX_EGRESS_BLOCKLIST.
	DecisionCode string
	// Reason is the bounded human reason; each route's redaction profile applies.
	Reason string
	// PolicyOutcome is the source policy summary, for example the OpenShell rule.
	PolicyOutcome string
	// Severity overrides the default (MEDIUM when blocked, INFO when allowed).
	Severity  string
	Timestamp time.Time
	// UserID and UserName are the host account the sandbox runs as: a POSIX
	// uid and its bare account name.
	UserID   string
	UserName string
}

// SandboxApprovalStage selects approval.requested or approval.resolved.
type SandboxApprovalStage string

const (
	SandboxApprovalRequested SandboxApprovalStage = "requested"
	SandboxApprovalResolved  SandboxApprovalStage = "resolved"
)

// SandboxApprovalKind is what the approval would open.
type SandboxApprovalKind string

const (
	SandboxApprovalNetworkRule SandboxApprovalKind = "network_rule"
	SandboxApprovalHostPort    SandboxApprovalKind = "host_port"
)

// SandboxApprovalScope is how far a resolved approval applies.
type SandboxApprovalScope string

const (
	SandboxApprovalScopeSandbox SandboxApprovalScope = "sandbox"
	SandboxApprovalScopeAlways  SandboxApprovalScope = "always"
)

// Registered approval results and resolver types.
const (
	SandboxApprovalApproved  = "approved"
	SandboxApprovalDenied    = "denied"
	SandboxApprovalExpired   = "expired"
	SandboxApprovalCancelled = "cancelled"

	SandboxApprovalByOperator  = "operator"
	SandboxApprovalByAutomatic = "automatic"
	SandboxApprovalByPolicy    = "policy"
)

// SandboxApprovalEvent is one rare sandbox ask: an OpenShell draft proposal or
// a host-port consent. Result, ActorType, and Scope apply to resolutions only.
type SandboxApprovalEvent struct {
	Sandbox    SandboxIdentity
	Stage      SandboxApprovalStage
	ApprovalID string
	Kind       SandboxApprovalKind
	// Host and Port identify the destination the approval would open. They
	// are canonicalized like SandboxEgressEvent's; a host or port that cannot
	// be is omitted rather than failing the approval record.
	Host string
	Port int
	// Result is approved, denied, expired, or cancelled (resolved only).
	Result string
	// ActorType is operator, automatic (triage), or policy (resolved only).
	ActorType string
	// Scope is set for approvals only.
	Scope SandboxApprovalScope
	// Risky marks triage-classified risky reach (private, IP-literal, or
	// credentialed destinations).
	Risky bool
	// Reason is the bounded triage or operator reason.
	Reason    string
	Severity  string
	Timestamp time.Time
	// UserID and UserName are the host account that launched the sandbox.
	UserID   string
	UserName string
	// ConversationID is as SandboxEgressEvent's.
	ConversationID string
}

// SandboxPolicyOperation is the registered defenseclaw.admin.operation of a
// sandbox policy change.
type SandboxPolicyOperation string

const (
	// SandboxPolicyApply renders and applies the profile policy.
	SandboxPolicyApply SandboxPolicyOperation = "sandbox.policy.apply"
	// SandboxPolicyRuleAdd merges an approved draft or host-port rule.
	SandboxPolicyRuleAdd SandboxPolicyOperation = "sandbox.policy.rule_add"
	// SandboxPolicyRuleRemove withdraws a previously merged rule.
	SandboxPolicyRuleRemove SandboxPolicyOperation = "sandbox.policy.rule_remove"
	// SandboxEgressUnblock allows a blocklisted destination.
	SandboxEgressUnblock SandboxPolicyOperation = "sandbox.egress.unblock"
	// SandboxEgressBlock blocks a destination.
	SandboxEgressBlock SandboxPolicyOperation = "sandbox.egress.block"
)

// SandboxPolicyEvent is one applied (or no-op) sandbox policy change. The
// resulting OpenShell revision is Sandbox.PolicyVersion.
type SandboxPolicyEvent struct {
	Sandbox         SandboxIdentity
	Operation       SandboxPolicyOperation
	PreviousVersion uint32
	// PolicyHash is the lowercase hex SHA-256 OpenShell reports for the policy.
	PolicyHash string
	// Actor is a trusted actor reference such as cli:<user> or triage.
	Actor string
	// Origin is api, cli, internal, or triage.
	Origin string
	// Target is a bounded reference to what changed, for example a host or
	// an egress rule's host pattern as the decider spells it. The recorder
	// rewrites the two pattern forms the identifier shape cannot hold (see
	// sandboxPolicyTarget) and rejects any other target that is not an
	// identifier of at most 1024 bytes.
	Target string
	// Reason is a registered reason code (a stable token).
	Reason      string
	ChangeCount int
	NoChange    bool
	Timestamp   time.Time
}

// SandboxHealthState is the openshell subsystem health transition.
type SandboxHealthState string

const (
	SandboxHealthStarting SandboxHealthState = "starting"
	SandboxHealthReady    SandboxHealthState = "ready"
	SandboxHealthDegraded SandboxHealthState = "degraded"
	SandboxHealthFailed   SandboxHealthState = "failed"
	SandboxHealthRestored SandboxHealthState = "restored"
	SandboxHealthStopped  SandboxHealthState = "stopped"
)

// SandboxHealthEvent is one durable openshell subsystem health transition.
// Sandbox is optional: the zero value describes the gateway integration as a
// whole (for example the watch stream), not one sandbox.
type SandboxHealthEvent struct {
	Sandbox SandboxIdentity
	State   SandboxHealthState
	// ErrorCode is a stable token (lower case), typically a gatewaylog
	// error code in lower case: openshell_watch_failed, not
	// OPENSHELL_WATCH_FAILED, which the recorder refuses.
	ErrorCode    string
	ErrorSummary string
	Timestamp    time.Time
}

// SandboxFindingKind classifies sandbox findings.
type SandboxFindingKind string

const (
	// SandboxFindingOCSF is an OpenShell OCSF FINDING event.
	SandboxFindingOCSF SandboxFindingKind = "ocsf_finding"
	// SandboxFindingHookSilence is harness activity with no hook traffic.
	SandboxFindingHookSilence SandboxFindingKind = "hook_silence"
	// SandboxFindingHookTamper is a tool that ran without a DefenseClaw
	// verdict: a PostToolUse whose PreToolUse was denied or never arrived.
	SandboxFindingHookTamper SandboxFindingKind = "hook_tamper"
	// SandboxFindingLargeUpload is a large upload to a first-seen host.
	SandboxFindingLargeUpload SandboxFindingKind = "large_upload"
	// SandboxFindingNestedRepo is a repository (a .git entry or an index
	// gitlink) that appeared inside a live-mounted project during a session;
	// its configuration could run code when version control runs there on
	// the host.
	SandboxFindingNestedRepo SandboxFindingKind = "nested_repo"
	// SandboxFindingShadowAI is an AI API the sandbox reached (or tried to)
	// that is neither its model provider nor its harness's vendor: a
	// catalogued AI provider or an inference-shaped host.
	SandboxFindingShadowAI SandboxFindingKind = "shadow_ai"
)

// SandboxFindingEvent is one sandbox security observation, emitted as
// log.finding.observed with category sandbox.<kind>.
type SandboxFindingEvent struct {
	Sandbox SandboxIdentity
	Kind    SandboxFindingKind
	// FindingID is the stable occurrence ID; a UUID is generated when empty.
	FindingID string
	// RuleID defaults to SANDBOX-<KIND>.
	RuleID string
	// Severity is required: INFO, LOW, MEDIUM, HIGH, or CRITICAL.
	Severity    string
	Title       string
	Description string
	// Evidence is a bounded, already-minimized evidence summary.
	Evidence    string
	Remediation string
	// TargetRef is a reference such as a host or binary path token. It is cut
	// to the registered 256 bytes; a value that is not an identifier is
	// omitted, and neither case drops the finding.
	TargetRef string
	// Confidence is in (0, 1]; 0 means not reported.
	Confidence float64
	Timestamp  time.Time
	// UserID and UserName are the host account that launched the sandbox.
	UserID   string
	UserName string
}

// SandboxWorkspaceOperation is the workspace protection operation.
type SandboxWorkspaceOperation string

const (
	SandboxWorkspaceSnapshot SandboxWorkspaceOperation = "snapshot"
	SandboxWorkspaceUndo     SandboxWorkspaceOperation = "undo"
	SandboxWorkspaceMask     SandboxWorkspaceOperation = "mask"
	SandboxWorkspaceReview   SandboxWorkspaceOperation = "review"
	SandboxWorkspaceUpload   SandboxWorkspaceOperation = "upload"
	SandboxWorkspacePull     SandboxWorkspaceOperation = "pull"
	// SandboxWorkspaceQuarantine renames the .git entry of a nested
	// repository that appeared in a live-mounted project during a session,
	// so nothing on the host reads its configuration.
	SandboxWorkspaceQuarantine SandboxWorkspaceOperation = "quarantine"
)

// SandboxWorkspaceResult is the observed result of a workspace operation.
type SandboxWorkspaceResult string

const (
	SandboxWorkspaceApplied   SandboxWorkspaceResult = "applied"
	SandboxWorkspaceCompleted SandboxWorkspaceResult = "completed"
	SandboxWorkspaceFailed    SandboxWorkspaceResult = "failed"
	SandboxWorkspaceNoChange  SandboxWorkspaceResult = "no_change"
	SandboxWorkspacePartial   SandboxWorkspaceResult = "partial"
	SandboxWorkspaceSkipped   SandboxWorkspaceResult = "skipped"
)

// Registered workspace snapshot kinds and copy-mode pull modes.
const (
	SandboxSnapshotGit        = "git"
	SandboxSnapshotFilesystem = "filesystem"

	SandboxPullApply  = "apply"
	SandboxPullBranch = "branch"
	SandboxPullPatch  = "patch"
)

// SandboxWorkspaceEvent is one snapshot, undo, mask, review, upload, pull, or
// quarantine.
// Nil counts are omitted; zero is a reported value.
//
// Two kinds of record are mandatory, so no route's collection settings can
// drop them: an undo, a mask, a quarantine, or a pull applied to the working
// tree or to a branch (enforcement_state_change) unless its result is no_change or
// skipped, and any record that flags changed files that can run code on the
// host (enforced_outcome).
type SandboxWorkspaceEvent struct {
	Sandbox   SandboxIdentity
	Operation SandboxWorkspaceOperation
	// Result defaults to applied for undo, mask, and pull and to completed
	// for snapshot, review, and upload.
	Result SandboxWorkspaceResult
	// FailureClass is a stable token set when Result is failed or partial.
	FailureClass string
	// Initiator is who asked for the operation, for example operator.
	Initiator    string
	SnapshotKind string
	SnapshotRef  string
	PullMode     string
	FileCount    *int64
	LinesAdded   *int64
	LinesRemoved *int64
	// FlaggedCount is the number of changed files that can run code on the host.
	FlaggedCount *int64
	ByteCount    *int64
	// Paths are workspace-relative masked or flagged paths; the first 64 are
	// kept. Names come from the sandboxed agent, so they are sanitized, never
	// rejected: invalid UTF-8 is replaced, NUL bytes are dropped, and paths
	// that are absolute, drive-qualified, or escape the workspace are skipped.
	// The counts still describe every file.
	Paths []string
	// Severity overrides the default (HIGH when failed, MEDIUM when files were
	// flagged, else INFO).
	Severity  string
	Timestamp time.Time
}

// SandboxActivityKind selects the family of a sandbox activity record.
type SandboxActivityKind string

const (
	// SandboxActivityProcess is a process start or exit (log.sandbox.process).
	SandboxActivityProcess SandboxActivityKind = "process"
	// SandboxActivitySSH is an SSH listener or connection event of the
	// sandbox (log.sandbox.ssh).
	SandboxActivitySSH SandboxActivityKind = "ssh"
	// SandboxActivityInference is a model call OpenShell's inference route
	// reported (log.sandbox.inference).
	SandboxActivityInference SandboxActivityKind = "inference"
)

// SandboxActivityEvent is one observation of what runs in, or reaches
// into, a sandbox: a process start or exit, an SSH event, or a model call.
// Kind selects the family and which fields apply; the rest are ignored.
// Every value but the identity and the user comes from the workload or its
// supervisor, so a value that does not fit its registered shape is omitted,
// never allowed to fail the record.
type SandboxActivityEvent struct {
	Sandbox SandboxIdentity
	Kind    SandboxActivityKind
	// ProcessEvent is SandboxProcessStart or SandboxProcessExit (process,
	// required); ProcessSource is SandboxProcessSource* (default ocsf).
	ProcessEvent  string
	ProcessSource string
	// PID and Executable name the process (process).
	PID        int
	Executable string
	// CommandLine is the process's command line (process start); each
	// destination's redaction profile governs it.
	CommandLine string
	// ExitCode is the exit code of an exited process, when reported.
	ExitCode *int
	// SSHActivity is OpenShell's SSH activity (LISTEN, OPEN, ...; ssh,
	// required), SSHAllowed and SSHDenied its verdict when it reported one,
	// SSHAuth the scheme and Peer the remote address.
	SSHActivity string
	SSHAllowed  bool
	SSHDenied   bool
	SSHAuth     string
	Peer        string
	// Provider, Model, Status, Latency and Operation describe a model call
	// (inference). A status other than Success records a failed outcome.
	Provider  string
	Model     string
	Status    string
	Latency   time.Duration
	Operation string
	// UserID and UserName are the host account that launched the sandbox.
	UserID   string
	UserName string
	// ConversationID is as SandboxEgressEvent's (process and inference).
	ConversationID string
	Timestamp      time.Time
}

// SandboxRecorder implements SandboxTelemetry on top of the Logger's bound v8
// runtime. It also tracks the last recorded phase of each sandbox name so it
// can supply the previous phase and publish the
// metric.defenseclaw.sandbox.active gauge. The gauge is derived from this
// state, so a process holds one recorder.
type SandboxRecorder struct {
	logger *Logger

	// lifecycle serializes lifecycle records end to end. The tracked phase is
	// read, the log emitted, the new phase committed, and the gauge recorded
	// under it, so gauge points reach the runtime in the order the phases
	// changed (a gauge keeps the last value written) and a failed emission
	// leaves the tracked phase untouched for the caller's retry. Lifecycle
	// events are rare; the other producers never take it.
	lifecycle sync.Mutex
	phases    map[string]sandboxTrackedPhase
}

type sandboxTrackedPhase struct {
	connector string
	phase     SandboxPhase
}

var _ SandboxTelemetry = (*SandboxRecorder)(nil)

// NewSandboxRecorder binds the sandbox producers to logger. The Logger's v8
// runtime binding is read per record, so a runtime attached later is used and
// a detached runtime fails closed.
func NewSandboxRecorder(logger *Logger) *SandboxRecorder {
	return &SandboxRecorder{logger: logger, phases: make(map[string]sandboxTrackedPhase)}
}

const (
	maxSandboxNameBytes          = 128
	maxSandboxIDBytes            = 256
	maxSandboxConditionMessage   = 1024
	maxSandboxEgressReasonBytes  = 512
	maxSandboxEgressOutcomeBytes = 4096
	maxSandboxPathBytes          = 4096
	maxSandboxWorkspacePaths     = 64
	maxSandboxWorkspacePathBytes = 1024
	maxSandboxWorkspacePathTotal = 16384 // of the JSON-encoded path array
	maxSandboxFindingTextBytes   = 4096
	maxSandboxFindingEvidence    = 8192
	maxSandboxFindingTargetBytes = 256
	maxSandboxAuthorityBytes     = 1024
	maxSandboxHostBytes          = 253
	maxSandboxNetworkTargetBytes = 256 // defenseclaw.network.target_ref
	maxSandboxPolicyTargetBytes  = 1024
	maxSandboxBindingIDBytes     = 128
	maxSandboxCommandLineBytes   = 4096
	maxSandboxActivityTokenBytes = 64
	maxSandboxOperationBytes     = 128
	maxSandboxPID                = 4194304
	maxSandboxInferenceLatencyMs = 86400000
)

// sandboxInvalidHost is the target_ref of a destination that cannot be
// canonicalized; server.address is then absent.
const sandboxInvalidHost = "invalid-host"

// sandboxHostRefPrefix starts the reference of a DNS name whose first label
// starts with "_" (_dmarc.example, _x.example). Egress patterns and the
// proxy accept such names and resolvers look them up, but a registered
// identifier must start with a letter or digit, so the name is recorded as
// "host:_x.example" (as "*.example" becomes "suffix:example") and
// server.address, which must be the bare name, is omitted.
const sandboxHostRefPrefix = "host:"

var (
	sandboxIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	sandboxHostPattern       = regexp.MustCompile(`^[a-z0-9_][a-z0-9._-]*$`)
	sandboxUnderscoreName    = regexp.MustCompile(`^_[A-Za-z0-9._-]*$`)
	sandboxDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sandboxPolicyHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// RecordSandboxLifecycle emits log.sandbox.lifecycle and, when the phase
// changed, metric.defenseclaw.sandbox.transitions, then refreshes the
// metric.defenseclaw.sandbox.active gauge for the sandbox's connector. The
// new phase is tracked only once the log was accepted, so a failed call can be
// retried with the same event.
func (recorder *SandboxRecorder) RecordSandboxLifecycle(ctx context.Context, input SandboxLifecycleEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if !identity.Phase.Valid() {
		return fmt.Errorf("audit: sandbox lifecycle requires a registered phase")
	}
	if input.PreviousPhase != "" && !input.PreviousPhase.Valid() {
		return fmt.Errorf("audit: sandbox lifecycle previous phase %q is not registered", input.PreviousPhase)
	}
	if input.Trigger != "" && !input.Trigger.valid() {
		return fmt.Errorf("audit: sandbox lifecycle trigger %q is not registered", input.Trigger)
	}
	severity, err := sandboxSeverity(input.Severity, sandboxLifecycleSeverity(identity.Phase))
	if err != nil {
		return err
	}
	recorder.lifecycle.Lock()
	defer recorder.lifecycle.Unlock()
	previous := input.PreviousPhase
	if tracked, known := recorder.phases[identity.Name]; previous == "" && known {
		previous = tracked.phase
	}
	fields := sandboxV8FieldsFor(identity)
	condition := sandboxConditionFields(input.Condition)
	exitCode := observability.Absent[int64]()
	if input.ExitCode != nil {
		exitCode = observability.Present(int64(*input.ExitCode))
	}
	event := recorder.newEvent(ctx, ActionSandboxLifecycle, identity, identity.Name, severity, input.Timestamp)
	outcome := sandboxLifecycleOutcome(identity.Phase)
	log := sandboxV8Log{
		action: ActionSandboxLifecycle, event: event, bucket: observability.BucketAgentLifecycle,
		eventName: observability.TelemetryEventSandboxLifecycle, phase: "lifecycle", outcome: outcome,
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxLifecycle(observability.LogSandboxLifecycleInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: string(identity.Phase), DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				DefenseClawSandboxPhasePrevious:    optionalSandboxEnum(string(previous)),
				DefenseClawSandboxLifecycleTrigger: optionalSandboxEnum(string(input.Trigger)),
				DefenseClawSandboxExitCode:         exitCode,
				DefenseClawSandboxConditionType:    condition.kind,
				DefenseClawSandboxConditionStatus:  condition.status,
				DefenseClawSandboxConditionReason:  condition.reason,
				DefenseClawSandboxConditionMessage: condition.message,
			})
		},
	}
	binding, disposition, err := recorder.admit(ctx, log)
	if err != nil {
		return err
	}
	activeCounts := recorder.commitPhaseLocked(identity.Name, identity.Connector, identity.Phase)
	// Gauges lead the batch: a batch stops at its first failure, and a lost
	// gauge point stays stale until the next lifecycle event.
	metrics := make([]RuntimeV8GeneratedMetric, 0, len(activeCounts)+1)
	for _, count := range activeCounts {
		metrics = append(metrics, newSandboxActiveMetric(event, count.connector, count.active))
	}
	if previous != identity.Phase && (previous != "" || identity.Phase == SandboxPhaseCreating) {
		metrics = append(metrics, newSandboxTransitionMetric(event, identity.Connector, previous, identity.Phase))
	}
	recorder.recordCompanions(ctx, binding, log, disposition, metrics)
	return nil
}

// RecordSandboxEgress emits log.egress.allowed or log.egress.blocked with the
// sandbox correlation and increments metric.defenseclaw.egress.events with
// source openshell or dc-egress-proxy, labelled with the sandbox's
// connector. A blocked decision is mandatory. The end of an allowed
// connection (End) emits log.egress.completed or log.egress.failed instead,
// with no metric. The destination is agent-chosen, so no host or port value
// fails the record. Neither does the session or agent ID: the agent fills
// both through the correlation envelope or its hooks, so a value that is not
// a registered identifier is omitted (see sandboxAgentCorrelation).
func (recorder *SandboxRecorder) RecordSandboxEgress(ctx context.Context, input SandboxEgressEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if input.Source != SandboxEgressSourceOpenShell && input.Source != SandboxEgressSourceProxy {
		return fmt.Errorf("audit: sandbox egress source %q is not registered", input.Source)
	}
	switch input.End {
	case "":
		if input.TimedOut {
			return fmt.Errorf("audit: only a failed sandbox egress record times out")
		}
		if input.Terminated {
			return fmt.Errorf("audit: only a failed sandbox egress record is cut short")
		}
	case SandboxEgressCompleted, SandboxEgressFailed:
		if input.Blocked {
			return fmt.Errorf("audit: a blocked sandbox egress decision has no end")
		}
		if input.TimedOut && input.End != SandboxEgressFailed {
			return fmt.Errorf("audit: only a failed sandbox egress record times out")
		}
		if input.Terminated && (input.End != SandboxEgressFailed || input.TimedOut) {
			return fmt.Errorf("audit: only a failed sandbox egress record that did not time out is cut short")
		}
	default:
		return fmt.Errorf("audit: sandbox egress end %q is not registered", input.End)
	}
	if input.BytesUp < 0 || input.BytesDown < 0 || input.Duration < 0 {
		return fmt.Errorf("audit: sandbox egress byte counts and duration must not be negative")
	}
	destination := canonicalSandboxDestination(input.Host, input.Port)
	host, serverAddress, port := destination.ref(), destination.address(), destination.port
	if !destination.canonical {
		host = sandboxInvalidHost
	}
	defaultSeverity := "INFO"
	if input.Blocked {
		defaultSeverity = "MEDIUM"
	}
	severity, err := sandboxSeverity(input.Severity, defaultSeverity)
	if err != nil {
		return err
	}
	resolvedIP := observability.Absent[string]()
	if input.ResolvedIP != "" {
		ip := net.ParseIP(strings.TrimSpace(input.ResolvedIP))
		if ip == nil {
			return fmt.Errorf("audit: sandbox egress resolved IP is not an address")
		}
		resolvedIP = observability.Present(sandboxIPIdentifier(ip))
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxEgress, identity, host, severity, input.Timestamp)
	decision, eventName, outcome := "allow", observability.TelemetryEventEgressAllowed, observability.OutcomeAllowed
	switch {
	case input.Blocked:
		decision, eventName, outcome = "block", observability.TelemetryEventEgressBlocked, observability.OutcomeBlocked
	case input.End == SandboxEgressCompleted:
		eventName, outcome = observability.TelemetryEventEgressCompleted, observability.OutcomeCompleted
	case input.End == SandboxEgressFailed && input.TimedOut:
		eventName, outcome = observability.TelemetryEventEgressFailed, observability.OutcomeTimedOut
	case input.End == SandboxEgressFailed && input.Terminated:
		eventName, outcome = observability.TelemetryEventEgressFailed, observability.OutcomeCancelled
	case input.End == SandboxEgressFailed:
		eventName, outcome = observability.TelemetryEventEgressFailed, observability.OutcomeFailed
	}
	source := observability.Present(string(input.Source))
	path := sandboxEgressPath(input.Path)
	scheme := optionalNetworkScheme(input.Scheme)
	reason := optionalSandboxText(input.Reason, maxSandboxEgressReasonBytes)
	policyOutcome := optionalSandboxText(input.PolicyOutcome, maxSandboxEgressOutcomeBytes)
	decisionCode := optionalNetworkIdentifier(input.DecisionCode)
	conversationID, agentID := sandboxAgentCorrelation(event, input.ConversationID)
	bytesUp, bytesDown, duration := observability.Absent[int64](), observability.Absent[int64](), observability.Absent[int64]()
	// OpenShell's record of a connection it closed (a policy reload)
	// counts neither bytes nor time; the proxy's ends do.
	if input.Source == SandboxEgressSourceProxy && (input.End == SandboxEgressCompleted || input.Terminated) {
		bytesUp, bytesDown = observability.Present(input.BytesUp), observability.Present(input.BytesDown)
	}
	if input.Source == SandboxEgressSourceProxy && input.End != "" {
		duration = observability.Present(input.Duration.Milliseconds())
	}
	actorPID, actorExe := optionalSandboxPID(input.PID), optionalSandboxText(input.Executable, maxSandboxPathBytes)
	log := sandboxV8Log{
		action: ActionSandboxEgress, event: event, bucket: observability.BucketNetworkEgress,
		eventName: eventName, phase: "policy", outcome: outcome, mandatory: input.Blocked,
		facts:    observability.MandatoryFacts{EnforcedOutcome: input.Blocked},
		enforced: input.Blocked,
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			allowed := observability.LogEgressAllowedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				GenAIConversationID:         conversationID,
				GenAIAgentID:                agentID,
				UserID:                      optionalNetworkIdentifier(input.UserID),
				DefenseClawUserIDKind:       optionalNetworkUserIDKind(useridentity.KindForID(input.UserID)),
				DefenseClawUserName:         optionalNetworkIdentifier(input.UserName),
				DefenseClawNetworkTargetRef: host, DefenseClawNetworkTargetPath: path,
				DefenseClawNetworkResolvedIp: resolvedIP, DefenseClawNetworkPolicyOutcome: policyOutcome,
				DefenseClawNetworkDecision: observability.Present(decision), DefenseClawNetworkDecisionCode: decisionCode,
				DefenseClawNetworkReason: reason, DefenseClawNetworkSource: source,
				DefenseClawNetworkBlocked: observability.Present(input.Blocked),
				URLScheme:                 scheme, ServerAddress: serverAddress, ServerPort: port,
				DefenseClawNetworkBytesUp: bytesUp, DefenseClawNetworkBytesDown: bytesDown,
				DefenseClawNetworkDurationMs: duration,
				DefenseClawSandboxProcessPid: actorPID, DefenseClawSandboxProcessExecutable: actorExe,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID: fields.bindingID,
			}
			switch eventName {
			case observability.TelemetryEventEgressCompleted:
				return builder.BuildLogEgressCompleted(observability.LogEgressCompletedInput(allowed))
			case observability.TelemetryEventEgressFailed:
				return builder.BuildLogEgressFailed(observability.LogEgressFailedInput(allowed))
			case observability.TelemetryEventEgressAllowed:
				return builder.BuildLogEgressAllowed(allowed)
			}
			return builder.BuildLogEgressBlocked(observability.LogEgressBlockedInput{
				Envelope: allowed.Envelope, Severity: allowed.Severity, LogLevel: allowed.LogLevel,
				Outcome: allowed.Outcome, GenAIConversationID: allowed.GenAIConversationID,
				GenAIAgentID: allowed.GenAIAgentID,
				UserID:       allowed.UserID, DefenseClawUserIDKind: allowed.DefenseClawUserIDKind,
				DefenseClawUserName:         allowed.DefenseClawUserName,
				DefenseClawNetworkTargetRef: host, DefenseClawNetworkTargetPath: path,
				DefenseClawNetworkResolvedIp: resolvedIP, DefenseClawNetworkPolicyOutcome: policyOutcome,
				DefenseClawNetworkDecision: allowed.DefenseClawNetworkDecision, DefenseClawNetworkDecisionCode: decisionCode,
				DefenseClawNetworkReason: reason, DefenseClawNetworkSource: source,
				DefenseClawNetworkBlocked: allowed.DefenseClawNetworkBlocked,
				URLScheme:                 scheme, ServerAddress: allowed.ServerAddress, ServerPort: port,
				DefenseClawSandboxProcessPid: actorPID, DefenseClawSandboxProcessExecutable: actorExe,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID: fields.bindingID,
				MandatoryEnforcedOutcome:    true,
			})
		},
	}
	var metrics []RuntimeV8GeneratedMetric
	if input.End == "" {
		metrics = append(metrics, newSandboxEgressMetric(event, identity.Connector, decision, string(input.Source)))
	}
	return recorder.emit(ctx, log, metrics)
}

// RecordSandboxApproval emits log.approval.requested or log.approval.resolved
// for a sandbox ask. A resolution is mandatory (approval_resolution).
func (recorder *SandboxRecorder) RecordSandboxApproval(ctx context.Context, input SandboxApprovalEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	approvalID := strings.TrimSpace(input.ApprovalID)
	if !runtimeV8Identifier(approvalID) {
		return fmt.Errorf("audit: sandbox approval requires a stable approval id")
	}
	if input.Kind != SandboxApprovalNetworkRule && input.Kind != SandboxApprovalHostPort {
		return fmt.Errorf("audit: sandbox approval kind %q is not registered", input.Kind)
	}
	destination := canonicalSandboxDestination(input.Host, input.Port)
	host, port := destination.address(), destination.port
	severity, err := sandboxSeverity(input.Severity, "INFO")
	if err != nil {
		return err
	}
	resolved := false
	outcome := observability.OutcomeAttempted
	eventName := observability.TelemetryEventApprovalRequested
	switch input.Stage {
	case SandboxApprovalRequested:
		if input.Result != "" || input.ActorType != "" || input.Scope != "" {
			return fmt.Errorf("audit: a requested sandbox approval must not carry a resolution")
		}
	case SandboxApprovalResolved:
		resolved = true
		eventName = observability.TelemetryEventApprovalResolved
		var ok bool
		if outcome, ok = sandboxApprovalOutcome(input.Result); !ok {
			return fmt.Errorf("audit: sandbox approval result %q is not registered", input.Result)
		}
		switch input.ActorType {
		case "", SandboxApprovalByOperator, SandboxApprovalByAutomatic, SandboxApprovalByPolicy:
		default:
			return fmt.Errorf("audit: sandbox approval actor type %q is not registered", input.ActorType)
		}
		switch input.Scope {
		case "":
		case SandboxApprovalScopeSandbox, SandboxApprovalScopeAlways:
			if input.Result != SandboxApprovalApproved {
				return fmt.Errorf("audit: only an approved sandbox approval has a scope")
			}
		default:
			return fmt.Errorf("audit: sandbox approval scope %q is not registered", input.Scope)
		}
	default:
		return fmt.Errorf("audit: sandbox approval stage %q is not registered", input.Stage)
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxApproval, identity, approvalID, severity, input.Timestamp)
	reason := optionalSandboxText(input.Reason, maxSandboxFindingTextBytes)
	kind := observability.Present(string(input.Kind))
	risky := observability.Present(input.Risky)
	conversationID, agentID := sandboxAgentCorrelation(event, input.ConversationID)
	userID := optionalNetworkIdentifier(input.UserID)
	userKind := optionalNetworkUserIDKind(useridentity.KindForID(input.UserID))
	userName := optionalNetworkIdentifier(input.UserName)
	log := sandboxV8Log{
		action: ActionSandboxApproval, event: event, bucket: observability.BucketComplianceActivity,
		eventName: eventName, phase: "approval", outcome: outcome, mandatory: resolved,
		facts: observability.MandatoryFacts{ApprovalResolution: resolved},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			if !resolved {
				return builder.BuildLogApprovalRequested(observability.LogApprovalRequestedInput{
					Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
					GenAIConversationID: conversationID,
					GenAIAgentID:        agentID,
					UserID:              userID, DefenseClawUserIDKind: userKind, DefenseClawUserName: userName,
					DefenseClawApprovalID: approvalID, DefenseClawApprovalDangerous: risky,
					DefenseClawGuardrailReason: reason, DefenseClawSandboxApprovalKind: kind,
					ServerAddress: host, ServerPort: port,
					DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name,
					DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
					DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
					DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
					DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				})
			}
			return builder.BuildLogApprovalResolved(observability.LogApprovalResolvedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				GenAIConversationID: conversationID,
				GenAIAgentID:        agentID,
				UserID:              userID, DefenseClawUserIDKind: userKind, DefenseClawUserName: userName,
				DefenseClawApprovalID: approvalID, DefenseClawApprovalResult: input.Result,
				DefenseClawApprovalActorType: optionalSandboxEnum(input.ActorType),
				DefenseClawApprovalDangerous: risky, DefenseClawGuardrailReason: reason,
				DefenseClawSandboxApprovalKind:  kind,
				DefenseClawSandboxApprovalScope: optionalSandboxEnum(string(input.Scope)),
				ServerAddress:                   host, ServerPort: port,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				MandatoryApprovalResolution: true,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}

// RecordSandboxPolicy emits log.policy.updated for a sandbox policy change.
// Policy changes are control-plane mutations and therefore mandatory.
func (recorder *SandboxRecorder) RecordSandboxPolicy(ctx context.Context, input SandboxPolicyEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if !input.Operation.valid() {
		return fmt.Errorf("audit: sandbox policy operation %q is not registered", input.Operation)
	}
	switch input.Origin {
	case "", "api", "cli", "internal", "triage":
	default:
		return fmt.Errorf("audit: sandbox policy origin %q is not registered", input.Origin)
	}
	if input.ChangeCount < 0 {
		return fmt.Errorf("audit: sandbox policy change count must not be negative")
	}
	if input.PolicyHash != "" && !sandboxPolicyHashPattern.MatchString(input.PolicyHash) {
		return fmt.Errorf("audit: sandbox policy hash must be lowercase hex sha256")
	}
	if input.Reason != "" && !observability.IsStableToken(input.Reason) {
		return fmt.Errorf("audit: sandbox policy reason must be a registered reason code")
	}
	target, err := sandboxPolicyTarget(input.Target)
	if err != nil {
		return err
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxPolicy, identity, identity.Name, "INFO", input.Timestamp)
	if strings.TrimSpace(input.Actor) != "" {
		event.Actor = strings.TrimSpace(input.Actor)
	}
	principal, principalKnown := controlPlaneV8Principal(event.Actor)
	outcome := observability.OutcomeApplied
	if input.NoChange {
		outcome = observability.OutcomeNoChange
	}
	revision, current := sandboxPolicyRevision(identity.PolicyVersion), sandboxPolicyRevision(input.PreviousVersion)
	afterSummary := observability.Absent[string]()
	if input.PolicyHash != "" {
		afterSummary = observability.Present("sha256:" + input.PolicyHash)
	}
	log := sandboxV8Log{
		action: ActionSandboxPolicy, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventPolicyUpdated, phase: "apply", outcome: outcome, mandatory: true,
		facts: observability.MandatoryFacts{ControlPlaneMutation: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogPolicyUpdated(observability.LogPolicyUpdatedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawAdminOperation:    string(input.Operation),
				DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
				DefenseClawAdminActorRef:        optionalControlPlaneV8Actor(event.Actor),
				DefenseClawAdminOrigin:          optionalSandboxEnum(input.Origin),
				DefenseClawAdminTargetRef:       target,
				DefenseClawAdminAfterSummary:    afterSummary,
				DefenseClawAdminReason:          optionalControlPlaneV8Reason(input.Reason),
				DefenseClawAdminRevision:        revision,
				DefenseClawAdminCurrentRevision: current,
				DefenseClawAdminChangeCount:     observability.Present(int64(input.ChangeCount)),
				DefenseClawSandboxID:            fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				MandatoryControlPlaneMutation: true,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}

// RecordSandboxHealth emits one durable log.subsystem.* transition for the
// openshell subsystem.
func (recorder *SandboxRecorder) RecordSandboxHealth(ctx context.Context, input SandboxHealthEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(false); err != nil {
		return err
	}
	if input.ErrorCode != "" && !observability.IsStableToken(input.ErrorCode) {
		return fmt.Errorf("audit: sandbox health error code must be a stable token")
	}
	var (
		eventName   string
		outcome     observability.Outcome
		severity    string
		healthState string
	)
	switch input.State {
	case SandboxHealthStarting:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemLifecycle, observability.OutcomeAttempted, "INFO", "starting"
	case SandboxHealthStopped:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemLifecycle, observability.OutcomeCompleted, "INFO", "stopped"
	case SandboxHealthReady:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemReady, observability.OutcomeCompleted, "INFO", "ready"
	case SandboxHealthRestored:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemRestored, observability.OutcomeCompleted, "INFO", "restored"
	case SandboxHealthDegraded:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemDegraded, observability.OutcomeFailed, "HIGH", "degraded"
	case SandboxHealthFailed:
		eventName, outcome, severity, healthState = observability.TelemetryEventSubsystemDegraded, observability.OutcomeFailed, "HIGH", "failed"
	default:
		return fmt.Errorf("audit: sandbox health state %q is not registered", input.State)
	}
	subsystem := string(gatewaylog.SubsystemOpenShell)
	fields := sandboxV8FieldsFor(identity)
	target := identity.Name
	if target == "" {
		target = subsystem
	}
	event := recorder.newEvent(ctx, ActionSandboxHealth, identity, target, severity, input.Timestamp)
	errorCode := optionalSandboxEnum(input.ErrorCode)
	errorSummary := optionalSandboxText(input.ErrorSummary, 65536)
	log := sandboxV8Log{
		action: ActionSandboxHealth, event: event, bucket: observability.BucketPlatformHealth,
		eventName: eventName, phase: "health", outcome: outcome, mandatory: true,
		facts: observability.MandatoryFacts{DurableHealthTransition: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			ready := observability.LogSubsystemReadyInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawHealthSubsystem: subsystem, DefenseClawHealthState: healthState,
				DefenseClawHealthErrorSummary: errorSummary, DefenseClawSchemaErrorCode: errorCode,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				MandatoryDurableHealthTransition: true,
			}
			switch eventName {
			case observability.TelemetryEventSubsystemLifecycle:
				return builder.BuildLogSubsystemLifecycle(observability.LogSubsystemLifecycleInput(ready))
			case observability.TelemetryEventSubsystemRestored:
				return builder.BuildLogSubsystemRestored(observability.LogSubsystemRestoredInput(ready))
			case observability.TelemetryEventSubsystemDegraded:
				return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
					Envelope: ready.Envelope, Severity: ready.Severity, LogLevel: ready.LogLevel,
					Outcome: ready.Outcome, DefenseClawHealthSubsystem: subsystem,
					DefenseClawHealthState: healthState, DefenseClawHealthErrorSummary: errorSummary,
					DefenseClawSchemaErrorCode: errorCode,
					DefenseClawSandboxID:       fields.id, DefenseClawSandboxName: fields.name,
					DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
					DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
					DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
					DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
					MandatoryDurableHealthTransition: true,
				})
			default:
				return builder.BuildLogSubsystemReady(ready)
			}
		},
	}
	return recorder.emit(ctx, log, nil)
}

// RecordSandboxFinding emits log.finding.observed for an OCSF FINDING event,
// hook silence or tamper, a large upload, a nested repository, or shadow AI.
func (recorder *SandboxRecorder) RecordSandboxFinding(ctx context.Context, input SandboxFindingEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if !input.Kind.valid() {
		return fmt.Errorf("audit: sandbox finding kind %q is not registered", input.Kind)
	}
	normalized := observability.NormalizeSeverity(input.Severity)
	if !normalized.Valid || !normalized.Present {
		return fmt.Errorf("audit: sandbox finding requires a canonical severity")
	}
	findingID := strings.TrimSpace(input.FindingID)
	if findingID == "" {
		findingID = uuid.NewString()
	}
	if !runtimeV8Identifier(findingID) {
		return fmt.Errorf("audit: sandbox finding id is not a stable identifier")
	}
	ruleID := strings.TrimSpace(input.RuleID)
	if ruleID == "" {
		ruleID = input.Kind.defaultRuleID()
	}
	if !runtimeV8Identifier(ruleID) {
		return fmt.Errorf("audit: sandbox finding rule id is not a stable identifier")
	}
	if math.IsNaN(input.Confidence) || input.Confidence < 0 || input.Confidence > 1 {
		return fmt.Errorf("audit: sandbox finding confidence must be within [0, 1]")
	}
	confidence := observability.Absent[float64]()
	if input.Confidence > 0 {
		confidence = observability.Present(input.Confidence)
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxFinding, identity, identity.Name, string(normalized.Severity), input.Timestamp)
	event.FindingOccurrenceID = findingID
	category := "sandbox." + string(input.Kind)
	log := sandboxV8Log{
		action: ActionSandboxFinding, event: event, bucket: observability.BucketSecurityFinding,
		eventName: observability.TelemetryEventFindingObserved, phase: "finding",
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogFindingObserved(observability.LogFindingObservedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				DefenseClawFindingID: findingID, DefenseClawFindingRuleID: ruleID,
				DefenseClawFindingCategory:          observability.Present(category),
				DefenseClawSecuritySeverity:         string(normalized.Severity),
				DefenseClawFindingConfidence:        confidence,
				DefenseClawFindingTargetRef:         optionalSandboxFindingTarget(input.TargetRef),
				DefenseClawGuardrailEvidenceSummary: optionalSandboxText(input.Evidence, maxSandboxFindingEvidence),
				DefenseClawFindingTitle:             optionalSandboxText(input.Title, maxSandboxFindingTextBytes),
				DefenseClawFindingDescription:       optionalSandboxText(input.Description, maxSandboxFindingTextBytes),
				DefenseClawFindingRemediation:       optionalSandboxText(input.Remediation, maxSandboxFindingTextBytes),
				UserID:                              optionalNetworkIdentifier(input.UserID),
				DefenseClawUserIDKind:               optionalNetworkUserIDKind(useridentity.KindForID(input.UserID)),
				DefenseClawUserName:                 optionalNetworkIdentifier(input.UserName),
				DefenseClawSandboxID:                fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}

// RecordSandboxWorkspace emits log.sandbox.workspace in the
// enforcement.action bucket. State-changing operations and flagged reviews
// are mandatory; see SandboxWorkspaceEvent.
func (recorder *SandboxRecorder) RecordSandboxWorkspace(ctx context.Context, input SandboxWorkspaceEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if !input.Operation.valid() {
		return fmt.Errorf("audit: sandbox workspace operation %q is not registered", input.Operation)
	}
	result := input.Result
	if result == "" {
		result = input.Operation.defaultResult()
	}
	outcome, ok := result.outcome()
	if !ok {
		return fmt.Errorf("audit: sandbox workspace result %q is not registered", input.Result)
	}
	switch input.SnapshotKind {
	case "", SandboxSnapshotGit, SandboxSnapshotFilesystem:
	default:
		return fmt.Errorf("audit: sandbox workspace snapshot kind %q is not registered", input.SnapshotKind)
	}
	switch input.PullMode {
	case "", SandboxPullApply, SandboxPullBranch, SandboxPullPatch:
	default:
		return fmt.Errorf("audit: sandbox workspace pull mode %q is not registered", input.PullMode)
	}
	if input.SnapshotRef != "" && !sandboxIdentifier(input.SnapshotRef, 512) {
		return fmt.Errorf("audit: sandbox workspace snapshot ref is not a bounded reference")
	}
	if input.FailureClass != "" && !observability.IsStableToken(input.FailureClass) {
		return fmt.Errorf("audit: sandbox workspace failure class must be a stable token")
	}
	initiator := strings.TrimSpace(input.Initiator)
	if initiator != "" && !runtimeV8Identifier(initiator) {
		return fmt.Errorf("audit: sandbox workspace initiator is not a stable identifier")
	}
	counts := map[string]*int64{
		"file": input.FileCount, "lines added": input.LinesAdded, "lines removed": input.LinesRemoved,
		"flagged": input.FlaggedCount, "byte": input.ByteCount,
	}
	for name, count := range counts {
		if count != nil && *count < 0 {
			return fmt.Errorf("audit: sandbox workspace %s count must not be negative", name)
		}
	}
	paths := sandboxWorkspacePaths(input.Paths)
	flagged := input.FlaggedCount != nil && *input.FlaggedCount > 0
	// A failed or partial state change may have written part of the change
	// before it stopped, so only a no-op result is exempt.
	stateChange := input.Operation.changesState(input.PullMode) &&
		result != SandboxWorkspaceNoChange && result != SandboxWorkspaceSkipped
	defaultSeverity := "INFO"
	switch {
	case result == SandboxWorkspaceFailed:
		defaultSeverity = "HIGH"
	case flagged:
		defaultSeverity = "MEDIUM"
	}
	severity, err := sandboxSeverity(input.Severity, defaultSeverity)
	if err != nil {
		return err
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxWorkspace, identity, identity.Name, severity, input.Timestamp)
	log := sandboxV8Log{
		action: ActionSandboxWorkspace, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxWorkspace, phase: "workspace", outcome: outcome,
		mandatory: flagged || stateChange,
		facts:     observability.MandatoryFacts{EnforcedOutcome: flagged, EnforcementStateChange: stateChange},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxWorkspace(observability.LogSandboxWorkspaceInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode, DefenseClawSandboxBindingID: fields.bindingID,
				DefenseClawEnforcementEffectiveAction:   observability.Present(string(input.Operation)),
				DefenseClawEnforcementInitiator:         optionalSandboxEnum(initiator),
				DefenseClawEnforcementFailureClass:      optionalSandboxEnum(input.FailureClass),
				DefenseClawSandboxWorkspaceOperation:    string(input.Operation),
				DefenseClawSandboxWorkspaceSnapshotKind: optionalSandboxEnum(input.SnapshotKind),
				DefenseClawSandboxWorkspaceSnapshotRef:  optionalSandboxEnum(input.SnapshotRef),
				DefenseClawSandboxWorkspacePullMode:     optionalSandboxEnum(input.PullMode),
				DefenseClawSandboxWorkspaceFileCount:    optionalSandboxCount(input.FileCount),
				DefenseClawSandboxWorkspaceLinesAdded:   optionalSandboxCount(input.LinesAdded),
				DefenseClawSandboxWorkspaceLinesRemoved: optionalSandboxCount(input.LinesRemoved),
				DefenseClawSandboxWorkspaceFlaggedCount: optionalSandboxCount(input.FlaggedCount),
				DefenseClawSandboxWorkspaceByteCount:    optionalSandboxCount(input.ByteCount),
				DefenseClawSandboxWorkspacePaths:        paths,
				MandatoryEnforcedOutcome:                flagged,
				MandatoryEnforcementStateChange:         stateChange,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}

// RecordSandboxActivity emits log.sandbox.process, log.sandbox.ssh or
// log.sandbox.inference (by Kind). None is mandatory: the manager bounds
// them per sandbox, and a route's collection settings decide whether they
// leave the host. Only the sandbox identity can fail the record; every
// workload-reported value that does not fit is omitted.
func (recorder *SandboxRecorder) RecordSandboxActivity(ctx context.Context, input SandboxActivityEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	var (
		eventName string
		bucket    observability.Bucket
		outcome   observability.Outcome
		target    = identity.Name
	)
	switch input.Kind {
	case SandboxActivityProcess:
		eventName, bucket = observability.TelemetryEventSandboxProcess, observability.BucketToolActivity
		switch input.ProcessEvent {
		case SandboxProcessStart:
			outcome = observability.OutcomeAttempted
		case SandboxProcessExit:
			outcome = observability.OutcomeCompleted
			if input.ExitCode != nil && *input.ExitCode != 0 {
				outcome = observability.OutcomeFailed
			}
		default:
			return fmt.Errorf("audit: sandbox process event %q is not registered", input.ProcessEvent)
		}
		switch input.ProcessSource {
		case "", SandboxProcessSourceOCSF, SandboxProcessSourceSample:
		default:
			return fmt.Errorf("audit: sandbox process source %q is not registered", input.ProcessSource)
		}
	case SandboxActivitySSH:
		eventName, bucket = observability.TelemetryEventSandboxSsh, observability.BucketComplianceActivity
		if !sandboxIdentifier(strings.TrimSpace(input.SSHActivity), maxSandboxActivityTokenBytes) {
			return fmt.Errorf("audit: a sandbox ssh record requires its activity")
		}
		switch {
		case input.SSHDenied:
			outcome = observability.OutcomeBlocked
		case input.SSHAllowed:
			outcome = observability.OutcomeAllowed
		default:
			outcome = observability.OutcomeCompleted
		}
	case SandboxActivityInference:
		eventName, bucket = observability.TelemetryEventSandboxInference, observability.BucketModelIO
		// A record without a status (OpenShell's is optional) says nothing
		// of a failure.
		outcome = observability.OutcomeCompleted
		if status := strings.TrimSpace(input.Status); status != "" && !strings.EqualFold(status, "success") {
			outcome = observability.OutcomeFailed
		}
	default:
		return fmt.Errorf("audit: sandbox activity kind %q is not registered", input.Kind)
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxActivity, identity, target, "INFO", input.Timestamp)
	conversationID, _ := sandboxAgentCorrelation(event, input.ConversationID)
	userID := optionalNetworkIdentifier(input.UserID)
	userKind := optionalNetworkUserIDKind(useridentity.KindForID(input.UserID))
	userName := optionalNetworkIdentifier(input.UserName)
	log := sandboxV8Log{
		action: ActionSandboxActivity, event: event, bucket: bucket, eventName: eventName, phase: "activity", outcome: outcome,
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			switch input.Kind {
			case SandboxActivityProcess:
				source := input.ProcessSource
				if source == "" {
					source = SandboxProcessSourceOCSF
				}
				exitCode := observability.Absent[int64]()
				if input.ExitCode != nil && input.ProcessEvent == SandboxProcessExit {
					exitCode = observability.Present(int64(*input.ExitCode))
				}
				commandLine := observability.Absent[string]()
				if input.ProcessEvent == SandboxProcessStart {
					commandLine = optionalSandboxText(input.CommandLine, maxSandboxCommandLineBytes)
				}
				return builder.BuildLogSandboxProcess(observability.LogSandboxProcessInput{
					Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
					DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
					DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
					DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
					DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
					DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
					DefenseClawSandboxBindingID:          fields.bindingID,
					DefenseClawSandboxProcessEvent:       input.ProcessEvent,
					DefenseClawSandboxProcessSource:      observability.Present(source),
					DefenseClawSandboxProcessPid:         optionalSandboxPID(input.PID),
					DefenseClawSandboxProcessExecutable:  optionalSandboxText(input.Executable, maxSandboxPathBytes),
					DefenseClawSandboxProcessCommandLine: commandLine,
					DefenseClawSandboxProcessExitCode:    exitCode,
					UserID:                               userID, DefenseClawUserIDKind: userKind, DefenseClawUserName: userName,
					GenAIConversationID: conversationID,
				})
			case SandboxActivitySSH:
				return builder.BuildLogSandboxSsh(observability.LogSandboxSshInput{
					Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
					DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
					DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
					DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
					DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
					DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
					DefenseClawSandboxBindingID:   fields.bindingID,
					DefenseClawSandboxSshActivity: strings.TrimSpace(input.SSHActivity),
					DefenseClawSandboxSshAuth:     optionalSandboxToken(input.SSHAuth, maxSandboxActivityTokenBytes),
					ClientAddress:                 optionalSandboxPeer(input.Peer),
					UserID:                        userID, DefenseClawUserIDKind: userKind, DefenseClawUserName: userName,
				})
			default:
				latency := observability.Absent[int64]()
				if ms := input.Latency.Milliseconds(); ms >= 0 && ms <= maxSandboxInferenceLatencyMs && input.Latency > 0 {
					latency = observability.Present(ms)
				}
				return builder.BuildLogSandboxInference(observability.LogSandboxInferenceInput{
					Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
					DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
					DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
					DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
					DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
					DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
					DefenseClawSandboxBindingID:          fields.bindingID,
					GenAIProviderName:                    optionalSandboxText(strings.ToLower(input.Provider), maxSandboxOperationBytes),
					GenAIRequestModel:                    optionalSandboxToken(input.Model, 256),
					DefenseClawSandboxInferenceStatus:    optionalSandboxToken(input.Status, maxSandboxActivityTokenBytes),
					DefenseClawSandboxInferenceLatencyMs: latency,
					DefenseClawSandboxInferenceOperation: optionalSandboxToken(input.Operation, maxSandboxOperationBytes),
					UserID:                               userID, DefenseClawUserIDKind: userKind, DefenseClawUserName: userName,
					GenAIConversationID: conversationID,
				})
			}
		},
	}
	return recorder.emit(ctx, log, nil)
}

// optionalSandboxToken keeps a workload-reported token that is a bounded
// identifier, else omits it.
func optionalSandboxToken(value string, maxBytes int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if !sandboxIdentifier(value, maxBytes) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

// optionalSandboxPeer is the address of a sandbox SSH peer as
// client.address: an IP literal (its port dropped), else omitted.
func optionalSandboxPeer(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := parseSandboxIP(strings.Trim(value, "[]"))
	if ip == nil {
		return observability.Absent[string]()
	}
	return observability.Present(sandboxIPIdentifier(ip))
}

// sandboxV8Log is one audit-owned generated log occurrence. The family is
// fixed by the producer method; emit never sees caller-selected identities.
type sandboxV8Log struct {
	action    Action
	event     Event
	bucket    observability.Bucket
	eventName string
	phase     string
	outcome   observability.Outcome
	mandatory bool
	facts     observability.MandatoryFacts
	enforced  bool
	build     func(
		*observability.FamilyBuilder,
		observability.FamilyEnvelopeInput,
		observability.Optional[observability.Severity],
		observability.Optional[observability.LogLevel],
	) (observability.Record, error)
}

func (recorder *SandboxRecorder) ready() error {
	if recorder == nil || recorder.logger == nil {
		return fmt.Errorf("audit: sandbox telemetry recorder is unavailable")
	}
	return nil
}

// emit sends one log through the bound runtime, then records the family's
// companion metrics and the audit-event counter.
func (recorder *SandboxRecorder) emit(
	ctx context.Context,
	log sandboxV8Log,
	metrics []RuntimeV8GeneratedMetric,
) error {
	binding, disposition, err := recorder.admit(ctx, log)
	if err != nil {
		return err
	}
	recorder.recordCompanions(ctx, binding, log, disposition, metrics)
	return nil
}

// admit sends one log through the bound runtime and returns the binding it
// used, so the companion metrics land on the same runtime generation.
func (recorder *SandboxRecorder) admit(
	ctx context.Context,
	log sandboxV8Log,
) (runtimeV8Binding, auditV8Disposition, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	binding := recorder.logger.runtimeV8BindingSnapshot()
	if binding.emitter == nil {
		return runtimeV8Binding{}, auditV8Unhandled, fmt.Errorf("audit: sandbox v8 runtime is unavailable")
	}
	classification := observability.ClassificationContext{
		Bucket: log.bucket, EventName: observability.EventName(log.eventName),
		RawSeverity: log.event.Severity, MandatoryFacts: log.facts, Enforced: log.enforced,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, observability.ProducerKey(log.action), classification,
		observability.SourceGateway, log.event.Connector, observability.ProducerKey(log.action),
	)
	if err != nil {
		return runtimeV8Binding{}, auditV8Unhandled, fmt.Errorf("audit: classify %s: %w", log.action, err)
	}
	correlation := controlPlaneV8Correlation(log.event)
	result, err := binding.emitter.EmitRuntimeV8(ctx, metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			if admission == router.AdmissionFloor {
				if !log.mandatory {
					return observability.Record{}, fmt.Errorf("audit: %s has no mandatory floor", log.action)
				}
				return buildRuntimeV8FloorRecord(
					log.event, snapshot, classification, observability.SourceGateway,
					log.phase, log.outcome, correlation,
				)
			}
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("audit: %s has no admitted path", log.action)
			}
			builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
				log.event, snapshot, observability.SourceGateway, log.phase, correlation,
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			record, buildErr := log.build(builder, envelope, severity, logLevel)
			return verifyRuntimeV8Record(record, buildErr, log.event, log.mandatory)
		},
	)
	if err != nil {
		return runtimeV8Binding{}, auditV8Unhandled, fmt.Errorf("audit: emit %s: %w", log.action, err)
	}
	disposition, err := runtimeV8Disposition(result, log.mandatory)
	if err != nil {
		return runtimeV8Binding{}, auditV8Unhandled, fmt.Errorf("audit: %s: %w", log.action, err)
	}
	return binding, disposition, nil
}

// recordCompanions records an admitted log's companion metrics and, when the
// log was persisted, the audit-event counter. They are best-effort: once the
// log is admitted, a metric failure must not report the occurrence as failed
// and invite a duplicating retry.
func (recorder *SandboxRecorder) recordCompanions(
	ctx context.Context,
	binding runtimeV8Binding,
	log sandboxV8Log,
	disposition auditV8Disposition,
	metrics []RuntimeV8GeneratedMetric,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	if disposition == auditV8Persisted {
		if metric, metricErr := newAuditEventRuntimeV8GeneratedMetric(log.event); metricErr == nil {
			metrics = append(metrics, metric)
		}
	}
	if len(metrics) > 0 {
		_ = recorder.logger.recordRuntimeV8GeneratedMetricBatch(ctx, binding, metrics)
	}
}

func (recorder *SandboxRecorder) newEvent(
	ctx context.Context,
	action Action,
	identity SandboxIdentity,
	target, severity string,
	timestamp time.Time,
) Event {
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	event := Event{
		ID: uuid.NewString(), Timestamp: timestamp.UTC(), Action: string(action),
		Target: target, Actor: "defenseclaw", Severity: severity, Connector: identity.Connector,
	}
	if ctx != nil {
		applyEnvelope(&event, EnvelopeFromContext(ctx))
	}
	stampAuditEventEnvelope(&event)
	return event
}

// commitPhaseLocked records name's new phase and returns the active-sandbox
// counts of every connector whose count may have changed. A deleted sandbox
// is forgotten. The caller holds recorder.lifecycle.
func (recorder *SandboxRecorder) commitPhaseLocked(
	name, connector string,
	phase SandboxPhase,
) []sandboxActiveCount {
	previous, known := recorder.phases[name]
	if phase == SandboxPhaseDeleted {
		delete(recorder.phases, name)
	} else {
		recorder.phases[name] = sandboxTrackedPhase{connector: connector, phase: phase}
	}
	affected := []string{connector}
	if known && previous.connector != connector {
		affected = append(affected, previous.connector)
	}
	counts := make([]sandboxActiveCount, 0, len(affected))
	for _, candidate := range affected {
		var active int64
		for _, tracked := range recorder.phases {
			if tracked.connector == candidate && tracked.phase.Active() {
				active++
			}
		}
		counts = append(counts, sandboxActiveCount{connector: candidate, active: active})
	}
	return counts
}

type sandboxActiveCount struct {
	connector string
	active    int64
}

// sandboxV8Fields is the correlation.sandbox projection of one identity.
type sandboxV8Fields struct {
	id, name, runtime, driver, imageDigest observability.Optional[string]
	profile, pack, phase, workdirMode      observability.Optional[string]
	bindingID                              observability.Optional[string]
	policyVersion                          observability.Optional[int64]
}

func sandboxV8FieldsFor(identity SandboxIdentity) sandboxV8Fields {
	fields := sandboxV8Fields{
		id: optionalSandboxEnum(identity.ID), name: optionalSandboxEnum(identity.Name),
		runtime: optionalSandboxEnum(identity.Runtime), driver: optionalSandboxEnum(identity.Driver),
		imageDigest: optionalSandboxEnum(identity.ImageDigest), profile: optionalSandboxEnum(identity.Profile),
		pack: optionalSandboxEnum(identity.Pack), phase: optionalSandboxEnum(string(identity.Phase)),
		workdirMode: optionalSandboxEnum(identity.WorkdirMode), bindingID: optionalSandboxEnum(identity.BindingID),
	}
	if identity.PolicyVersion > 0 {
		fields.policyVersion = observability.Present(int64(identity.PolicyVersion))
	}
	return fields
}

// validate rejects DefenseClaw-owned identity values that do not fit the
// registry. requireName is false only for gateway-wide health.
func (identity SandboxIdentity) validate(requireName bool) error {
	if requireName && identity.Name == "" {
		return fmt.Errorf("audit: sandbox record requires the sandbox name")
	}
	if identity.Name != "" && !sandboxIdentifier(identity.Name, maxSandboxNameBytes) {
		return fmt.Errorf("audit: sandbox name is not a bounded identifier")
	}
	if identity.ID != "" && !sandboxIdentifier(identity.ID, maxSandboxIDBytes) {
		return fmt.Errorf("audit: sandbox id is not a bounded identifier")
	}
	if identity.BindingID != "" && !sandboxIdentifier(identity.BindingID, maxSandboxBindingIDBytes) {
		return fmt.Errorf("audit: sandbox binding id is not a bounded identifier")
	}
	if identity.Connector != "" && !observability.IsStableToken(identity.Connector) {
		return fmt.Errorf("audit: sandbox connector %q is not a stable token", identity.Connector)
	}
	if identity.Pack != "" && !sandboxIdentifier(identity.Pack, 128) {
		return fmt.Errorf("audit: sandbox pack is not a bounded identifier")
	}
	if identity.ImageDigest != "" && !sandboxDigestPattern.MatchString(identity.ImageDigest) {
		return fmt.Errorf("audit: sandbox image digest must be sha256:<64 lowercase hex>")
	}
	if identity.Phase != "" && !identity.Phase.Valid() {
		return fmt.Errorf("audit: sandbox phase %q is not registered", identity.Phase)
	}
	for _, check := range []struct {
		field, value string
		allowed      []string
	}{
		{"runtime", identity.Runtime, []string{SandboxRuntimeOpenShell}},
		{"driver", identity.Driver, []string{SandboxDriverDocker, SandboxDriverPodman, SandboxDriverVM, SandboxDriverK8s}},
		{"profile", identity.Profile, []string{SandboxProfileOpen, SandboxProfileBalanced, SandboxProfileStrict}},
		{"workdir mode", identity.WorkdirMode, []string{SandboxWorkdirMount, SandboxWorkdirCopy}},
	} {
		if check.value != "" && !containsSandboxValue(check.allowed, check.value) {
			return fmt.Errorf("audit: sandbox %s %q is not registered", check.field, check.value)
		}
	}
	return nil
}

func containsSandboxValue(allowed []string, value string) bool {
	for _, candidate := range allowed {
		if candidate == value {
			return true
		}
	}
	return false
}

func (trigger SandboxLifecycleTrigger) valid() bool {
	switch trigger {
	case SandboxTriggerCreate, SandboxTriggerStart, SandboxTriggerStop, SandboxTriggerDelete,
		SandboxTriggerReconcile, SandboxTriggerWatch:
		return true
	default:
		return false
	}
}

func (operation SandboxPolicyOperation) valid() bool {
	switch operation {
	case SandboxPolicyApply, SandboxPolicyRuleAdd, SandboxPolicyRuleRemove,
		SandboxEgressUnblock, SandboxEgressBlock:
		return true
	default:
		return false
	}
}

func (kind SandboxFindingKind) valid() bool {
	switch kind {
	case SandboxFindingOCSF, SandboxFindingHookSilence, SandboxFindingHookTamper, SandboxFindingLargeUpload,
		SandboxFindingNestedRepo, SandboxFindingShadowAI:
		return true
	default:
		return false
	}
}

// defaultRuleID is the stable rule identity of a finding kind, for example
// SANDBOX-SHADOW-AI.
func (kind SandboxFindingKind) defaultRuleID() string {
	return "SANDBOX-" + strings.ToUpper(strings.ReplaceAll(string(kind), "_", "-"))
}

func (operation SandboxWorkspaceOperation) valid() bool {
	switch operation {
	case SandboxWorkspaceSnapshot, SandboxWorkspaceUndo, SandboxWorkspaceMask,
		SandboxWorkspaceReview, SandboxWorkspaceUpload, SandboxWorkspacePull, SandboxWorkspaceQuarantine:
		return true
	default:
		return false
	}
}

// changesState reports whether the operation changes what the host or the
// sandbox holds: undo restores host files, a mask hides secret files from the
// sandbox, a quarantine renames a nested repository's .git entry, and a pull
// applied to the working tree or to a branch writes the host repository. A
// patch pull writes only the patch file the operator asked for.
func (operation SandboxWorkspaceOperation) changesState(pullMode string) bool {
	switch operation {
	case SandboxWorkspaceUndo, SandboxWorkspaceMask, SandboxWorkspaceQuarantine:
		return true
	case SandboxWorkspacePull:
		return pullMode == SandboxPullApply || pullMode == SandboxPullBranch
	default:
		return false
	}
}

func (operation SandboxWorkspaceOperation) defaultResult() SandboxWorkspaceResult {
	switch operation {
	case SandboxWorkspaceUndo, SandboxWorkspaceMask, SandboxWorkspacePull, SandboxWorkspaceQuarantine:
		return SandboxWorkspaceApplied
	default:
		return SandboxWorkspaceCompleted
	}
}

func (result SandboxWorkspaceResult) outcome() (observability.Outcome, bool) {
	switch result {
	case SandboxWorkspaceApplied:
		return observability.OutcomeApplied, true
	case SandboxWorkspaceCompleted:
		return observability.OutcomeCompleted, true
	case SandboxWorkspaceFailed:
		return observability.OutcomeFailed, true
	case SandboxWorkspaceNoChange:
		return observability.OutcomeNoChange, true
	case SandboxWorkspacePartial:
		return observability.OutcomePartial, true
	case SandboxWorkspaceSkipped:
		return observability.OutcomeSkipped, true
	default:
		return "", false
	}
}

func sandboxLifecycleOutcome(phase SandboxPhase) observability.Outcome {
	switch phase {
	case SandboxPhaseReady, SandboxPhaseStopped, SandboxPhaseCompleted, SandboxPhaseDeleted:
		return observability.OutcomeCompleted
	case SandboxPhaseError, SandboxPhaseUnknown:
		return observability.OutcomeFailed
	default:
		return observability.OutcomeAttempted
	}
}

func sandboxLifecycleSeverity(phase SandboxPhase) string {
	switch phase {
	case SandboxPhaseError:
		return "HIGH"
	case SandboxPhaseUnknown:
		return "MEDIUM"
	default:
		return "INFO"
	}
}

func sandboxApprovalOutcome(result string) (observability.Outcome, bool) {
	switch result {
	case SandboxApprovalApproved:
		return observability.OutcomeApproved, true
	case SandboxApprovalDenied:
		return observability.OutcomeDenied, true
	case SandboxApprovalExpired:
		return observability.OutcomeTimedOut, true
	case SandboxApprovalCancelled:
		return observability.OutcomeCancelled, true
	default:
		return "", false
	}
}

// sandboxSeverity returns the canonical override or the family default.
func sandboxSeverity(override, fallback string) (string, error) {
	if strings.TrimSpace(override) == "" {
		return fallback, nil
	}
	normalized := observability.NormalizeSeverity(override)
	if !normalized.Valid || !normalized.Present {
		return "", fmt.Errorf("audit: sandbox severity %q is not canonical", override)
	}
	return string(normalized.Severity), nil
}

func sandboxPolicyRevision(version uint32) observability.Optional[string] {
	if version == 0 {
		return observability.Absent[string]()
	}
	return observability.Present(fmt.Sprintf("v%d", version))
}

// sandboxPolicyTarget is the defenseclaw.admin.target_ref of a policy change.
// The egress decider's host patterns include three forms that cannot start an
// identifier. A leading wildcard (*.example.com) is recorded as
// suffix:example.com. An IPv6 literal or prefix written with a leading "::"
// (::/0, ::1) takes an explicit zero group (0::/0, 0::1), which names the
// same addresses. A name whose first label starts with "_" (_x.example) is
// recorded as host:_x.example. Any other target that is not a bounded
// identifier is rejected: this mandatory record must say what the change
// opened or closed, so the target is never silently dropped.
func sandboxPolicyTarget(value string) (observability.Optional[string], error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return observability.Absent[string](), nil
	}
	if suffix, wildcard := strings.CutPrefix(value, "*."); wildcard && suffix != "" {
		value = "suffix:" + suffix
	} else if strings.HasPrefix(value, "::") && sandboxIPOrPrefix(value) {
		value = "0" + value
	} else if sandboxUnderscoreName.MatchString(value) {
		value = sandboxHostRefPrefix + value
	}
	if !sandboxIdentifier(value, maxSandboxPolicyTargetBytes) {
		return observability.Absent[string](), fmt.Errorf("audit: sandbox policy target is not a bounded reference")
	}
	return observability.Present(value), nil
}

// sandboxIPOrPrefix reports whether value is an IP literal or a CIDR prefix.
func sandboxIPOrPrefix(value string) bool {
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

type sandboxConditionV8 struct {
	kind, status, reason, message observability.Optional[string]
}

// sandboxConditionFields keeps only gateway tokens that fit their registered
// shape; the message is bounded, never parsed.
func sandboxConditionFields(condition *SandboxCondition) sandboxConditionV8 {
	result := sandboxConditionV8{
		kind: observability.Absent[string](), status: observability.Absent[string](),
		reason: observability.Absent[string](), message: observability.Absent[string](),
	}
	if condition == nil {
		return result
	}
	if sandboxIdentifier(condition.Type, 128) {
		result.kind = observability.Present(condition.Type)
	}
	switch condition.Status {
	case "True", "False", "Unknown":
		result.status = observability.Present(condition.Status)
	}
	if sandboxIdentifier(condition.Reason, 128) {
		result.reason = observability.Present(condition.Reason)
	}
	result.message = optionalSandboxText(condition.Message, maxSandboxConditionMessage)
	return result
}

// sandboxDestination is one canonicalized agent-chosen destination. host is
// meaningful only when canonical.
type sandboxDestination struct {
	host      string
	canonical bool
	port      observability.Optional[int64]
}

// ref is the destination's defenseclaw.network.target_ref: the host, with
// sandboxHostRefPrefix when it cannot start an identifier (sandboxInvalidHost
// when the prefixed name no longer fits).
func (d sandboxDestination) ref() string {
	if !strings.HasPrefix(d.host, "_") {
		return d.host
	}
	if ref := sandboxHostRefPrefix + d.host; len(ref) <= maxSandboxNetworkTargetBytes {
		return ref
	}
	return sandboxInvalidHost
}

// address is the destination's server.address: the host when it is
// canonical and can start an identifier, else absent.
func (d sandboxDestination) address() observability.Optional[string] {
	if !d.canonical || strings.HasPrefix(d.host, "_") {
		return observability.Absent[string]()
	}
	return observability.Present(d.host)
}

// canonicalSandboxDestination canonicalizes an agent-chosen host and port.
// The host may be a name, an IP literal, or a host:port authority; an
// explicit port wins over the authority's, and a port outside 1-65535 is
// omitted. Nothing here fails: the sandboxed agent picks these values, so a
// hostile one must never cost the decision its record.
func canonicalSandboxDestination(value string, port int) sandboxDestination {
	host, authorityPort, canonical := canonicalSandboxAuthority(value)
	if port == 0 {
		port = authorityPort
	}
	destination := sandboxDestination{host: host, canonical: canonical, port: observability.Absent[int64]()}
	if port >= 1 && port <= 65535 {
		destination.port = observability.Present(int64(port))
	}
	return destination
}

// canonicalSandboxAuthority canonicalizes a host, first as given and then as
// a host:port authority whose port it returns (0 when there is none).
func canonicalSandboxAuthority(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxSandboxAuthorityBytes {
		return "", 0, false
	}
	if host, ok := canonicalSandboxHost(value); ok {
		return host, 0, true
	}
	name, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	host, ok := canonicalSandboxHost(name)
	if !ok {
		return "", 0, false
	}
	return host, int(port), true
}

// canonicalSandboxHost canonicalizes a host without a port. IP literals lose
// their brackets and IPv6 zone and are spelled so they satisfy the identifier
// normalizer (which requires a leading alphanumeric). Names lose a trailing
// root dot, are lowercased, and internationalized ones take their ASCII
// (punycode) form; a name must then be letters, digits, '.', '-', and '_'
// only, so a port, path, userinfo, or wildcard never reaches telemetry. A
// name may start with '_' (see sandboxHostRefPrefix).
func canonicalSandboxHost(value string) (string, bool) {
	literal := value
	if strings.HasPrefix(literal, "[") && strings.HasSuffix(literal, "]") {
		literal = literal[1 : len(literal)-1]
	}
	if ip := parseSandboxIP(literal); ip != nil {
		return sandboxIPIdentifier(ip), true
	}
	name := strings.TrimSuffix(value, ".")
	if strings.IndexFunc(name, func(r rune) bool { return r >= utf8.RuneSelf }) >= 0 {
		// idna's result for invalid UTF-8 varies with the Unicode tables the
		// Go toolchain selects (older ones encode it into a punycode label),
		// so reject it up front.
		if !utf8.ValidString(name) {
			return "", false
		}
		ascii, err := idna.Lookup.ToASCII(name)
		if err != nil {
			return "", false
		}
		name = ascii
	}
	name = strings.ToLower(name)
	if len(name) > maxSandboxHostBytes || !sandboxHostPattern.MatchString(name) {
		return "", false
	}
	return name, true
}

// parseSandboxIP parses an IP literal, dropping an IPv6 zone (fe80::1%eth0).
func parseSandboxIP(value string) net.IP {
	if zone := strings.IndexByte(value, '%'); zone > 0 && strings.Contains(value[:zone], ":") {
		value = value[:zone]
	}
	return net.ParseIP(value)
}

func sandboxIPIdentifier(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	text := ip.String()
	if !strings.HasPrefix(text, ":") {
		return text
	}
	v6 := ip.To16()
	groups := make([]string, 8)
	for index := range groups {
		groups[index] = fmt.Sprintf("%x", uint16(v6[2*index])<<8|uint16(v6[2*index+1]))
	}
	return strings.Join(groups, ":")
}

// sandboxAgentCorrelation projects the envelope's session and agent IDs onto
// gen_ai.conversation.id and gen_ai.agent.id; session, the harness session
// the sandbox's hooks last named, wins over the envelope's. The agent
// chooses all of them (the session header and the hook payload's session_id
// feed the envelope), so a value that is not a registered identifier is
// omitted rather than allowed to fail the record. The record's correlation
// keeps the envelope's IDs unchanged, as every producer's does, so the
// request's records still join.
func sandboxAgentCorrelation(event Event, session string) (conversationID, agentID observability.Optional[string]) {
	conversationID = optionalNetworkIdentifier(event.SessionID)
	if strings.TrimSpace(session) != "" {
		conversationID = optionalNetworkIdentifier(session)
	}
	return conversationID, optionalNetworkIdentifier(event.AgentID)
}

// optionalSandboxPID keeps a sandbox process ID within its registered range.
func optionalSandboxPID(pid int) observability.Optional[int64] {
	if pid <= 0 || pid > maxSandboxPID {
		return observability.Absent[int64]()
	}
	return observability.Present(int64(pid))
}

// sandboxEgressPath keeps only an origin-form path: userinfo cannot appear in
// one, and the query and fragment are cut before telemetry construction.
func sandboxEgressPath(value string) observability.Optional[string] {
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	if !strings.HasPrefix(value, "/") || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(truncateUTF8(value, maxSandboxPathBytes))
}

// sandboxWorkspacePaths keeps the first workspace paths that fit their
// registered bounds. The sandboxed agent names these files and Linux names
// are arbitrary bytes, so a path is sanitized or skipped, never allowed to
// fail the record: see sandboxWorkspacePath.
//
// The registered total bounds the array's JSON encoding, not the raw path
// bytes. Brackets, quotes, commas, and escapes all count, and a name made of
// quotes or control bytes grows up to sixfold when encoded.
func sandboxWorkspacePaths(paths []string) observability.Optional[[]string] {
	kept := make([]string, 0, min(len(paths), maxSandboxWorkspacePaths))
	total := len("[]")
	for _, candidate := range paths {
		if len(kept) == maxSandboxWorkspacePaths {
			break
		}
		relative, ok := sandboxWorkspacePath(candidate)
		if !ok {
			continue
		}
		size := sandboxJSONStringBytes(relative)
		if len(kept) > 0 {
			size++ // the separating comma
		}
		if total+size > maxSandboxWorkspacePathTotal {
			break
		}
		total += size
		kept = append(kept, relative)
	}
	if len(kept) == 0 {
		return observability.Absent[[]string]()
	}
	return observability.Present(kept)
}

// sandboxJSONStringBytes is the size of value encoded as a JSON string with
// HTML escaping off, as the family builder measures a string array. It never
// undercounts: the builder writes U+2028 and U+2029 literally, which this
// counts as their six-byte escapes.
func sandboxJSONStringBytes(value string) int {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return maxSandboxWorkspacePathTotal + 1 // never fits
	}
	return len(bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}))
}

// sandboxWorkspacePath replaces invalid UTF-8, drops NUL bytes, and cleans
// value. It rejects a path that is empty, absolute, drive- or UNC-qualified,
// or escapes the workspace, since none of those is workspace-relative.
func sandboxWorkspacePath(value string) (string, bool) {
	value = strings.ReplaceAll(strings.ToValidUTF8(value, "\uFFFD"), "\x00", "")
	if value == "" || value[0] == '/' || value[0] == '\\' || sandboxDriveQualified(value) {
		return "", false
	}
	value = path.Clean(value)
	if value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return "", false
	}
	return truncateUTF8(value, maxSandboxWorkspacePathBytes), true
}

// sandboxDriveQualified reports a Windows drive prefix such as C: or C:\.
func sandboxDriveQualified(value string) bool {
	return len(value) >= 2 && value[1] == ':' &&
		(value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z')
}

// optionalSandboxFindingTarget bounds a finding target reference to the
// registered 256 bytes rather than dropping the finding. Identifier
// characters are ASCII and every prefix of an identifier is one, so the cut
// value still fits the registry.
func optionalSandboxFindingTarget(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || !sandboxIdentifierPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(truncateUTF8(value, maxSandboxFindingTargetBytes))
}

func sandboxIdentifier(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && sandboxIdentifierPattern.MatchString(value)
}

// optionalSandboxEnum carries an already-validated token.
func optionalSandboxEnum(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

// optionalSandboxText bounds free text without splitting a code point. The
// central route projection, not this producer, owns redaction.
func optionalSandboxText(value string, maxBytes int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(truncateUTF8(value, maxBytes))
}

func optionalSandboxCount(value *int64) observability.Optional[int64] {
	if value == nil {
		return observability.Absent[int64]()
	}
	return observability.Present(*value)
}

func sandboxMetricEnvelope(event Event, snapshot RuntimeV8BuildContext) (observability.FamilyEnvelopeInput, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) ||
		event.Timestamp.IsZero() || event.BinaryVersion == "" {
		return observability.FamilyEnvelopeInput{}, fmt.Errorf("audit: invalid sandbox v8 metric build context")
	}
	return observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(event.Timestamp.UTC()), Source: observability.SourceGateway,
		Connector: event.Connector, Action: event.Action, Phase: "metrics",
		Correlation: controlPlaneV8Correlation(event),
		Provenance: observability.FamilyProvenanceInput{
			Producer: "audit_logger", BinaryVersion: event.BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}, nil
}

func sandboxMetricBuilder(event Event) (*observability.FamilyBuilder, error) {
	return observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
}

// sandboxMetricEvent carries the identity connector onto a sandbox metric.
// The record connector may come from the context envelope; sandbox metrics
// always use SandboxIdentity.Connector, the key the active gauge is kept by.
func sandboxMetricEvent(event Event, connector string) Event {
	event.Connector = connector
	return event
}

func newSandboxTransitionMetric(event Event, connector string, from, to SandboxPhase) RuntimeV8GeneratedMetric {
	event = sandboxMetricEvent(event, connector)
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawSandboxTransitions),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			envelope, err := sandboxMetricEnvelope(event, snapshot)
			if err != nil {
				return observability.Record{}, err
			}
			builder, err := sandboxMetricBuilder(event)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawSandboxTransitions(observability.MetricDefenseClawSandboxTransitionsInput{
				Envelope: envelope, Value: 1,
				DefenseClawConnectorSource:  optionalSandboxEnum(connector),
				DefenseClawSandboxPhaseFrom: optionalSandboxEnum(string(from)),
				DefenseClawSandboxPhaseTo:   optionalSandboxEnum(string(to)),
			})
		},
	}
}

func newSandboxActiveMetric(event Event, connector string, active int64) RuntimeV8GeneratedMetric {
	event = sandboxMetricEvent(event, connector)
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawSandboxActive),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			envelope, err := sandboxMetricEnvelope(event, snapshot)
			if err != nil {
				return observability.Record{}, err
			}
			builder, err := sandboxMetricBuilder(event)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawSandboxActive(observability.MetricDefenseClawSandboxActiveInput{
				Envelope: envelope, Value: active,
				DefenseClawConnectorSource: optionalSandboxEnum(connector),
			})
		},
	}
}

func newSandboxEgressMetric(event Event, connector, decision, source string) RuntimeV8GeneratedMetric {
	event = sandboxMetricEvent(event, connector)
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawEgressEvents),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			envelope, err := sandboxMetricEnvelope(event, snapshot)
			if err != nil {
				return observability.Record{}, err
			}
			builder, err := sandboxMetricBuilder(event)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawEgressEvents(observability.MetricDefenseClawEgressEventsInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricDecision:  observability.Present(decision),
				DefenseClawMetricSource:    observability.Present(source),
				DefenseClawConnectorSource: optionalSandboxEnum(connector),
			})
		},
	}
}
