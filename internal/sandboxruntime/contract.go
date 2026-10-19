// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"
	"io"
	"time"
)

// ID names a runtime, independently of its compute or enforcement backend.
type ID string

const (
	Auto      ID = "auto"
	OpenShell ID = "openshell"
	Axis      ID = "axis"
)

// Capability describes independently qualified enforcement or transport.
// Defining a capability does not advertise it for any runtime or harness.
type Capability string

const (
	Headless                    Capability = "headless"
	Interactive                 Capability = "interactive"
	CopyWorkspace               Capability = "copy_workspace"
	LiveMount                   Capability = "live_mount"
	StrictFilesystem            Capability = "strict_filesystem"
	OfflineNetwork              Capability = "offline_network"
	BrokerEgress                Capability = "broker_egress"
	ManagedHooks                Capability = "managed_hooks"
	HostCredentials             Capability = "host_credentials"
	ExecutableCredentialBinding Capability = "executable_credential_binding"
	PersistentSessions          Capability = "persistent_sessions"
	PolicyUpdate                Capability = "policy_update"
	ImageBuild                  Capability = "image_build"
	CPUHardLimit                Capability = "cpu_hard_limit"
	MemoryHardLimit             Capability = "memory_hard_limit"
	ProcessTreeContainment      Capability = "process_tree_containment"
	UntrustedExecution          Capability = "untrusted_execution"
	SkipPermissions             Capability = "skip_permissions"
	MCPImport                   Capability = "mcp_import"
	MCPRemoteBroker             Capability = "mcp_remote_broker"
)

type ArtifactKind string

const (
	OCIImage         ArtifactKind = "oci_image"
	ExecutableBundle ArtifactKind = "executable_bundle"
)

// ArtifactIdentity describes already verified installation evidence. Digest is
// a canonical sha256 digest; this type neither reads nor verifies artifacts.
// Native executables must not be relabeled as an OCI image for admission.
type ArtifactIdentity struct {
	Kind   ArtifactKind `json:"kind"`
	Digest string       `json:"digest"`
}

// RuntimeIdentity pins the concrete adapter and artifact used by a session.
// HostOS and ExecutionOS differ for, for example, OpenShell MicroVMs on macOS.
// Backend is an explicit upstream provider; Driver names its actual substrate.
// Neither Backend nor Runtime may be an automatic selection in saved identity.
type RuntimeIdentity struct {
	Runtime      ID               `json:"runtime"`
	Backend      string           `json:"backend"`
	Driver       string           `json:"driver"`
	HostOS       string           `json:"host_os"`
	ExecutionOS  string           `json:"execution_os"`
	Architecture string           `json:"architecture"`
	Version      string           `json:"version"`
	Artifact     ArtifactIdentity `json:"artifact"`
}

// HarnessIdentity binds qualification to exact agent and immutable hook bytes.
type HarnessIdentity struct {
	Version      string           `json:"version"`
	HookContract string           `json:"hook_contract"`
	Artifact     ArtifactIdentity `json:"artifact"`
}

type HarnessVerification struct {
	Identity  HarnessIdentity `json:"identity"`
	Supported []Capability    `json:"capabilities"`
}

// RuntimeInfo is host-owned discovery evidence, never a guest capability claim.
// Available and Supported must be populated only after adapter qualification;
// structural validation is not runtime, hook, credential or policy certification.
type RuntimeInfo struct {
	Identity    RuntimeIdentity                `json:"identity"`
	Available   bool                           `json:"available"`
	Reason      string                         `json:"reason,omitempty"`
	Posture     string                         `json:"enforcement_posture"`
	Supported   []Capability                   `json:"capabilities"`
	Unavailable map[Capability]string          `json:"unsupported,omitempty"`
	Harnesses   map[string]HarnessVerification `json:"harnesses,omitempty"`
}

// SessionIdentity is host-owned custody metadata, not an agent identity or an
// authorization credential. Lifecycle operations must compare the full record.
type SessionIdentity struct {
	Owner   string          `json:"owner"`
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Runtime RuntimeIdentity `json:"runtime_identity"`
}

// Spec is policy-admitted, host-owned provisioning input. HostWorkspace names a
// sanitized private stage, never the live project or real HOME. Credentials are
// held in a separately scoped broker; only an opaque binding ID belongs here.
type Spec struct {
	Identity          SessionIdentity   `json:"identity"`
	Harness           string            `json:"harness"`
	HarnessIdentity   HarnessIdentity   `json:"harness_identity"`
	HostWorkspace     string            `json:"host_workspace"`
	GuestWorkspace    string            `json:"guest_workspace"`
	Command           []string          `json:"command,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	CPU               string            `json:"cpu,omitempty"`
	Memory            string            `json:"memory,omitempty"`
	Offline           bool              `json:"offline"`
	BindingID         string            `json:"binding_id,omitempty"`
	CredentialProfile string            `json:"credential_profile,omitempty"`
}

type Instance struct {
	Identity  SessionIdentity `json:"identity"`
	Phase     string          `json:"phase"`
	Workdir   string          `json:"workdir,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitzero"`
	ExitCode  *int32          `json:"exit_code,omitempty"`
}

// Command contains literal argv and validated, nonsecret environment entries.
// Implementations must not fall back to a shell or uncontained host execution.
type Command struct {
	Argv           []string          `json:"argv"`
	Env            map[string]string `json:"env,omitempty"`
	Workdir        string            `json:"workdir,omitempty"`
	Timeout        time.Duration     `json:"-"`
	MaxOutputBytes int64             `json:"max_output_bytes,omitempty"`
	Terminal       bool              `json:"terminal,omitempty"`
	Rows           uint16            `json:"rows,omitempty"`
	Columns        uint16            `json:"columns,omitempty"`
}

type ProcessIO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

type ExecResult struct {
	ExitCode        int32 `json:"exit_code"`
	TimedOut        bool  `json:"timed_out,omitempty"`
	OutputTruncated bool  `json:"output_truncated,omitempty"`
}

// Backend is an optional execution boundary beneath Controller. Adapters must
// verify owned identity on every operation, enforce admitted policy, and bound
// cancellation to the contained workload. These declarations start no runtime.
// The existing OpenShell manager need not implement this lower-level contract.
// Create and restart both prepare without untrusted execution or credentials,
// then dispatch the returned handle only through the owner's LaunchGate.
// On preparation error the adapter retains responsibility for partial resources;
// on success the host must register/abort the handle and own its lifecycle.
type Backend interface {
	Info(context.Context) (RuntimeInfo, error)
	Prepare(context.Context, *ExecutionPolicy, Spec) (PreparedProcess, PolicyReceipt, error)
	Inspect(context.Context, SessionIdentity) (Instance, error)
	Stop(context.Context, SessionIdentity) (Instance, error)
	Delete(context.Context, SessionIdentity) error
	Exec(context.Context, SessionIdentity, Command, ProcessIO) (ExecResult, error)
}

// TerminalBackend is optional and requires independently admitted Interactive
// capability. Backend.Exec handles terminal streams; Resize changes geometry.
type TerminalBackend interface {
	Resize(context.Context, SessionIdentity, uint16, uint16) error
}

// WorkspaceTransport is optional, independently of the execution OS. Both ends
// must bound archives and refuse links, special files and escaping paths.
type WorkspaceTransport interface {
	ImportWorkspace(context.Context, SessionIdentity, io.Reader, int64) error
	ExportWorkspace(context.Context, SessionIdentity, io.Writer, int64) error
}
