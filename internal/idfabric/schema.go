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

// Package idfabric produces the Astrix-shaped Identity Fabric telemetry that
// DefenseClaw contributes as an endpoint sensor: an aggregated per-agent
// inventory record and near-real-time session_start / pre_tool_use events.
//
// Field selection is allow-list, never best-effort redaction. Raw agent
// configuration, full commands and arguments, environment variables, request
// headers, secrets, URL user-info/path/query/fragment, prompt and tool
// inputs/results, transcript paths, working directories, and filesystem paths
// must never reach these structures. Optional fields are populated only when
// they can be extracted safely and unambiguously, and omitted otherwise.
//
// See docs/design/identity-fabric-discovery-telemetry-proposal.md.
package idfabric

import "time"

// SchemaModel names the Astrix model carried by a record.
type SchemaModel string

const (
	SchemaModelAgent      SchemaModel = "DefenseClawAgent"
	SchemaModelAgentEvent SchemaModel = "DefenseClawAgentEvent"
)

// SchemaVersion is the version of the projection implemented by this package.
// Bump it whenever an emitted field changes meaning.
const SchemaVersion = "1"

// DataSource identifies the producing sensor to Identity Fabric.
const DataSource = "defenseclaw"

// Metadata is Astrix's common message metadata, shared by both models.
//
// TenantID and IntegrationInstanceID are scoping values owned by AI Defense.
// DefenseClaw leaves them empty unless a managed deployment supplies them, so
// that a spooled record never invents a tenant it does not know.
type Metadata struct {
	SchemaModel           SchemaModel `json:"schema_model"`
	SchemaVersion         string      `json:"schema_version"`
	DataSource            string      `json:"data_source"`
	TenantID              string      `json:"tenant_id,omitempty"`
	IntegrationInstanceID string      `json:"integration_instance_id,omitempty"`
	EmittedAt             time.Time   `json:"emitted_at"`
	ProducerVersion       string      `json:"producer_version"`
}

// Platform is the agent's own platform. Open enum: unknown values pass through
// verbatim rather than being coerced.
type Platform string

const (
	PlatformClaudeCode Platform = "claude_code"
	PlatformCodex      Platform = "codex"
	PlatformCursor     Platform = "cursor"
)

// ProcessType describes how the agent runs on the endpoint.
type ProcessType string

const (
	ProcessTypeApp          ProcessType = "app"
	ProcessTypeCLI          ProcessType = "cli"
	ProcessTypeIDEExtension ProcessType = "ide_extension"
)

// RuntimeStatus is the result of a bounded process snapshot and can go stale
// immediately after collection.
type RuntimeStatus string

const (
	RuntimeStatusRunning    RuntimeStatus = "RUNNING"
	RuntimeStatusNotRunning RuntimeStatus = "NOT_RUNNING"
	RuntimeStatusUnknown    RuntimeStatus = "UNKNOWN"
)

// PresenceStatus is computed by AI Defense from successive complete snapshots,
// not by DefenseClaw. It is declared here only so the projection is readable
// against the Astrix model.
type PresenceStatus string

const (
	PresenceStatusPresent PresenceStatus = "PRESENT"
	PresenceStatusRemoved PresenceStatus = "REMOVED"
	PresenceStatusUnknown PresenceStatus = "UNKNOWN"
)

// OperatingSystem is the last known OS of the agent.
type OperatingSystem string

const (
	OSMac     OperatingSystem = "mac"
	OSLinux   OperatingSystem = "linux"
	OSWindows OperatingSystem = "windows"
)

// Agent identifies the agent platform instance.
//
// ID is derived by AI Defense from
// (integration_instance_id, device.id, user.sid|user.uid, agent.platform),
// so DefenseClaw leaves it empty.
type Agent struct {
	ID              string      `json:"id,omitempty"`
	Platform        Platform    `json:"platform"`
	PlatformVersion string      `json:"platform_version,omitempty"`
	ProcessType     ProcessType `json:"process_type"`
}

// User carries OS-user join keys plus, when a trusted source supplies it, an
// authenticated email.
//
// SID and UID must come from the hook process token, never from agent-supplied
// hook JSON, and must never describe the sidecar service account.
//
// AuthenticatedUserEmail is attribution evidence only. It is not identity
// attestation and does not prove who is operating the agent. Never synthesize
// it from username@domain, Git configuration, environment variables, agent
// configuration, or an unverified Windows UPN.
type User struct {
	AuthenticatedUserEmail string `json:"authenticated_user_email,omitempty"`
	SID                    string `json:"sid,omitempty"`
	UID                    string `json:"uid,omitempty"`
}

// Device describes the endpoint.
//
// ID is DefenseClaw's stable device public-key fingerprint. Mapping it to a
// hardware serial or another product's device identifier requires an explicit
// AI Defense / Identity Fabric mapping.
type Device struct {
	// ID is omitted rather than emitted empty when the endpoint has no device
	// key yet, so a consumer cannot mistake "identity not established" for a
	// device whose id is the empty string.
	ID              string          `json:"id,omitempty"`
	Hostname        string          `json:"hostname,omitempty"`
	Username        string          `json:"username,omitempty"`
	OperatingSystem OperatingSystem `json:"operating_system,omitempty"`
}

// ServerType distinguishes a remote MCP endpoint from a locally spawned one.
type ServerType string

const (
	ServerTypeRemote ServerType = "remote"
	ServerTypeLocal  ServerType = "local"
)

// AuthMethod is the declared authentication method of a remote server. Open
// enum. It reflects configuration only and does not mean authentication was
// attempted or succeeded.
type AuthMethod string

const (
	AuthMethodNone         AuthMethod = "none"
	AuthMethodOAuth        AuthMethod = "oauth"
	AuthMethodBearerToken  AuthMethod = "bearer_token"
	AuthMethodAPIKeyHeader AuthMethod = "api_key_header"
	AuthMethodBasic        AuthMethod = "basic"
	AuthMethodMTLS         AuthMethod = "mtls"
	AuthMethodUnknown      AuthMethod = "unknown"
)

// Runner is the recognized launcher form of a local server. Open enum.
type Runner string

const (
	RunnerNPX     Runner = "npx"
	RunnerUVX     Runner = "uvx"
	RunnerNode    Runner = "node"
	RunnerPython  Runner = "python"
	RunnerDocker  Runner = "docker"
	RunnerBinary  Runner = "binary"
	RunnerUnknown Runner = "unknown"
)

// MCPServer is the sanitized projection of one configured MCP server.
//
// This is configured-server evidence. It does not prove that a package is
// installed, that a remote endpoint is reachable, that authentication works,
// or that the server was ever used.
type MCPServer struct {
	// ServerName is the label as configured on the device, verbatim.
	ServerName string     `json:"server_name"`
	ServerType ServerType `json:"server_type"`

	// URL is remote-only and reduced to scheme://host[:port]. User-info, path,
	// query, and fragment are dropped, so it is omitted whenever the
	// configured value cannot be reduced safely.
	URL        string     `json:"url,omitempty"`
	AuthMethod AuthMethod `json:"auth_method,omitempty"`

	// Runner, Package, and PackageVersion are local-only. PackageVersion is
	// set only when the configuration pins it explicitly.
	Runner         Runner `json:"runner,omitempty"`
	Package        string `json:"package,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
}

// AgentRecord is the DefenseClawAgent aggregated inventory model.
//
// The lifecycle timestamps (created_at, updated_at, first_seen, last_seen) and
// PresenceStatus are computed by AI Defense from the record lifecycle and from
// successive endpoint observations, so DefenseClaw omits them. Models is
// likewise aggregated by AI Defense from observed events.
//
// IsPolicyEnforceable is intentionally a pointer and left nil: the current
// direction is that DefenseClaw does not assert this Astrix field. Setting it
// would mean "the connector supports enforcement, its managed hook
// registration is healthy, and the policy mode permits intervention" as an
// observation-time snapshot, never a guarantee about later executions.
type AgentRecord struct {
	Metadata

	RuntimeStatus       RuntimeStatus  `json:"runtime_status"`
	PresenceStatus      PresenceStatus `json:"presence_status,omitempty"`
	IsPolicyEnforceable *bool          `json:"is_policy_enforceable,omitempty"`

	Agent  Agent  `json:"agent"`
	User   User   `json:"user"`
	Device Device `json:"device"`

	Models     []string    `json:"models,omitempty"`
	MCPServers []MCPServer `json:"mcp_servers"`
}

// EventType names the DefenseClawAgentEvent payload variant.
type EventType string

const (
	EventTypeSessionStart EventType = "session_start"
	EventTypePreToolUse   EventType = "pre_tool_use"
)

// TimeSource records where EventTime came from, so a hook receipt time is
// never mistaken for an agent-reported time.
type TimeSource string

const (
	TimeSourceAgent       TimeSource = "agent"
	TimeSourceHookReceipt TimeSource = "hook_receipt"
)

// EventCommon is the shared envelope of both event payloads.
//
// Astrix defines <event_common>; this is DefenseClaw's minimal allow-listed
// stand-in until that definition is published. It deliberately carries no
// workspace path, transcript path, prompt, or tool input.
type EventCommon struct {
	EventType  EventType  `json:"event_type"`
	EventTime  time.Time  `json:"event_time"`
	TimeSource TimeSource `json:"event_time_source"`

	// SessionID correlates session_start with later pre_tool_use events.
	SessionID string `json:"session_id,omitempty"`

	Agent  Agent  `json:"agent"`
	User   User   `json:"user"`
	Device Device `json:"device"`

	// Model is the verbatim model id when the agent reports one.
	Model string `json:"model,omitempty"`
}

// MCPDiscoveryStatus states how complete a discovery pass was, so an
// incomplete scan cannot be read as an authoritative empty list.
type MCPDiscoveryStatus string

const (
	MCPDiscoveryComplete MCPDiscoveryStatus = "complete"
	MCPDiscoveryPartial  MCPDiscoveryStatus = "partial"
	MCPDiscoveryError    MCPDiscoveryStatus = "error"
)

// SessionStart is the session_start payload.
type SessionStart struct {
	EventCommon

	MCPDiscoveryStatus MCPDiscoveryStatus `json:"mcp_discovery_status,omitempty"`
	MCPDiscoveredAt    *time.Time         `json:"mcp_discovered_at,omitempty"`
	MCPServers         []MCPServer        `json:"mcp_servers"`
}

// PreToolUse is the pre_tool_use payload.
//
// ToolName is the agent's verbatim tool identifier. For MCP-provided tools it
// retains the agent's namespaced form, which is what makes this stronger usage
// evidence than configuration discovery. Tool inputs are never included.
type PreToolUse struct {
	EventCommon

	ToolName string `json:"tool_name,omitempty"`

	// MCPServerName is set only when ToolName unambiguously identifies a
	// configured MCP server.
	MCPServerName string `json:"mcp_server_name,omitempty"`
}

// AgentEvent is the DefenseClawAgentEvent model. Exactly one payload is set.
type AgentEvent struct {
	Metadata

	SessionStart *SessionStart `json:"session_start,omitempty"`
	PreToolUse   *PreToolUse   `json:"pre_tool_use,omitempty"`
}

// NewMetadata builds the common metadata for a record of the given model.
func NewMetadata(model SchemaModel, producerVersion string, emittedAt time.Time) Metadata {
	return Metadata{
		SchemaModel:     model,
		SchemaVersion:   SchemaVersion,
		DataSource:      DataSource,
		EmittedAt:       emittedAt.UTC(),
		ProducerVersion: producerVersion,
	}
}

// ProcessTypeForPlatform maps the in-scope connectors to their process type.
// Claude Code and Codex are CLIs; Cursor is an IDE extension. A finer active
// surface is not inferred without runtime evidence.
func ProcessTypeForPlatform(p Platform) ProcessType {
	switch p {
	case PlatformCursor:
		return ProcessTypeIDEExtension
	case PlatformClaudeCode, PlatformCodex:
		return ProcessTypeCLI
	default:
		return ProcessTypeCLI
	}
}
