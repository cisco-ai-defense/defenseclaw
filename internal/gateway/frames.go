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

package gateway

import "encoding/json"

// RequestFrame is a client → gateway RPC request.
type RequestFrame struct {
	Type   string      `json:"type"`
	ID     string      `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// ResponseFrame is a gateway → client RPC response.
type ResponseFrame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *FrameError     `json:"error,omitempty"`
}

// FrameError contains error details from a failed RPC response.
type FrameError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
}

// EventFrame is a gateway → client broadcast event.
type EventFrame struct {
	Type    string          `json:"type"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Seq     *int            `json:"seq,omitempty"`
}

// HelloOK is the payload of a successful connect response.
type HelloOK struct {
	Type     string         `json:"type"`
	Protocol int            `json:"protocol"`
	Features *HelloFeatures `json:"features,omitempty"`
	Auth     *HelloAuth     `json:"auth,omitempty"`
	Policy   *HelloPolicy   `json:"policy,omitempty"`
}

type HelloFeatures struct {
	Methods []string `json:"methods,omitempty"`
	Events  []string `json:"events,omitempty"`
}

type HelloAuth struct {
	DeviceToken string   `json:"deviceToken,omitempty"`
	Role        string   `json:"role,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

type HelloPolicy struct {
	TickIntervalMs int `json:"tickIntervalMs,omitempty"`
}

// ChallengePayload is the payload of a connect.challenge event.
type ChallengePayload struct {
	Nonce string `json:"nonce"`
	Ts    int64  `json:"ts"`
}

// ToolCallPayload is the payload of a tool_call event.
type ToolCallPayload struct {
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args,omitempty"`
	Status string          `json:"status,omitempty"`
	// ID is the provider-assigned tool_call identifier (e.g. the
	// OpenAI tool_call_id). Required for cross-event correlation in
	// /v1/agentwatch/summary top_tools aggregation and for joining
	// tool_call + tool_result rows in downstream SIEMs. Optional at
	// the wire level — legacy OpenClaw streams that do not carry a
	// callId leave it blank.
	ID string `json:"id,omitempty"`
	// SessionID is the OpenClaw session/conversation key this tool
	// call belongs to. Populated by the router when synthesizing a
	// tool_call from a session.tool / session.message envelope; raw
	// tool_call frames that arrive without a session context leave
	// it empty.
	SessionID string `json:"session_id,omitempty"`
	// RunID is the OpenClaw run identifier (one per agent invocation).
	// Same population rules as SessionID.
	RunID string `json:"run_id,omitempty"`
	// AgentName is the name of the agent the tool call runs under
	// (from the incoming stream or from cfg.Claw.Mode). Empty when
	// the caller did not supply one.
	AgentName string `json:"agent_name,omitempty"`
}

// ToolResultPayload is the payload of a tool_result event.
type ToolResultPayload struct {
	Tool     string `json:"tool"`
	Output   string `json:"output,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	// ID pairs a tool_result with the tool_call that produced it.
	// See ToolCallPayload.ID for the semantics and wire-level
	// optionality. When blank, SIEMs fall back to joining on Tool
	// name + temporal proximity (lossy but preserves legacy behavior).
	ID        string `json:"id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RunID     string `json:"run_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
}

// ApprovalRequestPayload is the payload of an exec.approval.requested event.
type ApprovalRequestPayload struct {
	ID            string                 `json:"id"`
	SystemRunPlan *SystemRunPlan         `json:"systemRunPlan,omitempty"`
	Request       *ApprovalRequestRecord `json:"request,omitempty"`
}

type SystemRunPlan struct {
	Argv       []string `json:"argv,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	RawCommand string   `json:"rawCommand,omitempty"`
}

type ApprovalRequestRecord struct {
	Command        string         `json:"command,omitempty"`
	CommandPreview string         `json:"commandPreview,omitempty"`
	CommandArgv    []string       `json:"commandArgv,omitempty"`
	Cwd            string         `json:"cwd,omitempty"`
	SystemRunPlan  *SystemRunPlan `json:"systemRunPlan,omitempty"`
}

// CommandContext normalizes approval-request command data across the legacy
// top-level payload shape and the newer nested request shape used by OpenClaw.
func (p ApprovalRequestPayload) CommandContext() (rawCmd string, argv []string, cwd string) {
	if p.SystemRunPlan != nil {
		rawCmd = p.SystemRunPlan.RawCommand
		argv = append(argv, p.SystemRunPlan.Argv...)
		cwd = p.SystemRunPlan.Cwd
	}

	if p.Request == nil {
		return rawCmd, argv, cwd
	}

	if p.Request.SystemRunPlan != nil {
		if rawCmd == "" {
			rawCmd = p.Request.SystemRunPlan.RawCommand
		}
		if len(argv) == 0 {
			argv = append(argv, p.Request.SystemRunPlan.Argv...)
		}
		if cwd == "" {
			cwd = p.Request.SystemRunPlan.Cwd
		}
	}

	if rawCmd == "" {
		rawCmd = p.Request.Command
	}
	if rawCmd == "" {
		rawCmd = p.Request.CommandPreview
	}
	if len(argv) == 0 {
		argv = append(argv, p.Request.CommandArgv...)
	}
	if cwd == "" {
		cwd = p.Request.Cwd
	}

	return rawCmd, argv, cwd
}

// ApprovalResolveParams is the params for exec.approval.resolve RPC.
type ApprovalResolveParams struct {
	ID       string `json:"id"`
	Decision string `json:"decision"`
}

// SkillsUpdateParams is the params for skills.update RPC.
type SkillsUpdateParams struct {
	SkillKey string `json:"skillKey"`
	Enabled  bool   `json:"enabled"`
}

// ConfigPatchParams is the legacy params for config.patch RPC (path/value style).
// Note: OpenClaw's config.patch actually expects { raw, baseHash } — see
// ConfigPatchRawParams. This struct is kept for the PatchConfig helper but
// will fail against real OpenClaw gateways.
type ConfigPatchParams struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// ConfigPatchRawParams is the params for config.patch RPC using the raw
// merge format. OpenClaw expects { raw: "<JSON string>", baseHash: "<sha256>" }.
// Unlike config.set (which replaces the entire config), config.patch performs
// a deep merge into the existing config.
type ConfigPatchRawParams struct {
	Raw      string `json:"raw"`
	BaseHash string `json:"baseHash,omitempty"`
}

// configGetResponse extracts the hash and config from a config.get response.
// OpenClaw nests the actual config under a "config" key in the payload.
type configGetResponse struct {
	Hash   string          `json:"hash"`
	Config *configGetInner `json:"config,omitempty"`
}

type configGetInner struct {
	Plugins *configPlugins `json:"plugins,omitempty"`
}

type configPlugins struct {
	Allow []string `json:"allow,omitempty"`
}

// RawFrame is used for initial JSON parsing to determine frame type.
type RawFrame struct {
	Type  string `json:"type"`
	Event string `json:"event,omitempty"`
}
