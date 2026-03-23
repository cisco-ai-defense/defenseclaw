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
	Type     string          `json:"type"`
	Protocol int             `json:"protocol"`
	Features *HelloFeatures  `json:"features,omitempty"`
	Auth     *HelloAuth      `json:"auth,omitempty"`
	Policy   *HelloPolicy    `json:"policy,omitempty"`
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
}

// ToolResultPayload is the payload of a tool_result event.
type ToolResultPayload struct {
	Tool     string `json:"tool"`
	Output   string `json:"output,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// ApprovalRequestPayload is the payload of an exec.approval.requested event.
type ApprovalRequestPayload struct {
	ID            string         `json:"id"`
	SystemRunPlan *SystemRunPlan `json:"systemRunPlan,omitempty"`
}

type SystemRunPlan struct {
	Argv       []string `json:"argv,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	RawCommand string   `json:"rawCommand,omitempty"`
}

// ApprovalResolveParams is the params for exec.approval.resolve RPC.
type ApprovalResolveParams struct {
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

// SkillsUpdateParams is the params for skills.update RPC.
type SkillsUpdateParams struct {
	SkillKey string `json:"skillKey"`
	Enabled  bool   `json:"enabled"`
}

// ConfigPatchParams is the params for config.patch RPC.
type ConfigPatchParams struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// RawFrame is used for initial JSON parsing to determine frame type.
type RawFrame struct {
	Type  string `json:"type"`
	Event string `json:"event,omitempty"`
}
