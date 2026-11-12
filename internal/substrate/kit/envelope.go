// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import "encoding/json"

// The actor hook contract with the gateway's actor listener (A2):
//
//	POST <gateway_url>/api/v1/substrate/hook/<connector>
//	x-defenseclaw-actor: placeholder            (egress swaps in the actor JWT)
//	Content-Type: application/json
//	X-DefenseClaw-Client: actor-hook/<kit version>
//	X-DefenseClaw-Kit-Version: <kit version>
//	X-DefenseClaw-Hook-Event: <event>           (when bound on the command line)
//	X-DefenseClaw-Hook-Contract: <contract id>  (when known)
//	X-DefenseClaw-Actor-Mode: interactive|unattended (a claim; the gateway
//	                          takes the mode from the registration)
//	X-DefenseClaw-Hook-Idempotency-Key, Idempotency-Key: <128-bit random>
//	                          (the same on the one retry)
//	body: HookEnvelope
//
// The answer is the host hook answer for the connector (action, reason,
// claude_code_output, codex_output or hook_output, ...), which the kit
// shapes with hookexec exactly as a host hook does. Codex notify events go
// to /api/v1/substrate/notify/codex with the same headers.
//
// A warm-up is GET <gateway_url>/api/v1/substrate/hook/<connector> with
// X-DefenseClaw-Warm: 1; any HTTP answer counts (the connection through
// egress is what is being made), and the gateway should answer 204.

// Paths of the actor listener the kit uses.
const (
	HookPathPrefix   = "/api/v1/substrate/hook/"
	NotifyPathPrefix = "/api/v1/substrate/notify/"
	WarmHeader       = "X-DefenseClaw-Warm"
)

// HookEnvelope is the body of an actor hook post.
type HookEnvelope struct {
	// V is ProtocolV1.
	V string `json:"v"`
	// Connector is the connector name ("claudecode", "codex").
	Connector string `json:"connector"`
	// Event is the hook event, from the command line or the payload.
	Event string `json:"event,omitempty"`
	// HookContract is the contract the image's settings were rendered for.
	HookContract string `json:"hook_contract,omitempty"`
	// Mode is the kit's view of the run (a claim).
	Mode string `json:"mode"`
	// KitVersion is the kit build (E18).
	KitVersion string `json:"kit_version"`
	// Payload is the agent's hook event, byte for byte.
	Payload json.RawMessage `json:"payload"`
	// Facts are what the kit saw in the actor's file system (claims, E19).
	Facts *Facts `json:"facts,omitempty"`
}

// Facts are file-system observations the gateway cannot make itself because
// it has no view of the actor's file system. Every field is a claim made by
// code that runs as the agent's user.
type Facts struct {
	// Paths are the path-valued arguments of the event, resolved.
	Paths []PathFact `json:"paths,omitempty"`
	// Files are small file contents the event refers to: the target of a
	// read, or the repository's MCP configuration and the stdio server files
	// it starts (E20).
	Files []AttachedFile `json:"files,omitempty"`
	// Truncated is set when a cap dropped paths or file bytes.
	Truncated bool `json:"truncated,omitempty"`
}

// PathFact is one path argument as the actor's file system resolves it.
type PathFact struct {
	// Field is where the path was found ("tool_input.file_path",
	// "tool_input.patch", "cwd").
	Field string `json:"field"`
	// Path is the value as the agent gave it.
	Path string `json:"path"`
	// Abs is Path made absolute against the event's cwd, cleaned.
	Abs string `json:"abs"`
	// Resolved is Abs with every symlink followed ("" when it does not
	// resolve).
	Resolved string `json:"resolved,omitempty"`
	// LinkChain lists each symlink hop from Abs, in order.
	LinkChain []string `json:"link_chain,omitempty"`
	// Type is file, dir, symlink (dangling), other or missing.
	Type  string `json:"type"`
	Mode  string `json:"mode,omitempty"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	NLink uint64 `json:"nlink,omitempty"`
	Size  int64  `json:"size,omitempty"`
	// InsideCWD reports whether Resolved (or Abs) is the cwd or below it.
	InsideCWD bool `json:"inside_cwd"`
	// Error is why the path could not be inspected.
	Error string `json:"error,omitempty"`
}

// AttachedFile is a file the kit read for the gateway.
type AttachedFile struct {
	// Role is read_target, mcp_config or mcp_server.
	Role     string `json:"role"`
	Path     string `json:"path"`
	Resolved string `json:"resolved,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	// Content is the file's bytes (base64 in JSON), possibly cut at the cap.
	Content   []byte `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}
