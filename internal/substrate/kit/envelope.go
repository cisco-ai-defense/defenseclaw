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
// The gateway answers X-DefenseClaw-Actor-Mode and X-DefenseClaw-Fail-Mode
// with every reply: the registration's run mode and the mode the kit applies
// when the gateway cannot answer (D8). The kit keeps them in its helper.
//
// The answer is the host hook answer for the connector (action, reason,
// claude_code_output, codex_output or hook_output, ...), which the kit
// shapes with hookexec exactly as a host hook does. Codex notify events go
// to /api/v1/substrate/notify/codex in the same envelope (payload: Codex's
// notify JSON, event agent-turn-complete).
//
// A warm-up is GET <gateway_url>/api/v1/substrate/hook/<connector> with
// X-DefenseClaw-Warm: 1; any HTTP answer counts (the connection through
// egress is what is being made), and the gateway should answer 204.

// Paths of the actor listener the kit uses.
const (
	HookPathPrefix   = "/api/v1/substrate/hook/"
	NotifyPathPrefix = "/api/v1/substrate/notify/"
	WarmHeader       = "X-DefenseClaw-Warm"
	ModeHeader       = "X-DefenseClaw-Actor-Mode"
	FailModeHeader   = "X-DefenseClaw-Fail-Mode"
)

// HookEnvelope is the body of an actor hook post.
type HookEnvelope struct {
	// V is EnvelopeVersion.
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
	// claimsCut adds ProofClaimsCut to Proofs (CollectFacts).
	claimsCut bool
	// Paths are the path-valued arguments of the event, resolved.
	Paths []PathFact `json:"paths,omitempty"`
	// Files are small file contents the event refers to: a skill folder's
	// files, or the repository's MCP configuration and the stdio server files
	// it starts (E20).
	Files []AttachedFile `json:"files,omitempty"`
	// Skills fingerprints every skill folder after PostToolUse,
	// SessionStart and Stop (GAP-0039).
	Skills []SkillFingerprint `json:"skills,omitempty"`
	// ProjectHooks are the project settings files that declare hooks the
	// actor's managed settings ignore, reported at SessionStart (GAP-0479).
	ProjectHooks []ProjectHooks `json:"project_hooks,omitempty"`
	// Proofs name the laptop's file-system proofs the kit made in the
	// actor's file system for the event's shell command (ShellCommandOf):
	// ProofPrivateKeyRead and ProofProtectedWrite.
	// The gateway, which has no view of that file system, uses a proof only
	// to add the laptop's finding, never to remove one (substrate-1 GAP-0471).
	Proofs []string `json:"proofs,omitempty"`
	// Truncated is set when a cap dropped paths or file bytes.
	Truncated bool `json:"truncated,omitempty"`
	// readsSkill marks a PreToolUse read of a file in a skill root: the
	// skill folder pass runs in that call.
	readsSkill bool
}

// SkillFingerprint is one skill folder's lstat fingerprint. Attached says
// its files are in Files (role skill_file) in this post.
type SkillFingerprint struct {
	Path     string `json:"path"`
	FP       string `json:"fp"`
	Attached bool   `json:"attached,omitempty"`
	// Receipt is the gateway's scan receipt for FP; the files are then not
	// attached.
	Receipt string `json:"receipt,omitempty"`
	// Over marks a folder past a kit cap (no FP): the gateway's fail mode
	// decides for it (GAP-0039). With FP empty and Path a skill root, it
	// stands for that root's folders past the listing cap.
	Over bool `json:"over,omitempty"`
	// Sums are the folder's file digests (relative name -> sha256 hex), sent
	// when its files did not fit this post: the gateway rebuilds FP from them
	// and trusts, without the files, a folder the attested template build
	// admitted (GAP-0164).
	Sums map[string]string `json:"sums,omitempty"`
	// Big marks a folder whose files are more than one post carries
	// (MaxAttachBytes): it is never attached, so only its Sums can match it.
	Big bool `json:"big,omitempty"`
}

// ProofPrivateKeyRead says the event's shell command reads the content of the
// actor's own SSH private key as the laptop's reader proves it against the
// real file system (hookpaths.ActionPrivateKeyReadWithDialect): through a
// symlink, a symlinked folder, a `..` walk or a cd (substrate-1 GAP-0471).
const ProofPrivateKeyRead = "private_key_read"

// ProofProtectedWrite says the laptop's protected-target decision
// (hookpaths.ActionCommandDecision), run on the event's shell command in the
// actor's file system, found it writes a protected file, such as a link to
// the actor's authorized_keys: what a managed laptop's hook client reports
// as its ActionDecisionKey (substrate-1 GAP-0471).
const ProofProtectedWrite = "protected_write"

// ProofClaimsCut says the kit's claims of the call are not complete: its
// placement of the shell command's path words stopped at a bound, or a path
// fact that a link moves was dropped at the fact cap. A word or argument
// past the cut may name a link no claim places, so the gateway gives the
// call the unknown tier (substrate-1 GAP-0622). A gateway that does not know
// it ignores it.
const ProofClaimsCut = "claims_cut"

// CommandWordField is the Field of a PathFact for a word of the event's
// shell command (hookpaths.CommandPathWords) whose place in the actor's file
// system differs from its spelling, or that is a private place of the home:
// Path is the word as the command spells it, Resolved its place with every
// link followed and Entry its place with its folders followed and its last
// name kept (substrate-1 GAP-0546, GAP-0549).
const CommandWordField = "command_word"

// PathFact is one path argument as the actor's file system resolves it.
type PathFact struct {
	// Field is where the path was found ("tool_input.file_path",
	// "tool_input.patch", CommandWordField).
	Field string `json:"field"`
	// Path is the value as the agent gave it.
	Path string `json:"path"`
	// Abs is Path made absolute against the event's cwd, cleaned.
	Abs string `json:"abs"`
	// Resolved is Path's place with every symlink followed, a `..` after a
	// link walked from the link's target as the kernel walks it ("" when it
	// does not resolve).
	Resolved string `json:"resolved,omitempty"`
	// Entry is, for a CommandWordField fact, the word's place with its
	// folders followed and its last name kept: what rm, mv, ln or ls act on.
	Entry string `json:"entry,omitempty"`
	// PrivateHome is set, for a CommandWordField fact, on a place inside the
	// actor's home and outside its SSH folder that only its owner can reach
	// (hookpaths.PrivateHomePlace): the destination of an own SSH folder
	// copy, which alerts as on the laptop (substrate-1 GAP-0549).
	PrivateHome bool `json:"private_home,omitempty"`
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

// ProjectHooks is one project settings file that declares hooks (GAP-0479).
// Only the file's digest and the hook event names travel, never its content:
// a local settings file can hold environment values.
type ProjectHooks struct {
	// Path is the file, absolute.
	Path string `json:"path"`
	// SHA256 is the digest of the whole file.
	SHA256 string `json:"sha256"`
	// Events are the hook events the file names, sorted (at most
	// maxProjectHookEvents).
	Events []string `json:"events"`
	// Hooks counts the hook commands the file declares.
	Hooks int `json:"hooks"`
}

// AttachedFile is a file the kit read for the gateway.
type AttachedFile struct {
	// Role is skill_file, mcp_config, mcp_server, mcp_module_absent (a
	// -m module the kit looked for in the folder and did not find), or one
	// of the folder facts of a registry fetcher and a bare command
	// (mcp_fetch_checked, mcp_fetch_local, mcp_fetch_config,
	// mcp_fetch_names, mcp_command_path, mcp_command_path_hit; fetchfacts.go, GAP-0573).
	Role     string `json:"role"`
	Path     string `json:"path"`
	Resolved string `json:"resolved,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	// Content is the file's bytes (base64 in JSON), possibly cut at the cap.
	Content   []byte `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}
