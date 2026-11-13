// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// The runtime MCP scan of a Substrate actor (PLAN E20, substrate-1
// GAP-0185). On PreToolUse the gateway scans the MCP servers the call adds
// (a Write of an MCP config, "claude mcp add", "mcp add-json") and, for a
// call of an MCP tool, the repository's MCP config and the in-repository
// server files the kit attached (role mcp_config, mcp_server). A server the
// scan blocks, or a config with keys that differ only by case (GAP-0176), is
// refused closed in every tier: the gateway answers 403 with
// kit.MCPRefusedCode and the kit writes the agent's own deny. The scan
// blocks what the host admission rules block and, as the template build
// does, every HIGH finding of an MCP server (fetch-and-exec, a private or
// metadata address). A config the
// scan cannot read as servers (cut by the attach cap, invalid, an Edit
// fragment) follows the fail mode: managed installs and the strict tier
// refuse, the OSS default tiers alert. On SessionStart, when the agent
// starts the repository's servers and no hook can stop it, a blocked server
// raises a HIGH alert; its tool calls are refused from the first one.

// SubstrateMCPScanner scans the MCP servers of one hook event.
type SubstrateMCPScanner interface {
	ScanMCP(ctx context.Context, payload json.RawMessage, files []SubstrateAttachedFile) ([]SubstrateMCPDecision, error)
}

// SubstrateMCPDecision is the scan answer for one MCP server, or for a
// config that could not be read as servers.
type SubstrateMCPDecision struct {
	// Source is the config path, "mcp add" or "mcp add-json".
	Source string
	// Server is the server name; "" for a config that names none the scan
	// could read (Unreadable) or that is ambiguous (Block).
	Server string
	// Attached is set for the repository config the kit attached (as
	// opposed to a server this call adds).
	Attached   bool
	Block      bool
	Unreadable bool
	// Warn is a finding the admission rules warn on: an alert, no refusal.
	Warn   bool
	Reason string
}

// AttestMCPScanner is the shipped SubstrateMCPScanner (E20, GAP-0185): the
// MCP servers a hook event adds or calls, read with attest.HookAssets and
// decided by the runtime scanner. The config rules and the GAP-0176 key
// check run in the gateway process. The mcp-scanner tool scan of a
// server's in-repository source runs only where that scanner is installed;
// the gateway image has none, so such a server follows the fail mode
// (managed and strict refuse, OSS allows with a MEDIUM alert; the lead's
// GAP-0164 ruling, a known limit). A server with no source to scan (a
// package or a remote URL) is decided by the config rules alone.
type AttestMCPScanner struct{ RT *attest.RuntimeScanner }

// ScanMCP implements SubstrateMCPScanner.
func (s AttestMCPScanner) ScanMCP(ctx context.Context, payload json.RawMessage, files []SubstrateAttachedFile) ([]SubstrateMCPDecision, error) {
	attached := make([]attest.AttachedFile, 0, len(files))
	configs := map[string]bool{}
	for _, f := range files {
		attached = append(attached, attest.AttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
		if f.Role == attest.RoleMCPConfig {
			configs[f.Path] = true
		}
	}
	var out []SubstrateMCPDecision
	for _, a := range attest.HookAssets(payload, attached) {
		if a.Kind != config.AdmissionTypeMCP {
			continue
		}
		d := SubstrateMCPDecision{Source: a.Path, Attached: configs[a.Path]}
		if a.Server != nil {
			d.Server = a.Server.Name
		}
		if a.Server == nil && a.Ambiguous == "" {
			d.Unreadable, d.Reason = true, "the config could not be read as MCP servers (cut, invalid or a partial edit)"
			out = append(out, d)
			continue
		}
		r, err := s.RT.Scan(ctx, a)
		switch {
		case err != nil:
			d.Unreadable, d.Reason = true, err.Error()
		case r.Action == "block":
			// A block from the config rules stands even when the tool scan
			// could not run.
			d.Block, d.Reason = true, r.Reason
		case r.Unavailable:
			// The server has in-repository source to scan and no
			// mcp-scanner can run here: the fail mode decides, as for an
			// unscanned skill (lead's GAP-0164 ruling).
			d.Unreadable, d.Reason = true, "the MCP tool scan cannot run in the gateway (no mcp-scanner)"
		case r.Action == "warn":
			d.Warn, d.Reason = true, r.Reason
		}
		out = append(out, d)
	}
	return out, nil
}

// substrateMCPEvents are the events the MCP pass runs on.
func substrateMCPEvent(event string) (pre, start bool) {
	switch event {
	case "PreToolUse", "preToolUse":
		return true, false
	case "SessionStart", "sessionStart":
		return false, true
	}
	return false, false
}

// mcpNameRE is what Claude Code keeps of a server name in its tool names
// (mcp__<server>__<tool>): every other character becomes "_".
var mcpNameRE = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// substrateMCPToolOf reports whether tool is a tool of server.
func substrateMCPToolOf(tool, server string) bool {
	return strings.HasPrefix(tool, "mcp__"+mcpNameRE.ReplaceAllString(server, "_")+"__")
}

// substrateMCPRefusal runs the MCP pass of one hook post and returns the
// refusal message, or "" to let the call go on.
func (st *substrateState) substrateMCPRefusal(ctx context.Context, env substrateEnvelope) string {
	pre, start := substrateMCPEvent(env.Event)
	if st.cfg.MCP == nil || (!pre && !start) {
		return ""
	}
	var files []SubstrateAttachedFile
	if env.Facts != nil {
		files = env.Facts.Files
	}
	var view struct {
		Tool string `json:"tool_name"`
	}
	_ = json.Unmarshal(env.Payload, &view)
	decisions, err := st.cfg.MCP.ScanMCP(ctx, env.Payload, files)
	if err != nil {
		decisions = []SubstrateMCPDecision{{Source: "mcp scan", Unreadable: true, Reason: "the MCP scan could not complete: " + err.Error()}}
	}
	block := st.cfg.BlockUnscannedSkills != nil && st.cfg.BlockUnscannedSkills(env.Connector)
	for _, d := range decisions {
		// A repository config decides only the calls of its servers; a
		// server this call adds decides the call itself.
		relevant := !d.Attached || (pre && strings.HasPrefix(view.Tool, "mcp__") && (d.Server == "" || substrateMCPToolOf(view.Tool, d.Server)))
		name := d.Server
		if name == "" {
			name = d.Source
		}
		switch {
		case d.Block:
			st.alertOnce(ctx, "HIGH", "Substrate MCP server refused by the runtime MCP scan: "+name, d.Source, env.Facts, mcpReason(d.Reason))
			if pre && relevant {
				return "DefenseClaw refused the MCP server " + name + ": " + d.Reason
			}
		case d.Unreadable && block:
			st.alertOnce(ctx, "HIGH", "Substrate MCP config refused: DefenseClaw could not read its servers", d.Source, env.Facts, mcpReason(d.Reason))
			if pre && relevant {
				return "DefenseClaw could not check the MCP servers of " + d.Source + " (" + d.Reason + "); this install refuses MCP servers it could not scan"
			}
		case d.Unreadable:
			st.alertOnce(ctx, "MEDIUM", "Substrate MCP config allowed unscanned: DefenseClaw could not read its servers", d.Source, env.Facts, mcpReason(d.Reason))
		case d.Warn:
			st.alertOnce(ctx, "MEDIUM", "Substrate MCP server allowed with a warning: "+name, d.Source, env.Facts, mcpReason(d.Reason))
		}
	}
	return ""
}

type mcpReason string

func (e mcpReason) Error() string { return string(e) }

// writeSubstrateMCPRefusal is the answer the kit turns into the agent's own
// closed deny (kit.MCPRefusedCode).
func writeSubstrateMCPRefusal(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": http.StatusText(http.StatusForbidden), "reason": kit.MCPRefusedCode, "message": message,
	})
}
