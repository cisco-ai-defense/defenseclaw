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

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The callout verdict route (GAP-0015): the egress callout (lane A4) sees
// an actor's MCP tools/call in body mode and asks the gateway for the
// verdict the hook path gives the same call, MCP asset policy included,
// so a call the hook would refuse is refused at egress too.
//
// The shape is the callout's (extproc.VerdictRequest and VerdictResponse),
// agreed with lane F2 in lanes/a2/PROGRESS.md:
//
//	POST /api/v1/substrate/callout/verdict   (admin listener only)
//	Authorization: Bearer <callout service token>
//	X-DefenseClaw-Client: substrate-extproc
//	{"actor":{"atespace":"...","name":"...","uid":"<optional>"},
//	 "mcp":{"host":"mcp.example.com","server":"<admin name>","tool":"...",
//	        "arguments":{...},"url":"<optional>","transport":"<optional>"},
//	 "session_id":"<Mcp-Session-Id, optional>"}
//	-> 200 {"action":"allow|alert|block","severity":"...","reason":"...",
//	        "source":"asset_policy|tool_rules|none","rule_ids":[...],
//	        "actor_uid":"...","profile":"..."}
//
// Any other status is the callout's failure mode. The callout knows the
// actor by atespace and name (upstream gives ext_proc no UID): the gateway
// finds the live UID and its registration; a uid the callout sends must
// be the live one. Verdicts are in action mode, as for every sandboxed
// hook: a rule that blocks blocks. Egress cannot hold a tools/call for an
// approval, so a rule that asks blocks too, with the reason saying so.

type substrateCalloutRequest struct {
	Actor struct {
		Atespace string `json:"atespace"`
		Name     string `json:"name"`
		UID      string `json:"uid,omitempty"`
	} `json:"actor"`
	MCP struct {
		Host      string          `json:"host,omitempty"`
		Server    string          `json:"server"`
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
		URL       string          `json:"url,omitempty"`
		Transport string          `json:"transport,omitempty"`
	} `json:"mcp"`
	SessionID string `json:"session_id,omitempty"`
}

// SubstrateCalloutVerdict is the route's answer.
type SubstrateCalloutVerdict struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Source   string   `json:"source"`
	RuleIDs  []string `json:"rule_ids,omitempty"`
	ActorUID string   `json:"actor_uid,omitempty"`
	Profile  string   `json:"profile,omitempty"`
}

func substrateCalloutBlock(reason, uid string) SubstrateCalloutVerdict {
	return SubstrateCalloutVerdict{Action: "block", Reason: reason, Source: "none", ActorUID: uid}
}

func (a *APIServer) substrateCalloutVerdict(st *substrateState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSubstrateJSONError(w, http.StatusMethodNotAllowed, "method")
			return
		}
		if !substrateCalloutAuthorized(st, r) {
			writeSubstrateJSONError(w, http.StatusUnauthorized, "callout_unauthorized")
			return
		}
		raw, ok := readAllLimited(r.Body, apiRequestBodyMaxBytes)
		if !ok {
			writeSubstrateJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		var req substrateCalloutRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.Actor.Atespace == "" || req.Actor.Name == "" ||
			strings.TrimSpace(req.MCP.Tool) == "" || (strings.TrimSpace(req.MCP.Server) == "" && strings.TrimSpace(req.MCP.Host) == "") {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if st.cfg.Lookup == nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "lookup_unavailable")
			return
		}
		live, err := st.cfg.Lookup.LookupActor(r.Context(), req.Actor.Atespace, req.Actor.Name)
		if errors.Is(err, identity.ErrActorNotFound) {
			writeSubstrateJSON(w, http.StatusOK, substrateCalloutBlock("the actor no longer exists", ""))
			return
		}
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "control_api_unavailable")
			return
		}
		// An actor that is not running makes no call: a request that names
		// one is stale or forged, as on the actor listener (GAP-0061).
		if live.State != identity.ActorRunning && live.State != identity.ActorResuming {
			writeSubstrateJSON(w, http.StatusOK, substrateCalloutBlock("the actor is not running", live.UID))
			return
		}
		if req.Actor.UID != "" && req.Actor.UID != live.UID {
			writeSubstrateJSON(w, http.StatusOK, substrateCalloutBlock("the call names an earlier actor with this name", live.UID))
			return
		}
		reg, found, err := st.cfg.Registrations.Get(r.Context(), req.Actor.Atespace, live.UID)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		if !found || reg.Deleted {
			writeSubstrateJSON(w, http.StatusOK, substrateCalloutBlock("this actor is not registered with DefenseClaw", live.UID))
			return
		}
		v := a.substrateMCPVerdict(r.Context(), reg, req)
		v.ActorUID, v.Profile = reg.UID, reg.Profile
		writeSubstrateJSON(w, http.StatusOK, v)
	})
}

// substrateMCPVerdict runs the hook path's MCP evaluation for the call.
func (a *APIServer) substrateMCPVerdict(ctx context.Context, reg registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
	ctx = a.substrateEvaluationContext(ctx, reg, sandboxauth.RouteHook)
	connectorName := sandboxauth.CanonicalConnector(reg.Connector)
	server := strings.TrimSpace(req.MCP.Server)
	if server == "" {
		server = strings.TrimSpace(req.MCP.Host)
	}
	tool := strings.TrimSpace(req.MCP.Tool)
	hookTool := "mcp__" + mcpToolNamePart(server) + "__" + tool

	out := SubstrateCalloutVerdict{Action: "allow", Source: "none"}
	url := strings.TrimSpace(req.MCP.URL)
	if url == "" && req.MCP.Host != "" {
		url = "https://" + strings.TrimSpace(req.MCP.Host)
	}
	probe := mcpRuntimeProbe{
		ServerName: server, ToolName: hookTool, URL: url,
		Transport: strings.TrimSpace(req.MCP.Transport), Surface: "hook", Matched: true, SessionID: req.SessionID,
	}
	if probe.Transport == "" && probe.URL != "" {
		probe.Transport = "http"
	}
	if decision, matched := a.evaluateRuntimeMCPAssetPolicy(ctx, connectorName, "PreToolUse", probe); matched && substrateAssetDenies(decision) {
		out.Action, out.Source, out.Reason, out.Severity = "block", "asset_policy", decision.Reason, "HIGH"
		return out
	}
	tv := a.inspectToolPolicyCtx(ctx, &ToolInspectRequest{
		Tool: hookTool, Args: req.MCP.Arguments, SessionID: req.SessionID, Connector: connectorName, MCPServerName: server,
	})
	if tv == nil {
		return out
	}
	action := strings.ToLower(tv.Action)
	if action == "" || action == "allow" || action == "alert" {
		if strings.EqualFold(tv.RawAction, "block") {
			action = "block" // observe mode never relaxes a sandboxed call
		}
	}
	reason := tv.Reason
	switch action {
	case "block":
		out.Action = "block"
	case "confirm", "ask":
		// Egress cannot hold the call for an answer; unattended asks deny
		// anyway (D12).
		out.Action = "block"
		reason = strings.TrimSpace("approval needed, which egress cannot hold for: " + reason)
	case "alert":
		out.Action = "alert"
	default:
		return out
	}
	out.Source, out.Reason, out.Severity, out.RuleIDs = "tool_rules", reason, tv.Severity, tv.Findings
	_ = reg
	return out
}

// substrateAssetDenies is an asset decision that holds the call in action
// mode (a block the profile would only observe still blocks a sandbox).
func substrateAssetDenies(d config.AssetPolicyDecision) bool {
	return d.Enabled && (d.Action == "block" || d.RawAction == "block")
}

// mcpToolNamePart keeps a server name to the characters a hook tool name
// carries (the callout's and the hooks' mcp__<server>__<tool> shape).
func mcpToolNamePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// substrateEvaluationContext is the context an actor's evaluation runs in
// outside the actor listener (the callout route): the same sandbox scope,
// verified actor, person and profile the actor listener sets.
func (a *APIServer) substrateEvaluationContext(ctx context.Context, reg registry.Registration, class sandboxauth.Route) context.Context {
	binding := sandboxauth.Binding{
		ID: reg.Key, SandboxID: reg.UID, SandboxName: reg.Atespace + "/" + reg.Name,
		Connector: sandboxauth.CanonicalConnector(reg.Connector), AgentVersion: reg.HarnessVersion,
		HookContractID: reg.HookContract, PolicyProfile: reg.Profile,
		Routes:  []sandboxauth.Route{class},
		Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}, RegistrationID: reg.Key,
	}
	ctx = sandboxauth.WithRequest(ctx, binding, nil)
	ctx = withSubstrateActor(ctx, verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID,
		identity.ActorSubjectPrefix+reg.Atespace+"/"+reg.Name, reg.Key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
	ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
	ctx = withProfilePath(ctx, profilePathHook)
	ctx = contextWithSubstratePerson(ctx, reg)
	return a.withGuardrailProfileDecision(ctx, binding.Connector)
}
