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

// Package calloutapi is the wire contract between the Agent Substrate
// egress callout (internal/substrate/extproc) and the gateway's callout
// verdict route (internal/gateway): one MCP tools/call the callout found in
// an inspected body, and the verdict the hook path gives the same call (MCP
// asset policy and tool rules in action mode). Both sides use these types,
// so the client and the route cannot drift apart.
//
//	POST /api/v1/substrate/callout/verdict   (admin listener only)
//	Authorization: Bearer <callout service token>
//	X-DefenseClaw-Client: substrate-extproc
package calloutapi

import "encoding/json"

// Path is the route on the gateway's admin listener. It is never served on
// the actor listener and never appears in an EgressPolicy.
const Path = "/api/v1/substrate/callout/verdict"

// Version is the only contract version.
const Version = "1"

// ClientTag is the X-DefenseClaw-Client value the callout sends (the admin
// listener keeps the CSRF gate).
const ClientTag = "substrate-extproc"

// Verdicts.
const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"
	VerdictAsk   = "ask"
)

// Request is one tools/call. Args are the arguments as the actor sent them.
type Request struct {
	V         string          `json:"v"`
	RequestID string          `json:"request_id,omitempty"`
	Actor     Actor           `json:"actor"`
	MCP       MCP             `json:"mcp"`
	Args      json.RawMessage `json:"args,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
}

// Actor names the actor. The callout has no UID (upstream gives ext_proc
// none); the gateway resolves the live UID and the registration.
type Actor struct {
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
}

// MCP is the server and tool. Server is the admin's mcp_hosts name for the
// host, or the host; URL is scheme, host and path, never the query.
type MCP struct {
	Server    string `json:"server"`
	URL       string `json:"url,omitempty"`
	Transport string `json:"transport,omitempty"`
	Method    string `json:"method,omitempty"`
	Tool      string `json:"tool"`
}

// Response is the route's answer. Verdict is allow, deny or ask; an
// unattended actor's ask already comes back as deny (D12).
type Response struct {
	V        string   `json:"v"`
	Verdict  string   `json:"verdict"`
	Reason   string   `json:"reason,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Findings []string `json:"findings,omitempty"`
	Source   string   `json:"source"`
	ActorUID string   `json:"actor_uid,omitempty"`
	Profile  string   `json:"profile,omitempty"`
}
