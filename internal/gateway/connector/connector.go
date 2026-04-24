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

// Package connector defines the adapter layer between agent frameworks and
// DefenseClaw's guardrail proxy. Each connector owns all security surfaces
// for its agent: LLM traffic routing, tool call inspection, agent hook events,
// component scanning, CodeGuard file scanning, and subprocess enforcement.
package connector

import (
	"context"
	"net/http"
)

// ToolInspectionMode describes how a connector monitors tool calls.
type ToolInspectionMode string

const (
	ToolModePreExecution ToolInspectionMode = "pre-execution"
	ToolModeResponseScan ToolInspectionMode = "response-scan"
	ToolModeBoth         ToolInspectionMode = "both"
)

// SubprocessPolicy declares how the connector restricts subprocess execution.
type SubprocessPolicy string

const (
	SubprocessSandbox SubprocessPolicy = "sandbox"
	SubprocessShims   SubprocessPolicy = "shims"
	SubprocessNone    SubprocessPolicy = "none"
)

// ConnectorSignals holds the raw, unresolved signals extracted by a connector
// from the inbound HTTP request. The proxy core resolves these into a concrete
// provider using the existing inferProviderFromURL / splitModel / inferProvider
// chain. From ConnectorSignals onwards, the pipeline is fully agent-agnostic.
type ConnectorSignals struct {
	RawAPIKey       string
	RawModel        string
	RawUpstream     string
	RawBody         []byte
	Stream          bool
	PassthroughMode bool
	ConnectorName   string
	StripHeaders    []string
	ExtraHeaders    map[string]string
}

// SetupOpts is passed to Setup/Teardown during `defenseclaw setup`.
type SetupOpts struct {
	DataDir     string // ~/.defenseclaw/
	ProxyAddr   string // 127.0.0.1:4000 (guardrail proxy — LLM traffic)
	APIAddr     string // 127.0.0.1:18970 (API server — inspection endpoints)
	APIToken    string // gateway bearer token; baked into hook curl -H
	Interactive bool
}

// Connector is the contract every agent framework adapter implements.
type Connector interface {
	Name() string
	Description() string
	ToolInspectionMode() ToolInspectionMode
	SubprocessPolicy() SubprocessPolicy

	Setup(ctx context.Context, opts SetupOpts) error
	Teardown(ctx context.Context, opts SetupOpts) error

	Authenticate(r *http.Request) bool
	Route(r *http.Request, body []byte) (*ConnectorSignals, error)
}

// CredentialSetter — optional, connectors implement to receive
// gateway token and master key at sidecar boot.
type CredentialSetter interface {
	SetCredentials(gatewayToken, masterKey string)
}

// HookEventHandler — optional, connectors that handle agent lifecycle
// events (Claude Code, Codex) implement this. The gateway registers
// the hook endpoint automatically.
type HookEventHandler interface {
	HookEndpointPath() string
	HandleHookEvent(ctx context.Context, payload []byte) ([]byte, error)
}

// ComponentScanner — optional, connectors that support scanning
// agent-specific skills, plugins, MCP servers implement this.
type ComponentScanner interface {
	ComponentTargets(cwd string) map[string][]string
	SupportsComponentScanning() bool
}

// StopScanner — optional, connectors that scan git-changed files
// at session stop implement this.
type StopScanner interface {
	SupportsStopScan() bool
}
