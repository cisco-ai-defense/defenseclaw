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

package sandboxrelay

import (
	"context"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// RouteClass is the kind of a relayed call.
type RouteClass string

const (
	RouteHook    RouteClass = "hook"
	RouteNotify  RouteClass = "notify"
	RouteInspect RouteClass = "inspect"
)

// OTLP signals of the relayed OTLP routes.
const (
	OTLPLogs    = "logs"
	OTLPMetrics = "metrics"
	OTLPTraces  = "traces"
)

// RelayCall is one relayed hook, notify or inspect call: the sandbox's body
// unchanged and the headers it sent. The client copies only ForwardHeaders
// out of Header and sets RegistrationHeader, ClientHeader and
// AgentSurfaceHeader itself.
type RelayCall struct {
	Class RouteClass
	// Target is the connector of a hook or notify call, or the inspect
	// kind (tool, request, response, tool-response).
	Target       string
	Registration string
	Header       http.Header
	Body         []byte
	// EgressRefusals are the sandbox's refusals its agent has not been
	// told of, sent in EgressRefusalsHeader (FitEgressRefusals) on a hook
	// call; nil sends none.
	EgressRefusals []EgressRefusal
}

// RelayResponse is the gateway's answer to a RelayCall: the handler's
// status and body unchanged, only ResponseHeaders, and the verdict trailer
// (nil when the handler recorded none).
type RelayResponse struct {
	Status   int
	Header   http.Header
	Body     []byte
	Decision *HookDecision
}

// OTLPCall is one relayed OTLP export, at most MaxOTLPBodyBytes.
type OTLPCall struct {
	Signal          string
	Registration    string
	ContentType     string
	ContentEncoding string
	Body            []byte
}

// Client is the daemon's connection to the managed gateway's hook socket.
// A non-2xx answer is returned as *Error (a relayed call's non-2xx is a
// RelayResponse instead, so it reaches the sandbox unchanged);
// ErrGatewayUnreachable and ErrSocketUntrusted fail closed.
type Client interface {
	// Settings is GET settings.
	Settings(ctx context.Context) (DaemonSettings, error)
	// Resolve is POST policy/resolve; connector is sent as ConnectorHeader.
	Resolve(ctx context.Context, req ResolveRequest) (ResolveResponse, error)
	// Bind is POST registrations/{id}/bind.
	Bind(ctx context.Context, registration string, req BindRequest) (RegistrationView, error)
	// Deleted is POST registrations/{id}/deleted.
	Deleted(ctx context.Context, registration string) error
	// Current is GET policy/current.
	Current(ctx context.Context, registration string) (CurrentPolicy, error)
	// Report is POST registrations/{id}/state: whether the sandbox runs
	// now, answered like Current.
	Report(ctx context.Context, registration string, running bool) (CurrentPolicy, error)
	// Restart is POST registrations/{id}/restart: the sandbox starts again
	// under the new registration it answers.
	Restart(ctx context.Context, registration string) (RegistrationView, error)
	// Explain is POST policy/explain.
	Explain(ctx context.Context, req ExplainRequest) (sandboxapi.ManagedExplain, error)
	// PolicyTest is POST policy/test for the registration's sandbox or, with
	// none, for a new run of the connector.
	PolicyTest(ctx context.Context, req PolicyTestRequest) (sandboxapi.PolicyTestResult, error)
	// Packs is GET policy/packs; Pack is GET policy/packs/{name}. The scope
	// is registration (one of the caller's sandboxes) or, without one, the
	// connector claim of a new run.
	Packs(ctx context.Context, registration, connector string) ([]PackView, error)
	Pack(ctx context.Context, registration, connector, name string) (PackView, error)
	// Decide is POST decisions; Decisions is GET decisions.
	Decide(ctx context.Context, req DecisionRequest) (DecisionResult, error)
	Decisions(ctx context.Context, registration string) ([]Decision, error)
	// Events is POST events.
	Events(ctx context.Context, batch EventBatch) error
	// Relay forwards a hook, notify or inspect call.
	Relay(ctx context.Context, call RelayCall) (RelayResponse, error)
	// OTLP forwards one OTLP export.
	OTLP(ctx context.Context, call OTLPCall) error
	// Close releases the idle connections.
	Close() error
}
