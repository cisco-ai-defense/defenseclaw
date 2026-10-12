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
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// addSandboxRelayOTLPRoutes adds the relayed OTLP routes (logs, metrics,
// traces), served by the receiver's own handlers.
func (a *APIServer) addSandboxRelayOTLPRoutes(routes map[string]sandboxRelayRoute) {
	for signal, h := range map[string]http.HandlerFunc{
		sandboxrelay.OTLPLogs: a.handleOTLPLogs, sandboxrelay.OTLPMetrics: a.handleOTLPMetrics, sandboxrelay.OTLPTraces: a.handleOTLPTraces,
	} {
		routes[sandboxrelay.PathOTLPPrefix+signal] = sandboxRelayRoute{class: sandboxauth.RouteOTLP, native: "/v1/" + signal, handler: h}
	}
}

// isSandboxRelayOTLPPath reports one of the relayed OTLP signal paths. The
// hook socket's CSRF check takes it as an OTLP endpoint, so a protobuf
// export is not refused for its Content-Type.
func isSandboxRelayOTLPPath(path string) bool {
	switch path {
	case sandboxrelay.PathOTLPPrefix + sandboxrelay.OTLPLogs,
		sandboxrelay.PathOTLPPrefix + sandboxrelay.OTLPMetrics,
		sandboxrelay.PathOTLPPrefix + sandboxrelay.OTLPTraces:
		return true
	}
	return false
}

// serveSandboxRelayOTLP answers one relayed OTLP export. The telemetry is
// attributed to the registration's connector and user, never to a source
// the export names, and one export is at most MaxOTLPBodyBytes.
func (a *APIServer) serveSandboxRelayOTLP(w http.ResponseWriter, r *http.Request, route sandboxRelayRoute, binding sandboxauth.Binding) {
	r.Body = http.MaxBytesReader(w, r.Body, sandboxrelay.MaxOTLPBodyBytes)
	r.Header.Set(otelSourceHeader, binding.Connector)
	route.handler(w, r)
}
