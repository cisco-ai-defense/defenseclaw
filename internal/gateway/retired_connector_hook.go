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
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// until 1.1: DefenseClaw 1.0.4 removed the OpenHands and OmniGent connectors
// (#1182), and with them their hook routes. A hook an older release set up
// can still post to /api/v1/openhands/hook or /api/v1/omnigent/hook: an
// OmniGent process that imported the 1.0.3 policy module before the upgrade
// keeps it in memory, and on a managed Unix host it posts over the hook
// socket with no token. Such a hook treats any answer that is not a verdict
// (a 404, a 401) as a failure, and in fail mode open it then lets the call
// run. So the gateway keeps both routes, and they block every call with the
// removal reason, until the old processes stop. They run no policy and
// change nothing, and they never allow, so they answer before every other
// check: with a valid token, a revoked one or none, a sandbox credential,
// on the TCP API, the hook socket (verified peer or not) and the sandbox
// ingress, the answer is the block. Delete with connector/removed.go in 1.1.

// retiredConnectorDrainLimit bounds the request body the retired routes read
// before they answer. Reading it keeps the connection open for the answer:
// a server that answers with most of a large body unread closes the
// connection, and the client may then see a reset instead of the block,
// which an old hook in fail mode open turns into an allow. The old hooks
// send at most 1 MiB by default.
const retiredConnectorDrainLimit = 16 << 20

// retiredConnectorDrainTimeout bounds how long the retired routes wait for
// that body. The routes answer before any credential check, and the TCP API
// and the hook socket have no read timeout, so without it a caller that
// declares a body and never sends it (or trickles it) would hold the
// connection and its goroutine for as long as it likes. An old hook sends
// its body at once, on loopback or a local socket, well inside it. The
// deadline is on the connection, so it also bounds the body net/http itself
// discards before and after the answer; the server sets the next request's
// deadline itself. A var so tests can shorten it.
var retiredConnectorDrainTimeout = 10 * time.Second

// retiredConnectorHookFirst serves a removed connector's hook route before
// next, so none of next's checks can refuse it.
func retiredConnectorHookFirst(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveRetiredConnectorHook(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveRetiredConnectorHook answers a request for a removed connector's hook
// route with a block verdict and reports true; any other request is left
// alone (false).
func serveRetiredConnectorHook(w http.ResponseWriter, r *http.Request) bool {
	name, ok := connector.RemovedConnectorForHookPath(r.URL.Path)
	if !ok {
		return false
	}
	if r.Body != nil && r.Body != http.NoBody {
		// Drain only under the deadline. Every listener chain can set it (the
		// tests cover each); were a writer unable to, skip the drain rather
		// than wait on the body without a bound.
		if http.NewResponseController(w).SetReadDeadline(time.Now().Add(retiredConnectorDrainTimeout)) == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, retiredConnectorDrainLimit))
		}
	}
	reason, _ := connector.RemovedConnectorDenyReason(name)
	// action is what the OmniGent module and the OpenHands hook read;
	// hook_output is the directive the OpenHands hook prints (its Secure
	// Client render reads only that).
	body, _ := json.Marshal(map[string]any{
		"action": "block",
		"reason": reason,
		"hook_output": map[string]string{
			"decision": "deny",
			"reason":   reason,
		},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return true
}
