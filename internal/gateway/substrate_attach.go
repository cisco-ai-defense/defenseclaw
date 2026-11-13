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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Attach through the admin listener (GAP-0085, GAP-0086; lead ruling
// 11-12 21:50Z). A launcher never dials the atenet router and holds no
// router client certificate: it reaches its actor's relay here, signed in
// as itself (OIDC, or Kubernetes credentials on an OSS cluster), and the
// gateway proxies to the relay through the router with its own in-cluster
// identity (its pod identity certificate, which the router's
// ingressAllowedSPIFFEIDs lists).
//
//	GET  /api/v1/substrate/actors/{atespace}/{name}/attach          WebSocket (dcrelay/1 ws)
//	ANY  /api/v1/substrate/actors/{atespace}/{name}/attach/{rest}   the relay's dcrelay/1/{rest}:
//	     poll[/{id}] (long-poll fallback), task[/{id}], status, exec, files
//
// The person must own the actor; an administrator may attach to any actor
// and is recorded as themselves (E2). The relay still requires a
// person-bound session token: the gateway mints one for the signed-in
// person and this actor incarnation for each request, so a token never
// crosses the laptop's network. The hop from the router to the relay is
// inside the cluster network; it is plain HTTP until the relay serves TLS
// with a certificate the gateway can verify (GAP-0109, documented limit).

// substrateAttachPath is the attach route and everything below it.
var substrateAttachPath = regexp.MustCompile(`^/api/v1/substrate/actors/[^/]+/[^/]+/attach(/.*)?$`)

const (
	// substrateAttachFrameMax bounds an attach request that is not a
	// workspace upload (poll frames, exec and task requests).
	substrateAttachFrameMax int64 = 4 << 20
	// substrateTarOverhead is what a tar body carries beyond its content:
	// headers and padding (as the relay allows).
	substrateTarOverhead int64 = 1 << 20
)

// substrateAttachBodyCap is the body cap of one attach request: the
// workspace cap (E23) for a file upload, a frame cap otherwise.
func substrateAttachBodyCap(r *http.Request, workspaceMax int64) int64 {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/attach/files") {
		if workspaceMax <= 0 {
			workspaceMax = 1 << 30
		}
		return workspaceMax + substrateTarOverhead
	}
	return substrateAttachFrameMax
}

// substrateAttachCSRF is the browser gate of attach traffic: a request
// that changes state carries the DefenseClaw client tag and no foreign
// Origin, as for every admin route, but any Content-Type (a tar stream, a
// WebSocket upgrade). The person check runs after it.
func substrateAttachCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !isLocalhostOrigin(o) {
			writeSubstrateJSONError(w, http.StatusForbidden, "origin_blocked")
			return
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if !safe && r.Header.Get("X-DefenseClaw-Client") == "" {
			writeSubstrateJSONError(w, http.StatusForbidden, "client_tag_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SubstrateRelayDialer opens a connection to an actor's relay port.
type SubstrateRelayDialer interface {
	DialRelay(ctx context.Context, atespace, name string) (net.Conn, error)
}

// substrateAttachSessionTTL is the lifetime of the per-request session
// token (a WebSocket keeps its connection past it; the relay checks the
// token at the upgrade).
const substrateAttachSessionTTL = 10 * time.Minute

func (a *APIServer) substrateAttach(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Relays == nil || st.cfg.Sessions == nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "attach_unavailable")
			return
		}
		rest := strings.Trim(r.PathValue("rest"), "/")
		if rest == "" {
			rest = relay.RouteWS
		}
		head, _, _ := strings.Cut(rest, "/")
		known := false
		// relay.AttachRoutes is the one route table: the launcher builds
		// <attach>/<route>, the relay serves relay.Path(route) (GAP-0158).
		for _, p := range relay.AttachRoutes {
			known = known || head == p
		}
		if !known || strings.Contains(rest, "..") || strings.Contains(rest, "//") {
			writeSubstrateJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		tok, _, err := st.cfg.Sessions.Issue(c.person.ID(), identity.SessionActor{Atespace: reg.Atespace, Name: reg.Name, UID: reg.UID}, substrateAttachSessionTTL)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "session_refused")
			return
		}
		if reg.Person.ID() != ownerOf(c.person).ID() {
			fmt.Fprintf(os.Stderr, "[substrate] administrator attach to another person's actor %s/%s\n", reg.Atespace, reg.Name)
		}
		if st.cfg.Activity != nil {
			st.cfg.Activity.ObserveActivity(SubstrateActivityRelay, reg.Atespace, reg.UID, time.Now())
		}
		space, name := reg.Atespace, reg.Name
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "actor.invalid"
				pr.Out.URL.Path, pr.Out.URL.RawPath = relay.Path(rest), ""
				pr.Out.Host = "actor.invalid"
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Del("Cookie")
				pr.Out.Header.Del("X-Forwarded-For")
				// Only the token the gateway minted reaches the relay.
				var keep []string
				for _, v := range pr.In.Header.Values("Sec-WebSocket-Protocol") {
					for _, p := range strings.Split(v, ",") {
						if p = strings.TrimSpace(p); p != "" && !strings.HasPrefix(p, "dcrelay.token.") {
							keep = append(keep, p)
						}
					}
				}
				pr.Out.Header.Del("Sec-WebSocket-Protocol")
				if len(keep) > 0 {
					pr.Out.Header.Set("Sec-WebSocket-Protocol", strings.Join(keep, ", "))
				}
				pr.Out.Header.Set("Authorization", "Bearer "+tok)
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return st.cfg.Relays.DialRelay(ctx, space, name)
				},
				Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 60 * time.Second,
			},
			FlushInterval: -1, // stream poll and task answers as they come
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				st.logRefusal("attach to %s/%s failed: %v", space, name, err)
				writeSubstrateJSONError(w, http.StatusBadGateway, "relay_unreachable")
			},
		}
		proxy.ServeHTTP(w, r)
	}
}
