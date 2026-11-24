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
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
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
// Only the person who owns the actor may attach; an administrator sees the
// inventory, never a session, and is refused with not_your_agent and
// audited as themselves (GAP-0435). The relay still requires a
// person-bound session token: the gateway mints one for the signed-in
// person and this actor incarnation for each request, so a token never
// crosses the laptop's network. The hop from the router to the relay is
// TLS for a template whose signed kit serves it (substrate.relay_tls,
// substrate_relaycert.go); templates built before 1.0.11 are plain.

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
		return workspaceMax + substrateTarOverhead
	}
	return substrateAttachFrameMax
}

// substrateWorkspaceMin is the smallest workspace cap (design 2.6: 1 MiB
// to 64 GiB): a value meant as megabytes (workspace_max_bytes: 512) would
// otherwise refuse every upload (RV1 P4-1).
const substrateWorkspaceMin int64 = 1 << 20

func substrateWorkspaceMax(configured int64) int64 {
	if configured <= 0 {
		return config.DefaultSubstrateWorkspaceMaxBytes
	}
	return max(min(configured, relay.MaxFilesBytes), substrateWorkspaceMin)
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
// token. The relay ends an attachment at its token's exp (GAP-0070), and
// the token ends with the caller's sign-in when that comes first
// (GAP-0588): the launcher then reconnects with a fresh one, as a planned
// renew.
const substrateAttachSessionTTL = 10 * time.Minute

// substrateSessionActor is the actor incarnation a relay session token
// names, with the task digest of its leader registration: the relay starts
// a headless task only when the text matches it (GAP-0162). Every route
// that issues a session token (create, session-cert, attach) uses it.
func substrateSessionActor(reg registry.Registration) identity.SessionActor {
	return identity.SessionActor{Atespace: reg.Atespace, Name: reg.Name, UID: reg.UID, TaskDigest: reg.TaskDigest}
}

// substrateAttachReportEvery is how often an open terminal attachment is
// reported (controller.DefaultAttachMaxAge is three of them).
var substrateAttachReportEvery = time.Minute

// substrateReportAttach reports an attachment of uid now and every
// substrateAttachReportEvery until the returned stop is called.
func substrateReportAttach(sink SubstrateActivitySink, atespace, uid string) (stop func()) {
	sink.ObserveActivity(SubstrateActivityAttach, atespace, uid, time.Now())
	every := substrateAttachReportEvery
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				sink.ObserveActivity(SubstrateActivityAttach, atespace, uid, now)
			}
		}
	}()
	return func() { close(done) }
}

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
		reg, status, reason := a.substrateFindSession(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		// A port forward or MCP bridge (B3.2, B3.3) gets a token for its
		// own dc.scope only (substrate_streams.go).
		stream, sstatus, sreason := a.substrateStreamOpen(st, r, reg, rest)
		if sstatus != http.StatusOK {
			writeSubstrateJSONError(w, sstatus, sreason)
			return
		}
		defer stream.close(r.Context())
		actor := substrateSessionActor(reg)
		if stream != nil {
			actor.Scope = stream.scope
		}
		c, _ := substrateCallerFrom(r.Context())
		tok, exp, err := st.cfg.Sessions.IssueUntil(identity.SignInOf(c.person), actor, substrateAttachSessionTTL, c.person.SessionBound())
		if errors.Is(err, identity.ErrSessionBound) {
			// The sign-in ends this second: the launcher asks for a new
			// one (GAP-0588).
			writeSubstrateRefusal(w, http.StatusUnauthorized, string(identity.ReasonExpired))
			return
		}
		if err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "session_refused")
			return
		}
		if st.cfg.Activity != nil {
			st.cfg.Activity.ObserveActivity(SubstrateActivityRelay, reg.Atespace, reg.UID, time.Now())
			// A terminal attachment (WebSocket, or a long-poll request
			// other than its close) is reported while it is open, so a
			// controller without a CPU feed keeps the actor (GAP-0534).
			if head == relay.RouteWS || stream != nil || (head == relay.RoutePoll && r.Method != http.MethodDelete) {
				defer substrateReportAttach(st.cfg.Activity, reg.Atespace, reg.UID)()
			}
		}
		if rest == relay.RouteFiles && r.Method == http.MethodPut {
			// B2: a push or a sync batch says so; the admin-off switch
			// refuses it here (the first copy of a run carries no op).
			switch r.Header.Get(relay.OpHeader) {
			case relay.OpPush:
				if !substrateSwitch(st.cfg.FilesPush) {
					writeSubstrateJSONError(w, http.StatusForbidden, "push_disabled")
					return
				}
			case relay.OpSync:
				if !substrateSwitch(st.cfg.FilesSync) {
					writeSubstrateJSONError(w, http.StatusForbidden, "sync_disabled")
					return
				}
			}
		}
		dial, dstatus, dreason := a.substrateRelayDial(r.Context(), st, reg)
		if dstatus != http.StatusOK {
			writeSubstrateJSONError(w, dstatus, dreason)
			return
		}
		if stream != nil && stream.kind == relay.RouteMCP {
			// B3.3: the gateway ends an MCP stream itself and judges every
			// tools/call (substrate_mcpbridge.go); it is never a byte proxy.
			a.serveSubstrateMCPBridge(w, r, st, reg, stream, tok, dial)
			return
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
				pr.Out.Header.Del(relay.UploadMaxHeader)
				if rest == relay.RouteFiles && r.Method == http.MethodPut {
					pr.Out.Header.Set(relay.UploadMaxHeader, strconv.FormatInt(substrateWorkspaceMax(st.cfg.WorkspaceMaxBytes), 10))
				}
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
					c, err := dial(ctx)
					return stream.wrap(c), err
				},
				Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 60 * time.Second,
			},
			FlushInterval: -1, // stream poll and task answers as they come
			// A terminal WebSocket learns how long its session token
			// lives, so the launcher renews the attachment just before
			// the relay would end it (GAP-0588). Only the gateway sets the
			// header; one from the relay is dropped.
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Del(relay.SessionSecondsHeader)
				if resp.StatusCode == http.StatusSwitchingProtocols {
					if left := int(time.Until(exp) / time.Second); left > 0 {
						resp.Header.Set(relay.SessionSecondsHeader, strconv.Itoa(left))
					}
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				st.logRefusal("attach to %s/%s failed: %v", space, name, err)
				writeSubstrateJSONError(w, http.StatusBadGateway, "relay_unreachable")
			},
		}
		// The stream ends when its sign-in is ended (B5.1): the proxy closes
		// the upgraded relay connection when the request context ends.
		ctx, release := st.cfg.Streams.Open(r.Context(), revocation.Stream{Person: c.person.ID(), TokenKey: c.person.TokenKey, IssuedAt: c.person.IssuedAt})
		defer release()
		if ctx.Err() != nil && r.Context().Err() == nil {
			// Ended while the request was on its way here (RV1-04).
			writeSubstrateJSONError(w, http.StatusUnauthorized, substrateReasonSigninEnded)
			return
		}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}
}
