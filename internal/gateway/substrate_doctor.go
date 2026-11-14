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
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// Gateway-side checks for `defenseclaw substrate doctor --cluster`, from where
// the gateway runs (its DNS, its network):
//
//	GET /api/v1/substrate/doctor   (administrators)  {"checks":[{id,status,detail,fix}]}
//	GET /api/v1/substrate/info     (no sign-in)      {sign_in, issuer, client_id, attach, actor_tokens}
//
// substrate.model_upstreams_private (GAP-0040): a cluster that reaches a
// model provider through a VPC interface endpoint resolves the provider
// host to private addresses, and the guardrail proxy's SSRF guard refuses
// them unless guardrail.allow_private_upstreams lists each one (by
// design: IPs only). The check names the addresses to list.

// SubstrateCheck is one doctor row.
type SubstrateCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass, warn, fail
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// SubstrateResolver looks up a host (net.DefaultResolver.LookupHost).
type SubstrateResolver func(ctx context.Context, host string) ([]string, error)

// SubstrateUpstreamCheck checks that every model provider host the
// gateway serves resolves to public addresses, or to private ones the
// SSRF guard lets through.
func SubstrateUpstreamCheck(ctx context.Context, providers map[string]SubstrateLLMProvider, allowed []string, lookup SubstrateResolver) SubstrateCheck {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	sort.Strings(names)
	var missing, private []string
	var unresolved []string
	for _, n := range names {
		u, err := url.Parse(providers[n].Origin)
		if err != nil || u.Hostname() == "" {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := lookup(cctx, u.Hostname())
		cancel()
		if err != nil {
			unresolved = append(unresolved, n)
			continue
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
				continue
			}
			private = append(private, n)
			if !slices.Contains(allowed, ip.String()) && !slices.Contains(missing, ip.String()) {
				missing = append(missing, ip.String())
			}
		}
	}
	c := SubstrateCheck{ID: "substrate.model_upstreams_private", Status: "pass",
		Detail: "every model provider host resolves to public addresses or to allowed private ones"}
	switch {
	case len(missing) > 0:
		c.Status = "fail"
		c.Detail = "model provider hosts resolve to private addresses (a VPC endpoint) that the guardrail proxy refuses: " +
			strings.Join(slices.Compact(private), ", ")
		c.Fix = "list the endpoint addresses in guardrail.allow_private_upstreams (chart value guardrail.allowPrivateUpstreams): " +
			strings.Join(missing, ", ")
	case len(unresolved) > 0:
		c.Status = "warn"
		c.Detail = "the gateway cannot resolve these providers: " + strings.Join(unresolved, ", ")
		c.Fix = "check the cluster DNS and egress to the provider, or remove the provider's credential"
	}
	return c
}

func (a *APIServer) substrateDoctor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		if !c.admin {
			writeSubstrateJSONError(w, http.StatusForbidden, "administrators_only")
			return
		}
		var checks []SubstrateCheck
		if st.cfg.Doctor != nil {
			checks = st.cfg.Doctor(r.Context())
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"checks": checks})
	}
}

// substrateInfo is what a launcher needs before it signs in. It names
// nothing secret.
func (a *APIServer) substrateInfo(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		info := map[string]any{}
		for k, v := range st.cfg.Info {
			info[k] = v
		}
		info["attach"] = st.cfg.Relays != nil
		if h, ok := st.tokens.report(time.Now()); ok {
			info["actor_tokens"] = h
		}
		writeSubstrateJSON(w, http.StatusOK, info)
	}
}

// actorTokenRefusalWindow is how long a cluster-wide actor token refusal
// is reported when no actor token has verified since.
const actorTokenRefusalWindow = 10 * time.Minute

// actorTokenHealth tracks the actor token refusals that hit every actor of
// the cluster at once: the key set cannot be read, the issuer differs from
// the one Substrate signs with, or the control API cannot answer. A
// refusal of one bad token (signature, audience, UID) is not tracked.
type actorTokenHealth struct {
	mu           sync.Mutex
	lastReason   identity.Reason
	lastRefused  time.Time
	lastVerified time.Time
}

// ActorTokenState is the /info actor_tokens member: present only while
// actor tokens are being refused cluster-wide. It names a reason, never a
// token or a caller.
type ActorTokenState struct {
	State  string `json:"state"` // refusing
	Reason string `json:"reason"`
	Since  string `json:"since"`
}

func clusterWideRefusal(r identity.Reason) bool {
	switch r {
	case identity.ReasonKeysetFailed, identity.ReasonIssuer, identity.ReasonUnavailable:
		return true
	}
	return false
}

func (h *actorTokenHealth) refused(r identity.Reason, now time.Time) {
	if !clusterWideRefusal(r) {
		return
	}
	h.mu.Lock()
	h.lastReason, h.lastRefused = r, now
	h.mu.Unlock()
}

func (h *actorTokenHealth) verified(now time.Time) {
	h.mu.Lock()
	h.lastVerified = now
	h.mu.Unlock()
}

// report returns the state while the last cluster-wide refusal is newer
// than the last verified token and inside the window.
func (h *actorTokenHealth) report(now time.Time) (ActorTokenState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastRefused.IsZero() || !h.lastRefused.After(h.lastVerified) || now.Sub(h.lastRefused) > actorTokenRefusalWindow {
		return ActorTokenState{}, false
	}
	return ActorTokenState{State: "refusing", Reason: string(h.lastReason), Since: h.lastRefused.UTC().Format(time.RFC3339)}, true
}
