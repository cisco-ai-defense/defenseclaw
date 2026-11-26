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
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// Gateway-side checks for `defenseclaw substrate doctor --cluster`, from where
// the gateway runs (its DNS, its network):
//
//	GET /api/v1/substrate/doctor   (administrators)  {"checks":[{id,status,detail,fix}]}
//	GET /api/v1/substrate/info     (no sign-in)      {sign_in, issuer, client_id, attach, actor_tokens, egress_callout}
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
		if st.cfg.SignInServer != nil {
			checks = append(checks, st.checkSignIn(r.Context()))
		}
		if st.cfg.EgressCallout != nil {
			if cs, ok := st.cfg.EgressCallout(r.Context()); ok {
				checks = append(checks, SubstrateEgressCalloutCheck(cs))
			}
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"checks": checks})
	}
}

// substrateInfo is what a launcher needs before it signs in. It names
// nothing secret.
func (a *APIServer) substrateInfo(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		info := map[string]any{}
		for k, v := range st.cfg.Info {
			info[k] = v
		}
		info["attach"] = st.cfg.Relays != nil
		if h, ok := st.tokens.report(time.Now()); ok {
			info["actor_tokens"] = h
		}
		if h, ok := st.signIn.report(); ok {
			info["sign_in_server"] = h
		}
		if st.cfg.EgressCallout != nil {
			// At most one leader read per interval (the create path's
			// controller cache), and never a slow answer for a launcher.
			ctx, cancel := context.WithTimeout(r.Context(), egressCalloutInfoWait)
			cs, ok := st.cfg.EgressCallout(ctx)
			cancel()
			if ok {
				info["egress_callout"] = SubstrateEgressCalloutOf(cs)
			}
		}
		writeSubstrateJSON(w, http.StatusOK, info)
	}
}

// egressCalloutInfoWait bounds the slot read /info may wait for.
const egressCalloutInfoWait = 3 * time.Second

// Egress callout states (the /info egress_callout member).
const (
	EgressCalloutDefenseClaw = "defenseclaw"
	EgressCalloutOther       = "other"
	EgressCalloutNone        = "none"
	EgressCalloutUnknown     = "unknown"
)

// SubstrateEgressCallout is the /info egress_callout member (GAP-0497):
// whether the DefenseClaw callout holds Substrate's egress callout slot, and
// when it does not, which DefenseClaw checks are off and what the fail mode
// does about it. It never names the other callout (/info takes no sign-in);
// the administrators' /doctor row does.
type SubstrateEgressCallout struct {
	// State is defenseclaw, other (another callout holds the slot), none
	// (no callout is registered) or unknown (the controller could not read
	// it, or its last report through the leader is missing or stale).
	State string `json:"state"`
	// FailMode is closed (managed agents reach only DefenseClaw while
	// another callout holds the slot; unattended runs always), open
	// (agents keep their egress without the checks) or off
	// (substrate.extproc.enabled: false).
	FailMode string `json:"fail_mode"`
	// ChecksOff are the DefenseClaw checks that do not run (other, none).
	ChecksOff []string `json:"checks_off,omitempty"`
	// Since is when the slot last changed (RFC 3339).
	Since string `json:"since,omitempty"`
}

// SubstrateEgressCalloutOf is the /info member of a controller status.
func SubstrateEgressCalloutOf(cs controller.CalloutStatus) SubstrateEgressCallout {
	out := SubstrateEgressCallout{FailMode: cs.FailMode}
	switch {
	case !cs.Known || cs.Err != "":
		// What could not be read is never the DefenseClaw callout.
		out.State = EgressCalloutUnknown
	case cs.Ours:
		out.State = EgressCalloutDefenseClaw
	case cs.Holder == "":
		out.State = EgressCalloutNone
	default:
		out.State = EgressCalloutOther
	}
	if out.State == EgressCalloutOther || out.State == EgressCalloutNone {
		out.ChecksOff = slices.Clone(controller.CalloutChecks)
	}
	if !cs.Since.IsZero() {
		out.Since = cs.Since.UTC().Format(time.RFC3339)
	}
	return out
}

// SubstrateEgressCalloutCheck is the administrators' doctor row for the
// slot, naming what holds it.
func SubstrateEgressCalloutCheck(cs controller.CalloutStatus) SubstrateCheck {
	const id = "substrate.egress_callout"
	switch m := SubstrateEgressCalloutOf(cs); m.State {
	case EgressCalloutDefenseClaw:
		return SubstrateCheck{ID: id, Status: "pass", Detail: "the DefenseClaw callout holds Substrate's egress callout slot (" + cs.Holder + ")"}
	case EgressCalloutUnknown:
		why := cs.Err
		if why == "" {
			why = "the slot has not been read yet"
		}
		return SubstrateCheck{ID: id, Status: "warn", Detail: "cannot verify the egress callout: " + why,
			Fix: "check the controller's log: the DefenseClaw 1.0.10 chart lets the controller's ServiceAccount get the atenet-egress ConfigMap " +
				"in the Substrate namespace. Check the slot with your own kubeconfig: defenseclaw substrate doctor --cluster --install-file FILE"}
	default:
		what := "no egress callout is registered"
		if cs.Holder != "" {
			what = "egress goes to another callout (" + cs.Holder + ")"
		}
		return SubstrateCheck{ID: id, Status: "fail",
			Detail: what + ": these DefenseClaw checks do not run: " + strings.Join(m.ChecksOff, ", ") + "; " + egressCalloutFailModeText(m.FailMode),
			Fix:    "register the DefenseClaw callout again: defenseclaw substrate setup --install-file FILE, then ate-setup deploy with that file"}
	}
}

// egressCalloutFailModeText says what the fail mode does while the slot is
// not DefenseClaw's.
func egressCalloutFailModeText(mode string) string {
	switch mode {
	case controller.CalloutFailOpen:
		return "fail open: agents keep their egress without them (unattended runs reach only DefenseClaw)"
	case controller.CalloutOff:
		return "substrate.extproc.enabled is false: agents keep their egress without them"
	}
	return "fail closed: managed agents reach only DefenseClaw until the DefenseClaw callout is back"
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

// SubstrateSignInServer is the OIDC issuer people sign in with, as the
// gateway's person verifier reaches it (identity.KeySet).
type SubstrateSignInServer interface {
	DiagnoseIssuer(ctx context.Context) identity.IssuerDiagnosis
}

// signInCheckEvery is how often the gateway checks its sign-in server.
const signInCheckEvery = time.Minute

// signInRetryAfter is the pause before a check that failed is made once
// more: a failure is reported only when it repeats, so one discovery
// timeout or server error does not say nobody can sign in (GAP-0279). A
// real outage is reported by the first check that runs after it starts:
// within signInCheckEvery plus this pause plus two fetch timeouts (about
// 1 min 12 s). The administrators' doctor runs the same check with the same
// retry: it hides a one-off failure too, and shows an outage within about
// 12 s (the pause plus two fetches).
var signInRetryAfter = 2 * time.Second

// signInHealth is the last check of the sign-in server.
type signInHealth struct {
	mu    sync.Mutex
	last  identity.IssuerDiagnosis
	at    time.Time
	since time.Time
}

// record keeps d and reports the cause it replaced when the cause changed
// (a check that never ran counts as passing).
func (h *signInHealth) record(d identity.IssuerDiagnosis, now time.Time) (before string, changed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case d.Cause == "":
		h.since = time.Time{}
	case h.last.Cause != d.Cause || h.since.IsZero():
		h.since = now
	}
	before, changed = h.last.Cause, h.last.Cause != d.Cause
	h.last, h.at = d, now
	return before, changed
}

// failing is the cause of the last check ("" when it passed or never ran).
func (h *signInHealth) failing() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last.Cause
}

// SignInServerState is the /info sign_in_server member: present only while
// the last check failed. It names the cause class, never the detail, so a
// person who cannot sign in learns why without the server's internals.
type SignInServerState struct {
	State  string `json:"state"` // failing
	Reason string `json:"reason"`
	Since  string `json:"since"`
}

func (h *signInHealth) report() (SignInServerState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last.Cause == "" {
		return SignInServerState{}, false
	}
	return SignInServerState{State: "failing", Reason: h.last.Cause, Since: h.since.UTC().Format(time.RFC3339)}, true
}

// watchSignIn checks the sign-in server now and every signInCheckEvery.
func (st *substrateState) watchSignIn(ctx context.Context) {
	t := time.NewTicker(signInCheckEvery)
	defer t.Stop()
	for {
		st.checkSignIn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// checkSignIn checks the sign-in server now, records the result, and
// returns the doctor row (GET /api/v1/substrate/doctor, administrators).
func (st *substrateState) checkSignIn(ctx context.Context) SubstrateCheck {
	d := st.cfg.SignInServer.DiagnoseIssuer(ctx)
	if d.Cause != "" {
		// Once more before it counts (GAP-0279).
		t := time.NewTimer(signInRetryAfter)
		select {
		case <-ctx.Done():
			t.Stop()
			return SignInServerCheck(d)
		case <-t.C:
		}
		d = st.cfg.SignInServer.DiagnoseIssuer(ctx)
	}
	c := SignInServerCheck(d)
	if before, changed := st.signIn.record(d, time.Now()); changed {
		st.signInChanged(ctx, before, d, c)
	}
	return c
}

// signInChanged logs a change of the sign-in server's cause and writes it as
// an audit alert, so an audit export shows when sign-in broke and when it
// came back, as doctor and status do (substrate-1 GAP-0463). A failure that
// goes on for the same cause writes nothing more.
func (st *substrateState) signInChanged(ctx context.Context, before string, d identity.IssuerDiagnosis, c SubstrateCheck) {
	details := map[string]any{"event": "sign_in_server", "check": c.ID, "issuer": d.Issuer}
	severity, summary := "INFO", "the sign-in server answers again: "+c.Detail
	if d.Cause == "" {
		fmt.Fprintf(os.Stderr, "[substrate] %s: %s\n", c.ID, c.Detail)
		details["state"], details["previous_cause"] = "restored", before
	} else {
		fmt.Fprintf(os.Stderr, "[substrate] %s: %s; fix: %s\n", c.ID, c.Detail, c.Fix)
		severity, summary = "HIGH", "sign-in server failing ("+d.Cause+"): "+c.Detail
		details["state"], details["cause"], details["fix"] = "failing", d.Cause, c.Fix
		if s, ok := st.signIn.report(); ok {
			details["since"] = s.Since
		}
	}
	if st.alert != nil {
		st.alert(ctx, severity, summary, details)
	}
}

// SubstrateRelayCertReissueCheck is the doctor row for
// substrate.relay_cert_reissue (GAP-0861): the configured value and the
// active mode.
func SubstrateRelayCertReissueCheck(configured, active string) SubstrateCheck {
	src := "set to " + active
	if configured == config.SubstrateRelayCertReissueAuto {
		src = "auto: " + active + " in this install"
	}
	detail := "relay_cert_reissue is " + active + " (" + src + "): a second relay serving certificate for an actor without proof of the live key is issued with a HIGH audit row on every replica"
	if active == config.SubstrateRelayCertReissueRefuse {
		detail = "relay_cert_reissue is " + active + " (" + src + "): a second relay serving certificate for an actor without proof of the live key is refused on every replica and after restarts; the owner or an administrator clears it with recover"
	}
	return SubstrateCheck{ID: "substrate.relay_cert_reissue", Status: "pass", Detail: detail}
}

// SignInServerCheck is the doctor row for a sign-in server check, with a
// fix for each cause (GAP-0262).
func SignInServerCheck(d identity.IssuerDiagnosis) SubstrateCheck {
	const id = "substrate.oidc_issuer"
	c := SubstrateCheck{ID: id, Status: "fail", Detail: "the sign-in server " + d.Issuer + ": " + d.Detail}
	switch d.Cause {
	case "":
		return SubstrateCheck{ID: id, Status: "pass",
			Detail: fmt.Sprintf("the sign-in server %s answers from the gateway: TLS verifies, discovery names it, and its key set has %d keys", d.Issuer, d.Keys)}
	case identity.IssuerUnreachable:
		c.Detail = "the gateway cannot reach the sign-in server " + d.Issuer + " (" + d.Detail + "): nobody can sign in"
		c.Fix = "check that substrate.identity.oidc.issuer is the address the sign-in server answers on now (its DNS name may have changed), and that the gateway's network and DNS reach it"
	case identity.IssuerTLSName:
		c.Detail = "the sign-in server's certificate does not name " + d.Issuer + " (" + d.Detail + "): nobody can sign in"
		c.Fix = "issue the sign-in server a certificate whose names include the issuer host, or set substrate.identity.oidc.issuer to a name the certificate has"
	case identity.IssuerTLSUntrusted:
		c.Detail = "the sign-in server's certificate does not verify against the gateway's trust bundle (" + d.Detail + "): nobody can sign in"
		c.Fix = "give the gateway the CA that signed it (chart value gateway.oidcCA, --oidc-ca-file), or renew an expired certificate"
	case identity.IssuerHTTP:
		c.Detail = "the sign-in server does not serve its discovery document (" + d.Detail + "): nobody can sign in"
		c.Fix = "check substrate.identity.oidc.issuer: it is the address that ends before /.well-known (for Keycloak, .../realms/REALM)"
	case identity.IssuerUnavailable:
		c.Detail = "the sign-in server " + d.Issuer + " answers with server errors (" + d.Detail + "), twice in a row: sign-ins may fail"
		c.Fix = "the address is right but the sign-in server is failing: check its health and logs (for Keycloak, the realm and its database), then run doctor again"
	case identity.IssuerMismatch:
		c.Detail = d.Detail + ": every sign-in is refused"
		c.Fix = "set substrate.identity.oidc.issuer to exactly the issuer the discovery document names (scheme, host, port and path)"
	case identity.IssuerKeys:
		c.Detail = "the sign-in server's key set does not load (" + d.Detail + "): no sign-in can be verified"
		c.Fix = "check the sign-in server's jwks_uri and that the gateway reaches it"
	}
	return c
}

// SubstrateSecretEchoHits are the echo-host entries (egressspec.EchoHosts,
// then substrate.egress.no_swap_hosts) that a host of sec covers, each once.
func SubstrateSecretEchoHits(sec config.SubstrateSecret, noSwap []string) []string {
	var hits []string
	for _, h := range sec.Inject.Hosts {
		for _, e := range egressspec.EchoHostsCoveredWith(h, noSwap) {
			if !slices.Contains(hits, e) {
				hits = append(hits, e)
			}
		}
	}
	return hits
}

// SubstrateSecretEchoHostCheck is the doctor row substrate.secret_echo_host
// (B1 D1-6): it fails when an admin secret is bound to a host that returns
// the requests it gets, because the controller drops that binding
// (secret_echo_host) and the agent no longer gets the secret there. It
// warns for an entry that keeps the echo with inject.allow_echo.
func SubstrateSecretEchoHostCheck(secrets []config.SubstrateSecret, noSwap []string) SubstrateCheck {
	c := SubstrateCheck{ID: "substrate.secret_echo_host", Status: "pass",
		Detail: "no secret is bound to a host that returns the requests it gets"}
	var dropped, kept []string
	for _, sec := range secrets {
		hits := SubstrateSecretEchoHits(sec, noSwap)
		if len(hits) == 0 {
			continue
		}
		line := sec.Name + " (" + strings.Join(hits, ", ") + ")"
		if sec.Inject.AllowEcho {
			kept = append(kept, line)
		} else {
			dropped = append(dropped, line)
		}
	}
	switch {
	case len(dropped) > 0:
		c.Status = "fail"
		c.Detail = "these secrets are not added on hosts that return the requests they get: " + strings.Join(dropped, "; ")
		c.Fix = "bind each secret to the API host that needs it; to keep the echo on purpose, set inject.allow_echo: true on the entry"
	case len(kept) > 0:
		c.Status = "warn"
		c.Detail = "inject.allow_echo adds these secrets on hosts that return them to the agent: " + strings.Join(kept, "; ")
		c.Fix = "remove inject.allow_echo unless the echo is intended"
	}
	return c
}

// SubstrateSecretBindingFormCheck is the substrate.secret_binding_form row
// (RV3 P4-3): it warns for each binding whose template's form or basic
// user changed since its value was stored, because the stored value then
// makes an invalid header until the person sets it again. A binding stored
// before 1.0.11 records no form and is not judged. It reads the same
// Binding.StoredForm and Template.FormStamp as the person's list and test
// status "template changed" (GAP-0778).
func SubstrateSecretBindingFormCheck(store *secretbind.Store, templates []config.SubstrateSecretTemplate) SubstrateCheck {
	c := SubstrateCheck{ID: "substrate.secret_binding_form", Status: "pass", Detail: "every binding's value is in its template's form"}
	if store == nil {
		c.Detail = "self-service bindings are off"
		return c
	}
	catalog := secretbind.Catalog(templates)
	var stale []string
	for _, b := range store.All() {
		t, ok := secretbind.Find(catalog, b.Template)
		if !ok || b.StoredForm == "" || b.State != secretbind.Active {
			continue
		}
		if now := t.FormStamp(b); now != b.StoredForm {
			stale = append(stale, b.Name+" ("+b.Template+": "+b.StoredForm+" -> "+now+")")
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		c.Status = "warn"
		c.Detail = "these bindings hold a value in a form their template no longer uses, so the header Substrate adds is not valid: " + strings.Join(stale, "; ")
		c.Fix = "ask each owner to run defenseclaw substrate secrets set NAME again, or put the template's form back"
	}
	return c
}

// SubstrateSecretBindingStoreCheck is the substrate.secret_bindings row: the
// self-service bindings ConfigMap reads, and no entry in it was left out as
// invalid (a hand edit). A left-out entry is dropped on the next change, so
// the row names it first (RV3 P3-2).
func SubstrateSecretBindingStoreCheck(store *secretbind.Store) SubstrateCheck {
	c := SubstrateCheck{ID: "substrate.secret_bindings", Status: "pass", Detail: "the self-service bindings read"}
	if store == nil {
		c.Detail = "self-service bindings are off"
		return c
	}
	loaded, dropped, err := store.Health()
	switch {
	case err != nil && !loaded:
		c.Status, c.Detail = "fail", "the self-service bindings do not read: "+err.Error()
		c.Fix = "check that the gateway can get and patch its bindings ConfigMap"
	case err != nil:
		c.Status, c.Detail = "warn", "the last read of the self-service bindings failed, the gateway uses the one before: "+err.Error()
		c.Fix = "check the bindings ConfigMap: a hand edit may have left it unreadable"
	case len(dropped) > 0:
		c.Status, c.Detail = "warn", "these binding entries are not valid and are left out: "+strings.Join(dropped, ", ")
		c.Fix = "fix or remove them in the bindings ConfigMap; the next add or rm rewrites it without them"
	}
	return c
}
