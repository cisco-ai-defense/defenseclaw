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

// Ended sign-ins (B5.1). A person ends this sign-in (logout) or every
// sign-in made before now (logout --all); an administrator ends another
// person's (admin revoke). The leader keeps the list; every replica pulls
// it, refuses an ended token on the admin listener, refuses a relay session
// minted before a person-wide end, and closes the open attach streams of
// an ended sign-in. A replica whose list is older than max_stale refuses
// both (revocation_unavailable): it fails closed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

// Reason codes of the sign-in routes (rows in internal/substrate/reasons).
var (
	substrateReasonSigninEnded   = reasons.Must(revocation.ReasonEnded)
	substrateReasonRevocationOff = reasons.Must(revocation.ReasonUnavailable)
	substrateReasonPersonUnknown = reasons.Must("person_unknown")
	substrateReasonNoIssueTime   = reasons.Must("signin_no_issue_time")
)

// substrateRevocationRefusal is the answer for a token of person (key, iat)
// on this replica: status 0 when it may be used, else 401 signin_ended or
// 503 revocation_unavailable. Revocation off (nil snapshot) accepts all.
func (st *substrateState) substrateRevocationRefusal(person, key string, iat time.Time) (int, string) {
	switch err := st.cfg.Revocations.Check(person, key, iat); {
	case err == nil:
		return 0, ""
	case errors.Is(err, revocation.ErrEnded):
		return http.StatusUnauthorized, substrateReasonSigninEnded
	default:
		return http.StatusServiceUnavailable, substrateReasonRevocationOff
	}
}

// substrateRevocationOn reports whether this replica can take a revoke.
func (st *substrateState) substrateRevocationOn() bool {
	return st.cfg.Revocations != nil && st.cfg.RevocationSource != nil
}

// substrateRevokeAndPull writes e at the leader, applies it here at once,
// and returns the entry and how many open streams this replica closed. The
// other replicas close theirs at their next pull.
func (st *substrateState) substrateRevokeAndPull(ctx context.Context, e revocation.Entry) (revocation.Entry, int, error) {
	before := st.cfg.Streams.Closed()
	out, err := st.cfg.RevocationSource.Put(ctx, e)
	if err != nil {
		return revocation.Entry{}, 0, err
	}
	if err := st.cfg.Revocations.Pull(ctx, st.cfg.RevocationSource); err != nil {
		// Written at the leader; this replica applies it at its next pull.
		st.logRefusal("revocation: pull after a revoke failed: %v", err)
	}
	st.cfg.Streams.CloseEnded()
	return out, int(st.cfg.Streams.Closed() - before), nil
}

// substrateRevocationView is an entry as the routes answer it: never a
// token key.
func substrateRevocationView(e revocation.Entry, closed int) map[string]any {
	v := map[string]any{"person": e.Person, "at": e.At, "until": e.Until, "closed": closed}
	switch {
	case e.Token != "":
		v["scope"] = "this"
	case e.Overflow:
		// Ended tokens past the per-person cap; a lift keeps it (RV1-05).
		v["scope"], v["not_before"] = "overflow", e.NotBefore
	default:
		v["scope"], v["not_before"] = "all", e.NotBefore
	}
	if e.By != "" {
		v["by"] = e.By
	}
	if e.Reason != "" {
		v["reason"] = e.Reason
	}
	return v
}

func (a *APIServer) substrateAuditRevocation(st *substrateState, r *http.Request, c substrateCaller, event, severity, summary string, e revocation.Entry) {
	details := map[string]any{"event": event, "person_id": e.Person, "by_id": ownerOf(c.person).ID(), "route": r.Pattern}
	if e.Reason != "" {
		details["reason"] = e.Reason
	}
	if a.logger != nil {
		_ = a.logger.LogAlertCtx(context.WithoutCancel(r.Context()), "substrate", severity, summary, details)
	}
	st.logRefusal("%s", summary)
}

// substrateSigninRevoke is POST /api/v1/substrate/signin/revoke: the
// caller ends its own sign-in ({"scope":"this"}, the default) or every
// sign-in of itself made before now ({"scope":"all"}). With scope this,
// "also" carries the other tokens the launcher holds for this sign-in
// (the ID token and the access token, RV1-03): each one that verifies as
// the caller is ended in the same write.
func (a *APIServer) substrateSigninRevoke(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !st.substrateRevocationOn() {
			// What a gateway without revocation answers: the launcher
			// keeps its old note (the copy works until it expires).
			writeSubstrateJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		var in struct {
			Scope string   `json:"scope"`
			Also  []string `json:"also"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) || len(in.Also) > 4 {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		e := revocation.Entry{Person: c.person.ID(), By: ownerOf(c.person).ID()}
		principal := c.person.Principal
		switch in.Scope {
		case "", "this":
			if c.person.TokenKey == "" {
				writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
				return
			}
			e.Token = c.person.TokenKey
			e.Also = st.substrateAlsoKeys(r.Context(), c.person, in.Also)
		case "all":
			if c.person.IssuedAt.IsZero() {
				// A Kubernetes token with no issue time (RV1-01): an end by
				// time would also refuse every later sign-in of the person.
				writeSubstrateJSONError(w, http.StatusBadRequest, substrateReasonNoIssueTime)
				return
			}
			e.NotBefore = substrateCallerWatermark(c.person.IssuedAt, time.Now())
		default:
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		out, closed, err := st.substrateRevokeAndPull(r.Context(), e)
		if err != nil {
			st.logRefusal("revocation: put failed: %v", err)
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, substrateReasonRevocationOff)
			return
		}
		a.substrateAuditRevocation(st, r, c, "substrate.signin.revoked", "MEDIUM",
			fmt.Sprintf("person ended their own sign-in (scope %v)", substrateRevocationView(out, 0)["scope"]), out)
		v := substrateRevocationView(out, closed)
		if principal != "" {
			v["principal"] = principal
		}
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}

// substrateAlsoKeys is the token keys of the tokens in also that verify
// as the caller's person, other than the caller's own. A token that does
// not verify is not accepted anywhere, so there is nothing of it to end.
func (st *substrateState) substrateAlsoKeys(ctx context.Context, caller identity.Person, also []string) []string {
	var keys []string
	for _, tok := range also {
		if tok = strings.TrimSpace(tok); tok == "" || st.cfg.People == nil {
			continue
		}
		p, err := st.cfg.People.Verify(ctx, tok)
		if err == nil && p.ID() == caller.ID() && p.TokenKey != "" && p.TokenKey != caller.TokenKey {
			keys = append(keys, p.TokenKey)
		}
	}
	return keys
}

// substrateCallerWatermark is the not-before of a person's own logout
// --all: the next second of this gateway's clock, or later when the
// caller's own token says its sign-in server's clock is ahead, so the
// caller's sign-in, and any made before it, is always covered (RV1-06).
func substrateCallerWatermark(iat, now time.Time) time.Time {
	nb := revocation.Watermark(now)
	if own := iat.Truncate(time.Second).Add(time.Second); own.After(nb) {
		return own
	}
	return nb
}

// substrateResolvePerson turns an admin's user argument into issuer#subject:
// given as issuer#subject, or a principal some registration names.
func (st *substrateState) substrateResolvePerson(ctx context.Context, user string) (string, bool, error) {
	user = strings.TrimSpace(user)
	if iss, sub, ok := strings.Cut(user, "#"); ok {
		return user, iss != "" && sub != "" && !strings.ContainsAny(user, " \t\r\n"), nil
	}
	if user == "" || st.cfg.Registrations == nil {
		return "", false, nil
	}
	regs, err := st.cfg.Registrations.List(ctx, registry.Filter{IncludeDeleted: true})
	if err != nil {
		return "", false, err
	}
	found := ""
	for _, reg := range regs {
		if reg.Person.Subject != "" && strings.EqualFold(reg.Person.Principal, user) {
			if found != "" && found != reg.Person.ID() {
				// Two people share a principal (two issuers): the admin
				// names one by issuer#subject.
				return "", false, nil
			}
			found = reg.Person.ID()
		}
	}
	return found, found != "", nil
}

// substrateAdminRevocations is GET|POST|DELETE
// /api/v1/substrate/admin/revocations (administrators only): list the
// person-wide ends, end every sign-in of a person made before now, or lift
// a person's end early (HIGH).
func (a *APIServer) substrateAdminRevocations(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodDelete:
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			writeSubstrateJSONError(w, http.StatusMethodNotAllowed, "method")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		if !c.admin {
			writeSubstrateJSONError(w, http.StatusForbidden, "admin_only")
			return
		}
		if !st.substrateRevocationOn() {
			writeSubstrateJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		if r.Method == http.MethodGet {
			list := []map[string]any{}
			for _, e := range st.cfg.Revocations.Active() {
				list = append(list, substrateRevocationView(e, 0))
			}
			a.substrateAuditAdminRead(st, r, "revocations", len(list), "")
			writeSubstrateJSON(w, http.StatusOK, map[string]any{"revocations": list})
			return
		}
		var in struct {
			User   string `json:"user"`
			Reason string `json:"reason"`
		}
		if r.Method == http.MethodDelete {
			in.User = r.URL.Query().Get("user")
		} else if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if len(in.Reason) > 256 || strings.ContainsAny(in.Reason, "\r\n") {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		person, ok, err := st.substrateResolvePerson(r.Context(), in.User)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registry_unavailable")
			return
		}
		if !ok {
			writeSubstrateJSONError(w, http.StatusNotFound, substrateReasonPersonUnknown)
			return
		}
		e := revocation.Entry{Person: person, By: ownerOf(c.person).ID(), Reason: in.Reason}
		event, severity, verb := "substrate.signin.revoked", "MEDIUM", "ended every sign-in of"
		if r.Method == http.MethodDelete {
			e.Lift = true
			event, severity, verb = "substrate.signin.revoke_lifted", "HIGH", "lifted the end of the sign-ins of"
		} else {
			e.NotBefore = revocation.Watermark(time.Now())
		}
		out, closed, err := st.substrateRevokeAndPull(r.Context(), e)
		if err != nil {
			st.logRefusal("revocation: put failed: %v", err)
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, substrateReasonRevocationOff)
			return
		}
		a.substrateAuditRevocation(st, r, c, event, severity, fmt.Sprintf("administrator %s %s", verb, person), out)
		v := substrateRevocationView(out, closed)
		if e.Lift {
			v = map[string]any{"person": person, "lifted": true}
		}
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}

// SubstrateRevocationCheck is the doctor row substrate.signin_revocation:
// warn when revocation is off, fail when this replica's list is stale.
func SubstrateRevocationCheck(snap *revocation.Snapshot, now time.Time) SubstrateCheck {
	const id = "substrate.signin_revocation"
	if snap == nil {
		return SubstrateCheck{ID: id, Status: "warn",
			Detail: "ending sign-ins is off: a copied sign-in token works until it expires (up to 24 h)",
			Fix:    "set substrate.identity.revocation.enabled: true and restart the gateway"}
	}
	if err := snap.Check("", "", now); errors.Is(err, revocation.ErrUnavailable) {
		detail := "this gateway has not loaded the list of ended sign-ins yet"
		if t := snap.Synced(); !t.IsZero() {
			detail = fmt.Sprintf("this gateway's list of ended sign-ins is %s old (limit %s)", now.Sub(t).Round(time.Second), snap.MaxStale)
		}
		return SubstrateCheck{ID: id, Status: "fail", Detail: detail + ": it refuses sign-ins until it reads the list again",
			Fix: "check that the leader pod is running and reachable from the gateway"}
	}
	return SubstrateCheck{ID: id, Status: "pass",
		Detail: fmt.Sprintf("on: %d person-wide end(s) active, list read %s ago", len(snap.Active()), now.Sub(snap.Synced()).Round(time.Second))}
}
