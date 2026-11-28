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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// The secrets admin API (PLAN 7.2, D14). It returns names only, never a
// value, and never echoes one.
//
//	GET    /api/v1/substrate/secrets[?mine=1]     {"secrets":[{name, scope, hosts, mine, status}]}
//	PUT    /api/v1/substrate/secrets/{name}       {"value": "..."}
//	DELETE /api/v1/substrate/secrets/{name}
//	POST   /api/v1/substrate/secrets/{name}/test  {"name", "status"}
//
// A person sees the secrets their profile binds (substrate.secrets[].
// profiles) and sets or removes only their own value of a per_person
// secret (`secrets set --mine`), stored where its source names, under
// render.PersonKey of their OIDC subject. A shared secret is set by an
// administrator. Only Kubernetes sources (ate-secret://k8s.io/...) are
// written here; a Vault or cloud source is managed in that store.

// SubstrateSecretStore reads and writes one key of a Kubernetes Secret.
type SubstrateSecretStore interface {
	Set(ctx context.Context, namespace, name, key string, value []byte) error
	Remove(ctx context.Context, namespace, name, key string) error
	Exists(ctx context.Context, namespace, name, key string) (bool, error)
}

// ErrSubstrateSecretNotOwned is the SubstrateSecretStore error for a Secret
// that exists but was not created by DefenseClaw (no managed-by label): it
// is not changed (GAP-0183).
var ErrSubstrateSecretNotOwned = errors.New("the Secret is not managed by DefenseClaw")

// Secret statuses.
const (
	substrateSecretSet     = "set"
	substrateSecretNotSet  = "not set"
	substrateSecretManaged = "managed outside DefenseClaw"
	substrateSecretUnknown = "unknown"
	substrateSecretMaxSize = secretbind.MaxStoredValue
)

// substrateK8sSource splits ate-secret://k8s.io/<provider>/<ns>/<secret>/<key>.
func substrateK8sSource(src string) (ns, name, key string, ok bool) {
	u, err := url.Parse(src)
	if err != nil || u.Scheme != "ate-secret" || u.Host != "k8s.io" {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

// substrateSecretFor resolves the source of sec for the caller: the person
// placeholder is their key.
func substrateSecretFor(sec config.SubstrateSecret, subject string) string {
	if sec.Scope == render.ScopePerPerson {
		return strings.ReplaceAll(sec.Source, egressspec.PersonPlaceholder, render.PersonKey(subject))
	}
	return sec.Source
}

func substrateSecretBound(sec config.SubstrateSecret, profile string, admin bool) bool {
	if admin {
		return true
	}
	for _, g := range sec.Profiles {
		if ok, _ := path.Match(g, profile); ok {
			return true
		}
	}
	return false
}

func (a *APIServer) substrateSecretLookup(st *substrateState, r *http.Request) (substrateCaller, string, []config.SubstrateSecret) {
	c, _ := substrateCallerFrom(r.Context())
	profile, _, _ := st.cfg.substrateProfiles()(c.person, "", "", false)
	own := a.substrateOwnBindings(st, c)
	if len(own) == 0 {
		return c, profile, st.cfg.Secrets
	}
	// Admin entries come first, so a name an admin uses later always finds
	// the admin entry; add refuses a name already taken (secret_name_taken).
	return c, profile, append(slices.Clip(st.cfg.Secrets), own...)
}

func (a *APIServer) substrateListSecrets(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		profile, _, _ := st.cfg.substrateProfiles()(c.person, "", "", false)
		mine := r.URL.Query().Get("mine") == "1"
		var regs []registry.Registration
		regsKnown := false
		if st.cfg.Registrations != nil {
			var err error
			regs, err = st.cfg.Registrations.List(r.Context(), registry.Filter{OwnerID: ownerOf(c.person).ID()})
			regsKnown = err == nil
		}
		// ?agent=NAME: only the usable secrets that reach the caller's agent
		// NAME, for the registry files the launcher writes at its start
		// (B1 2.6, S7).
		actor, status, reason := substrateSecretsAgent(r.URL.Query().Get("agent"), regs, regsKnown)
		if status != 0 {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		if actor != nil {
			profile = actor.Profile
		}
		entries := a.substrateSecretEntries(st, c, profile)
		askStates := a.substrateBindingAsks(r.Context(), st, c)
		catalog := secretbind.Catalog(st.secretTemplates())
		now := time.Now()
		uses := st.substrateHostUses(r.Context(), regs)
		noSwap := st.noSwapHosts()
		out := []map[string]any{}
		for _, e := range entries {
			sec := e.sec
			perPerson := sec.Scope == render.ScopePerPerson
			if mine && !perPerson {
				continue
			}
			status, reason := a.substrateSecretState(r.Context(), st, e, c.person.Subject, askStates, now)
			// --mine: values you stored, and every binding of yours
			// whatever its state (waiting, denied, expired).
			if mine && status != substrateSecretSet && e.binding == nil {
				continue
			}
			if actor != nil && (e.uncovered || !substrateSecretUsable(status) || substrateSecretForActor(e, *actor) != "") {
				continue
			}
			v := substrateSecretView(e, status, reason, regs, regsKnown)
			addSubstrateSecretRegistry(v, e, catalog)
			if u, agent, ok := substrateSecretLastUse(e, status, regs, uses, noSwap, now); ok {
				addSubstrateSecretLastUse(v, u, agent)
			}
			out = append(out, v)
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"secrets": out})
	}
}

// substrateSecretsAgent finds the caller's live agent named name among
// regs (nil for no name). status is non-zero when it cannot be answered.
func substrateSecretsAgent(name string, regs []registry.Registration, regsKnown bool) (*registry.Registration, int, string) {
	if name == "" {
		return nil, 0, ""
	}
	if !regsKnown {
		return nil, http.StatusServiceUnavailable, "registrations_unavailable"
	}
	for i := range regs {
		if regs[i].Name == name && !regs[i].Deleted {
			return &regs[i], 0, ""
		}
	}
	return nil, http.StatusNotFound, "secret_agent_not_found"
}

// addSubstrateSecretRegistry says which registry file of the agent's home
// a secret feeds at start (B1 2.6): its template's registry (npm, pypi)
// for a person's binding; npm for an administrator's entry injected in the
// Authorization header, the header npm sends a registry token in (the rule
// the template build used before 1.0.11, GAP-0529). The placeholder is the
// entry's own one, never a value.
func addSubstrateSecretRegistry(v map[string]any, e substrateSecretEntry, catalog []secretbind.Template) {
	kind := ""
	if e.binding != nil {
		if t, ok := secretbind.Find(catalog, e.binding.Template); ok && (t.Registry == "npm" || t.Registry == "pypi") {
			kind = t.Registry
		}
	} else if strings.EqualFold(strings.TrimSpace(e.sec.Inject.Header), "Authorization") {
		kind = "npm"
	}
	if kind == "" {
		return
	}
	v["registry"] = kind
	if p := e.sec.Inject.Placeholder; p != "" {
		v["placeholder"] = p
	}
}

// substrateSecretView is the list and test answer for one secret: never a
// value. kind is template (the caller's own binding) or admin. The last
// use is added by the caller (addSubstrateSecretLastUse).
func substrateSecretView(e substrateSecretEntry, status, reason string, regs []registry.Registration, regsKnown bool) map[string]any {
	sec := e.sec
	scope := sec.Scope
	if scope == "" {
		scope = render.ScopeShared
	}
	v := map[string]any{"name": sec.Name, "scope": scope, "hosts": sec.Inject.Hosts, "mine": sec.Scope == render.ScopePerPerson,
		"status": status, "kind": "admin"}
	if reason != "" {
		v["reason"] = reason
	}
	if b := e.binding; b != nil {
		v["kind"], v["template"] = "template", b.Template
		if !b.Expires.IsZero() {
			v["expires"] = b.Expires.UTC()
		}
		if b.State == secretbind.Waiting && b.AskID != "" {
			v["ask_id"] = b.AskID
		}
	}
	if regsKnown {
		v["agents"] = substrateSecretAgents(e, status, regs)
	}
	return v
}

// substrateWritableSecret finds the named secret the caller may write and
// where its value lives.
func (a *APIServer) substrateWritableSecret(st *substrateState, r *http.Request) (ns, name, key string, status int, reason string) {
	c, profile, secrets := a.substrateSecretLookup(st, r)
	want := r.PathValue("name")
	for _, sec := range secrets {
		if sec.Name != want || !substrateSecretBound(sec, profile, c.admin) {
			continue
		}
		if sec.Scope != render.ScopePerPerson && !c.admin {
			return "", "", "", http.StatusForbidden, "shared_secret_admin_only"
		}
		ns, name, key, ok := substrateK8sSource(substrateSecretFor(sec, c.person.Subject))
		if !ok {
			return "", "", "", http.StatusConflict, "secret_managed_outside_defenseclaw"
		}
		if st.cfg.SecretStore == nil {
			return "", "", "", http.StatusServiceUnavailable, "secret_store_unavailable"
		}
		return ns, name, key, http.StatusOK, ""
	}
	return "", "", "", http.StatusNotFound, "secret_not_found"
}

func (a *APIServer) substrateSetSecret(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name, key, status, reason := a.substrateWritableSecret(st, r)
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		var in struct {
			Value string `json:"value"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Value == "" || len(in.Value) > substrateSecretMaxSize || !utf8.ValidString(in.Value) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "value_required")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		stored, bad := a.substrateStoredValue(st, c, ns, name, key, in.Value)
		if bad != "" {
			writeSubstrateJSONError(w, http.StatusBadRequest, bad)
			return
		}
		if err := st.cfg.SecretStore.Set(r.Context(), ns, name, key, []byte(stored)); err != nil {
			// The error names the Secret, never the value.
			fmt.Fprintf(os.Stderr, "[substrate] secret %s not stored: %v\n", r.PathValue("name"), err)
			a.recordSubstrateSecretChange(r.Context(), st, r.PathValue("name"), audit.SubstrateSecretSet, "", true)
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_stored"))
			return
		}
		a.substrateRestampBinding(r.Context(), st, c, ns, name, key)
		a.recordSubstrateSecretChange(r.Context(), st, r.PathValue("name"), audit.SubstrateSecretSet, "", false)
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "status": substrateSecretSet})
	}
}

func (a *APIServer) substrateRemoveSecret(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name, key, status, reason := a.substrateWritableSecret(st, r)
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		if err := st.cfg.SecretStore.Remove(r.Context(), ns, name, key); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] secret %s not removed: %v\n", r.PathValue("name"), err)
			a.recordSubstrateSecretChange(r.Context(), st, r.PathValue("name"), audit.SubstrateSecretRemoved, "", true)
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_removed"))
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		if err := a.substrateRemoveBinding(r.Context(), st, c, r.PathValue("name"), key); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] binding %s not removed: %v\n", r.PathValue("name"), err)
			a.recordSubstrateSecretChange(r.Context(), st, r.PathValue("name"), audit.SubstrateSecretRemoved, "", true)
			writeSubstrateJSONError(w, http.StatusBadGateway, "secret_not_removed")
			return
		}
		a.recordSubstrateSecretChange(r.Context(), st, r.PathValue("name"), audit.SubstrateSecretRemoved, "", false)
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "status": substrateSecretNotSet})
	}
}

// substrateSecretErrorStatus and substrateSecretErrorReason answer a store
// error: a Secret DefenseClaw does not own is 409, anything else 502.
func substrateSecretErrorStatus(err error) int {
	if errors.Is(err, ErrSubstrateSecretNotOwned) {
		return http.StatusConflict
	}
	return http.StatusBadGateway
}

func substrateSecretErrorReason(err error, other string) string {
	if errors.Is(err, ErrSubstrateSecretNotOwned) {
		return "secret_not_managed_by_defenseclaw"
	}
	return other
}

func (a *APIServer) substrateTestSecret(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Agent string `json:"agent"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
				writeSubstrateJSONError(w, http.StatusBadRequest, "secret_test_agent_invalid")
				return
			}
		}
		c, _ := substrateCallerFrom(r.Context())
		profile, _, _ := st.cfg.substrateProfiles()(c.person, "", "", false)
		for _, e := range a.substrateSecretEntries(st, c, profile) {
			if e.sec.Name != r.PathValue("name") {
				continue
			}
			var reg registry.Registration
			if in.Agent != "" {
				space, name, ok := strings.Cut(in.Agent, "/")
				if !ok {
					writeSubstrateJSONError(w, http.StatusBadRequest, "secret_test_agent_invalid")
					return
				}
				got, status, reason := a.substrateFind(st, r, space, name)
				if status != http.StatusOK {
					writeSubstrateJSONError(w, status, reason)
					return
				}
				reg = got
				a.substrateAuditAdminTarget(st, r, reg, "secret test", "INFO")
			}
			now := time.Now()
			status, reason := a.substrateSecretState(r.Context(), st, e, c.person.Subject, a.substrateBindingAsks(r.Context(), st, c), now)
			out := substrateSecretView(e, status, reason, nil, false)
			if st.cfg.Registrations != nil && st.cfg.SecretUses != nil {
				if regs, err := st.cfg.Registrations.List(r.Context(), registry.Filter{OwnerID: ownerOf(c.person).ID()}); err == nil {
					if u, agent, ok := substrateSecretLastUse(e, status, regs, st.substrateHostUses(r.Context(), regs), st.noSwapHosts(), now); ok {
						addSubstrateSecretLastUse(out, u, agent)
					}
				}
			}
			if in.Agent != "" {
				// The actor's own person decides a personal secret's value.
				astatus, areason := status, reason
				if reg.Person.Subject != c.person.Subject {
					astatus, areason = a.substrateSecretState(r.Context(), st, e, reg.Person.Subject, nil, time.Now())
				}
				inPolicy, why := a.substrateSecretInPolicy(r.Context(), st, e, astatus, areason, reg)
				ag := map[string]any{"actor": reg.Atespace + "/" + reg.Name, "in_policy": inPolicy}
				if why != "" {
					ag["reason"] = why
				}
				out["agent"] = ag
			}
			writeSubstrateJSON(w, http.StatusOK, out)
			return
		}
		writeSubstrateJSONError(w, http.StatusNotFound, "secret_not_found")
	}
}

// substratePayloadHMAC is the gateway's keyed digest (the telemetry HMAC
// of the device key); a test replaces it.
var substratePayloadHMAC = gatewaylog.ComputePayloadHMAC

// substrateSubjectKey is the keyed pseudonym of a person's OIDC subject
// (hmac-sha256:<64 hex>), "" with no subject or no telemetry key.
func substrateSubjectKey(subject string) string {
	if subject == "" {
		return ""
	}
	d := substratePayloadHMAC(struct {
		Kind    string `json:"kind"`
		Subject string `json:"subject"`
	}{Kind: "substrate_person", Subject: subject})
	if d == "" {
		return ""
	}
	return "hmac-sha256:" + d
}

// recordSubstrateSecretChange writes the typed audit record of one secret
// value or binding change (log.substrate.secret.changed, B1 M-OBS-1). It
// carries the name, the operation and the bound host, never the value; it
// replaces the old stderr "secret ... set by" line. A record that cannot be
// written is noted on stderr and does not fail the change.
func (a *APIServer) recordSubstrateSecretChange(ctx context.Context, st *substrateState, name string,
	op audit.SubstrateSecretOperation, host string, failed bool) {
	ev := audit.SubstrateSecretChangeEvent{Name: name, Operation: op, Host: host, Failed: failed, Timestamp: time.Now()}
	// The record says who made the change (RV3 P2-4): the acting person,
	// as a keyed pseudonym, never the subject itself.
	if c, ok := substrateCallerFrom(ctx); ok {
		ev.SubjectKey = substrateSubjectKey(c.person.Subject)
	}
	if st != nil && st.cfg.SecretAudit != nil {
		st.cfg.SecretAudit(ctx, ev)
		return
	}
	if a == nil || a.logger == nil {
		return
	}
	if err := a.managedSandboxRecorder().RecordSubstrateSecretChange(context.WithoutCancel(ctx), ev); err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] secret %s change record failed: %v\n", name, err)
	}
}
