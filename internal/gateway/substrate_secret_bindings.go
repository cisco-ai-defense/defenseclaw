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
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// Self-service binding statuses and limits (B1 2.1, 2.6).
const (
	substrateSecretWaiting = "waiting on admin"
	// substrateBindingMaxExpiry bounds --expires: a binding lives at most
	// about 13 months before it must be added again.
	substrateBindingMaxExpiry = 400 * 24 * time.Hour
)

var (
	errSubstrateBindingTaken = errors.New("name taken")
	errSubstrateBindingLimit = errors.New("binding limit")
)

// substrateBindingsOn reports whether people may add bindings: the mode is
// bindings and the gateway has a store. values_only keeps set on listed
// secrets; off reads no store at all.
// selfService is the self-service config in force: the live one when the
// gateway follows config.yaml, with the boot namespace and provider (where
// the values live is fixed until a restart).
func (st *substrateState) selfService() config.SubstrateSelfServiceSecretsConfig {
	if st.cfg.LiveSelfService == nil {
		return st.cfg.SelfService
	}
	ss, _ := st.cfg.LiveSelfService()
	ss.Namespace, ss.Provider = st.cfg.SelfService.Namespace, st.cfg.SelfService.Provider
	return ss
}

// noSwapHosts is substrate.egress.no_swap_hosts in force (RV3 P3-1).
func (st *substrateState) noSwapHosts() []string {
	if st.cfg.LiveNoSwapHosts == nil {
		return st.cfg.NoSwapHosts
	}
	return st.cfg.LiveNoSwapHosts()
}

// secretTemplates is the template catalog config in force.
func (st *substrateState) secretTemplates() []config.SubstrateSecretTemplate {
	if st.cfg.LiveSelfService == nil {
		return st.cfg.SecretTemplates
	}
	_, ts := st.cfg.LiveSelfService()
	return ts
}

func substrateBindingsOn(st *substrateState) (status int, reason string) {
	switch {
	case st.cfg.Bindings == nil || st.selfService().EffectiveMode() == config.SelfServiceOff:
		return http.StatusNotFound, "secret_bindings_off"
	case st.selfService().EffectiveMode() == config.SelfServiceValuesOnly:
		return http.StatusForbidden, "secret_bindings_locked"
	}
	return http.StatusOK, ""
}

// substrateOwnBindings are the caller's own bindings, in every state, as
// substrate.secrets entries: set, rm and test then find them like any
// per-person secret. Their source keeps the person placeholder, so it
// resolves to the caller's own value Secret.
func (a *APIServer) substrateOwnBindings(st *substrateState, c substrateCaller) []config.SubstrateSecret {
	if st.cfg.Bindings == nil || c.person.Subject == "" || st.selfService().EffectiveMode() == config.SelfServiceOff {
		return nil
	}
	catalog := secretbind.Catalog(st.secretTemplates())
	ss := st.selfService()
	var out []config.SubstrateSecret
	for _, b := range st.cfg.Bindings.ForOwner(render.PersonKey(c.person.Subject)) {
		t, _ := secretbind.Find(catalog, b.Template)
		sec := secretbind.SecretFor(t, ss.EffectiveProvider(), ss.EffectiveNamespace(), b, ss.AllowEchoBindings)
		sec.Profiles = []string{"*"} // the owner always reaches their own binding
		out = append(out, sec)
	}
	return out
}

// substrateSecretTemplates answers GET /api/v1/substrate/secret-templates:
// the templates the caller's profile may use.
func (a *APIServer) substrateSecretTemplates(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status, reason := substrateBindingsOn(st); status == http.StatusNotFound {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		c, profile, _ := a.substrateSecretLookup(st, r)
		out := []secretbind.Template{}
		for _, t := range secretbind.Catalog(st.secretTemplates()) {
			if c.admin || t.ForProfile(profile) {
				out = append(out, t)
			}
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"templates": out, "mode": st.selfService().EffectiveMode()})
	}
}

// substrateAddSecret answers POST /api/v1/substrate/secrets: the caller
// binds a value of their own to one host under a template. A host inside
// the template's patterns is active at once; one outside them waits on an
// administrator (secret_binding_outside_templates). The value is stored
// first, in the caller's own Secret, and removed again if the binding
// cannot be written.
func (a *APIServer) substrateAddSecret(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status, reason := substrateBindingsOn(st); status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		// One view of the config for the whole request (RV4 F10).
		ss, tmpls, noSwap := st.selfService(), st.secretTemplates(), st.noSwapHosts()
		c, profile, secrets := a.substrateSecretLookup(st, r)
		if c.person.Subject == "" {
			writeSubstrateJSONError(w, http.StatusForbidden, "secret_needs_person")
			return
		}
		if st.cfg.SecretStore == nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "secret_store_unavailable")
			return
		}
		var in struct {
			Name      string    `json:"name"`
			Template  string    `json:"template"`
			Host      string    `json:"host"`
			Value     string    `json:"value"`
			Expires   time.Time `json:"expires,omitzero"`
			AllowEcho bool      `json:"allow_echo,omitempty"`
			User      string    `json:"user,omitempty"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*substrateSecretMaxSize))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "value_required")
			return
		}
		if in.Value == "" || len(in.Value) > substrateSecretMaxSize || !utf8.ValidString(in.Value) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "value_required")
			return
		}
		t, ok := secretbind.Find(secretbind.Catalog(tmpls), in.Template)
		if !ok || (!c.admin && !t.ForProfile(profile)) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_template_unknown")
			return
		}
		if in.User != "" && t.Form != secretbind.FormBasic {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_invalid")
			return
		}
		host := strings.ToLower(strings.TrimSpace(in.Host))
		if p, ok := egressspec.ParsePattern(host); !ok || p.Any {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_pattern")
			return
		}
		if len(egressspec.EchoHostsCoveredWith(host, noSwap)) > 0 && (!in.AllowEcho || !ss.AllowEchoBindings) {
			writeSubstrateJSONError(w, http.StatusForbidden, "secret_echo_host")
			return
		}
		now := time.Now().UTC()
		if !in.Expires.IsZero() && (!in.Expires.After(now) || in.Expires.Sub(now) > substrateBindingMaxExpiry) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_invalid")
			return
		}
		for _, sec := range secrets {
			if sec.Name == in.Name {
				writeSubstrateJSONError(w, http.StatusConflict, "secret_name_taken")
				return
			}
		}
		owner := render.PersonKey(c.person.Subject)
		// The cached store answers the name and the limit before an ask is
		// opened or a value is written; the Update below keeps the
		// authoritative check (RV4 F6).
		mine := st.cfg.Bindings.ForOwner(owner)
		for _, x := range mine {
			if x.Name == in.Name {
				writeSubstrateJSONError(w, http.StatusConflict, "secret_name_taken")
				return
			}
		}
		if len(mine) >= ss.EffectiveMaxPerPerson() {
			writeSubstrateJSONError(w, http.StatusConflict, "secret_binding_limit")
			return
		}
		b := secretbind.Binding{ID: secretbind.NewID(), Name: in.Name, Owner: owner, Template: t.Name, Hosts: []string{host},
			State: secretbind.Active, Expires: in.Expires.UTC(), AllowEcho: in.AllowEcho && ss.AllowEchoBindings,
			BasicUser: in.User, Created: now}
		b.StoredForm = t.FormStamp(b)
		reason := ""
		if !t.Covers(host) {
			b.State, reason = secretbind.Waiting, "secret_binding_outside_templates"
		}
		stored, err := t.StoredValue(b, in.Value)
		if err != nil || b.Check() != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_invalid")
			return
		}
		// A host outside every template waits on an administrator's ask
		// (outside_templates: ask) or is refused (refuse). The ask is
		// opened first, so the stored binding carries its id; it is denied
		// again below if the binding is not stored.
		var ask asks.Ask
		if reason != "" {
			switch {
			case ss.EffectiveOutsideTemplates() == "refuse":
				writeSubstrateJSONError(w, http.StatusForbidden, "secret_binding_outside_refused")
				return
			case st.cfg.Asks == nil:
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "secret_store_unavailable")
				return
			}
			ask, err = st.cfg.Asks.OpenAsk(r.Context(), asks.Ask{
				Kind: asks.KindSecretBinding, OwnerID: ownerOf(c.person).ID(), Profile: profile,
				Host: host, Tool: b.Name, Rule: asks.BindingRule(b.ID), Severity: "MEDIUM",
				Summary:        fmt.Sprintf("%s asks to bind their secret %s (template %s) to %s", c.person.Subject, b.Name, t.Name, host),
				TimeoutSeconds: int64(ss.EffectiveAskTimeout() / time.Second),
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[substrate] binding %s: ask not opened: %v\n", b.Name, err)
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "secret_store_unavailable")
				return
			}
			b.AskID = ask.ID
		}
		dropAsk := func() {
			if ask.ID != "" {
				_, _ = st.cfg.Asks.Resolve(r.Context(), asks.ResolveRequest{ID: ask.ID, Decision: "deny",
					Note: "the binding was not stored", CallerID: ownerOf(c.person).ID(), Admin: true})
			}
		}
		ns, vname := ss.EffectiveNamespace(), secretbind.ValueSecretName(owner)
		if err := st.cfg.SecretStore.Set(r.Context(), ns, vname, b.ID, []byte(stored)); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] secret %s not stored: %v\n", b.Name, err)
			dropAsk()
			a.recordSubstrateSecretChange(r.Context(), st, b.Name, audit.SubstrateSecretBindingAdded, host, true)
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_stored"))
			return
		}
		limit := ss.EffectiveMaxPerPerson()
		err = st.cfg.Bindings.Update(r.Context(), func(d *secretbind.Doc) error {
			n := 0
			for _, x := range d.Bindings {
				if x.Owner != owner {
					continue
				}
				if x.Name == b.Name {
					return errSubstrateBindingTaken
				}
				n++
			}
			if n >= limit {
				return errSubstrateBindingLimit
			}
			d.Bindings = append(d.Bindings, b)
			return nil
		})
		if err != nil {
			// The value has no binding: take it back out.
			_ = st.cfg.SecretStore.Remove(r.Context(), ns, vname, b.ID)
			dropAsk()
			status, code := http.StatusBadGateway, "secret_not_stored"
			switch {
			case errors.Is(err, errSubstrateBindingTaken):
				status, code = http.StatusConflict, "secret_name_taken"
			case errors.Is(err, errSubstrateBindingLimit), errors.Is(err, secretbind.ErrFull):
				status, code = http.StatusConflict, "secret_binding_limit"
			default:
				fmt.Fprintf(os.Stderr, "[substrate] binding %s not stored: %v\n", b.Name, err)
			}
			a.recordSubstrateSecretChange(r.Context(), st, b.Name, audit.SubstrateSecretBindingAdded, host, true)
			writeSubstrateJSONError(w, status, code)
			return
		}
		a.recordSubstrateSecretChange(r.Context(), st, b.Name, audit.SubstrateSecretBindingAdded, host, false)
		out := map[string]any{"name": b.Name, "id": b.ID, "template": t.Name, "host": host, "status": substrateSecretSet}
		code := http.StatusCreated
		if reason != "" {
			out["status"], out["reason"], out["ask_id"], code = substrateSecretWaiting, reason, ask.ID, http.StatusAccepted
			// An administrator may have answered the ask before the binding
			// was written; that answer found no binding to move, so it is
			// applied now (RV4 F2).
			if got, ok := a.substrateFindAsk(r.Context(), st, ownerOf(c.person).ID(), ask.ID); ok && got.State != asks.StatePending {
				if err := a.substrateBindingDecided(r.Context(), st, got); err != nil && !errors.Is(err, errSubstrateBindingGone) {
					fmt.Fprintf(os.Stderr, "[substrate] binding %s: answered ask not applied: %v\n", b.Name, err)
				} else if got.State == asks.StateApproved {
					delete(out, "reason")
					out["status"], code = substrateSecretSet, http.StatusCreated
				} else {
					out["status"], out["reason"] = substrateSecretDenied, "secret_binding_denied"
				}
			}
		}
		if !b.Expires.IsZero() {
			out["expires"] = b.Expires
		}
		writeSubstrateJSON(w, code, out)
	}
}

// substrateStoredValue is the value set stores at ns/name/key. When that
// is the caller's own binding it is the template's stored form
// (base64(user:token) for basic), so a re-set keeps injection working;
// anything else (an admin per_person secret) is stored as given. reason is
// set when the binding's template is gone or cannot form the value.
func (a *APIServer) substrateStoredValue(st *substrateState, c substrateCaller, ns, name, key, value string) (stored, reason string) {
	if st.cfg.Bindings == nil || c.person.Subject == "" {
		return value, ""
	}
	owner := render.PersonKey(c.person.Subject)
	if ns != st.selfService().EffectiveNamespace() || name != secretbind.ValueSecretName(owner) {
		return value, ""
	}
	for _, b := range st.cfg.Bindings.ForOwner(owner) {
		if b.ID != key {
			continue
		}
		t, ok := secretbind.Find(secretbind.Catalog(st.secretTemplates()), b.Template)
		if !ok {
			return "", "secret_template_unknown"
		}
		v, err := t.StoredValue(b, value)
		if err != nil {
			return "", "secret_invalid"
		}
		return v, ""
	}
	return value, ""
}

// substrateRestampBinding records, after a set of the caller's own binding
// value, the form the value was just stored in (RV3 P4-3).
func (a *APIServer) substrateRestampBinding(ctx context.Context, st *substrateState, c substrateCaller, ns, name, key string) {
	if st.cfg.Bindings == nil || c.person.Subject == "" {
		return
	}
	owner := render.PersonKey(c.person.Subject)
	if ns != st.selfService().EffectiveNamespace() || name != secretbind.ValueSecretName(owner) {
		return
	}
	catalog := secretbind.Catalog(st.secretTemplates())
	_ = st.cfg.Bindings.Update(ctx, func(d *secretbind.Doc) error {
		for i := range d.Bindings {
			if x := &d.Bindings[i]; x.ID == key && x.Owner == owner {
				if t, ok := secretbind.Find(catalog, x.Template); ok {
					x.StoredForm = t.FormStamp(*x)
				}
			}
		}
		return nil
	})
}

// substrateRemoveBinding drops the caller's binding named name from the
// store after the value under removedKey was removed. A name that is not a
// binding (a per-person admin secret) is left alone. When an admin
// per_person secret of the same name shadowed the binding, removedKey was
// the admin secret's: the binding's own value goes too, so no value is
// left behind without a binding (RV3 P3-3).
func (a *APIServer) substrateRemoveBinding(ctx context.Context, st *substrateState, c substrateCaller, name, removedKey string) error {
	if st.cfg.Bindings == nil || c.person.Subject == "" {
		return nil
	}
	owner := render.PersonKey(c.person.Subject)
	found := false
	var askIDs []string
	for _, b := range st.cfg.Bindings.ForOwner(owner) {
		if b.Name != name {
			continue
		}
		found = true
		if b.State == secretbind.Waiting && b.AskID != "" {
			askIDs = append(askIDs, b.AskID)
		}
		if b.ID != removedKey && st.cfg.SecretStore != nil {
			if err := st.cfg.SecretStore.Remove(ctx, st.selfService().EffectiveNamespace(), secretbind.ValueSecretName(owner), b.ID); err != nil {
				return err
			}
		}
	}
	if !found {
		return nil
	}
	if err := st.cfg.Bindings.Update(ctx, func(d *secretbind.Doc) error {
		d.Bindings = slicesDeleteBinding(d.Bindings, owner, name)
		return nil
	}); err != nil {
		return err
	}
	// A waiting binding's ask is denied with it, so no administrator is
	// asked about a binding that is gone (RV4 F4). An ask that was already
	// answered answers ErrDecided, which is fine.
	if st.cfg.Asks != nil {
		for _, id := range askIDs {
			_, _ = st.cfg.Asks.Resolve(ctx, asks.ResolveRequest{ID: id, Decision: "deny",
				Note: "the binding was removed", CallerID: ownerOf(c.person).ID(), Admin: true})
		}
	}
	return nil
}

func slicesDeleteBinding(in []secretbind.Binding, owner, name string) []secretbind.Binding {
	out := in[:0]
	for _, b := range in {
		if b.Owner != owner || b.Name != name {
			out = append(out, b)
		}
	}
	return out
}

// substrateFindAsk returns the ask id of the person ownerID, read again
// from the ask store.
func (a *APIServer) substrateFindAsk(ctx context.Context, st *substrateState, ownerID, id string) (asks.Ask, bool) {
	if st.cfg.Asks == nil || id == "" {
		return asks.Ask{}, false
	}
	list, err := st.cfg.Asks.List(ctx, asks.ListRequest{OwnerID: ownerID, All: ownerID == ""})
	if err != nil {
		return asks.Ask{}, false
	}
	for _, x := range list {
		if x.ID == id {
			return x, true
		}
	}
	return asks.Ask{}, false
}

// substrateReapplyBindingDecision handles an administrator's decision on a
// binding ask that is already answered: when the ask was answered the same
// way, it moves the binding again and reports ok (RV4 F2). A binding that
// already moved stays as it is, so a repeat is harmless.
func (a *APIServer) substrateReapplyBindingDecision(ctx context.Context, st *substrateState, c substrateCaller,
	id, decision string) (asks.Ask, bool, error) {
	if !c.admin || st.cfg.Bindings == nil {
		return asks.Ask{}, false, nil
	}
	got, ok := a.substrateFindAsk(ctx, st, "", id)
	want := asks.StateDenied
	if decision == "approve" {
		want = asks.StateApproved
	}
	if !ok || got.Kind != asks.KindSecretBinding || got.State != want {
		return asks.Ask{}, false, nil
	}
	return got, true, a.substrateBindingDecided(ctx, st, got)
}

// errSubstrateBindingGone is an answered binding ask whose binding was
// removed meanwhile.
var errSubstrateBindingGone = errors.New("the binding of this ask is gone")

// substrateBindingDecided moves the binding of a secret_binding ask an
// administrator answered: approved -> active (its owner's actors get it on
// the controller's next pass), anything else -> denied (render drops it
// with secret_binding_denied). Only a waiting binding that names this ask
// moves; one that already moved stays. A binding that is gone answers
// errSubstrateBindingGone. An ask that expires unanswered moves nothing:
// list says "ask expired", and the person removes the binding and adds it
// again (RV4 F5).
func (a *APIServer) substrateBindingDecided(ctx context.Context, st *substrateState, got asks.Ask) error {
	id := got.BindingID()
	if id == "" || st.cfg.Bindings == nil {
		return nil
	}
	state, op := secretbind.Denied, audit.SubstrateSecretBindingDenied
	if got.State == asks.StateApproved {
		state, op = secretbind.Active, audit.SubstrateSecretBindingApproved
	}
	var name, host string
	err := st.cfg.Bindings.Update(ctx, func(d *secretbind.Doc) error {
		for i := range d.Bindings {
			x := &d.Bindings[i]
			if x.ID != id || x.AskID != got.ID {
				continue
			}
			if x.State == secretbind.Waiting {
				x.State, name = state, x.Name
				if len(x.Hosts) > 0 {
					host = x.Hosts[0]
				}
			}
			return nil
		}
		return errSubstrateBindingGone
	})
	if errors.Is(err, errSubstrateBindingGone) || (err == nil && name == "") {
		return err
	}
	a.recordSubstrateSecretChange(ctx, st, firstNonEmptyString(name, got.Tool), op, firstNonEmptyString(host, got.Host), err != nil)
	return err
}
