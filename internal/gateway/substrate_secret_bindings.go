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
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
func substrateBindingsOn(st *substrateState) (status int, reason string) {
	switch {
	case st.cfg.Bindings == nil || st.cfg.SelfService.EffectiveMode() == config.SelfServiceOff:
		return http.StatusNotFound, "secret_bindings_off"
	case st.cfg.SelfService.EffectiveMode() == config.SelfServiceValuesOnly:
		return http.StatusForbidden, "secret_bindings_locked"
	}
	return http.StatusOK, ""
}

// substrateOwnBindings are the caller's own bindings, in every state, as
// substrate.secrets entries: set, rm and test then find them like any
// per-person secret. Their source keeps the person placeholder, so it
// resolves to the caller's own value Secret.
func (a *APIServer) substrateOwnBindings(st *substrateState, c substrateCaller) []config.SubstrateSecret {
	if st.cfg.Bindings == nil || c.person.Subject == "" || st.cfg.SelfService.EffectiveMode() == config.SelfServiceOff {
		return nil
	}
	catalog := secretbind.Catalog(st.cfg.SecretTemplates)
	ss := st.cfg.SelfService
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
		for _, t := range secretbind.Catalog(st.cfg.SecretTemplates) {
			if c.admin || t.ForProfile(profile) {
				out = append(out, t)
			}
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"templates": out, "mode": st.cfg.SelfService.EffectiveMode()})
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
		t, ok := secretbind.Find(secretbind.Catalog(st.cfg.SecretTemplates), in.Template)
		if !ok || (!c.admin && !t.ForProfile(profile)) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_template_unknown")
			return
		}
		host := strings.ToLower(strings.TrimSpace(in.Host))
		if p, ok := egressspec.ParsePattern(host); !ok || p.Any {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_pattern")
			return
		}
		if len(egressspec.EchoHostsCoveredWith(host, st.cfg.NoSwapHosts)) > 0 && !(in.AllowEcho && st.cfg.SelfService.AllowEchoBindings) {
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
		b := secretbind.Binding{ID: secretbind.NewID(), Name: in.Name, Owner: owner, Template: t.Name, Hosts: []string{host},
			State: secretbind.Active, Expires: in.Expires.UTC(), AllowEcho: in.AllowEcho && st.cfg.SelfService.AllowEchoBindings,
			Created: now}
		reason := ""
		if !t.Covers(host) {
			b.State, reason = secretbind.Waiting, "secret_binding_outside_templates"
		}
		if err := b.Check(); err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "secret_invalid")
			return
		}
		ns, vname := st.cfg.SelfService.EffectiveNamespace(), secretbind.ValueSecretName(owner)
		if err := st.cfg.SecretStore.Set(r.Context(), ns, vname, b.ID, []byte(in.Value)); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] secret %s not stored: %v\n", b.Name, err)
			a.recordSubstrateSecretChange(r.Context(), st, b.Name, audit.SubstrateSecretBindingAdded, host, true)
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_stored"))
			return
		}
		limit := st.cfg.SelfService.EffectiveMaxPerPerson()
		err := st.cfg.Bindings.Update(r.Context(), func(d *secretbind.Doc) error {
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
			out["status"], out["reason"], code = substrateSecretWaiting, reason, http.StatusAccepted
		}
		if !b.Expires.IsZero() {
			out["expires"] = b.Expires
		}
		writeSubstrateJSON(w, code, out)
	}
}

// substrateRemoveBinding drops the caller's binding named name from the
// store after its value was removed. A name that is not a binding (a
// per-person admin secret) is left alone.
func (a *APIServer) substrateRemoveBinding(ctx context.Context, st *substrateState, c substrateCaller, name string) error {
	if st.cfg.Bindings == nil || c.person.Subject == "" {
		return nil
	}
	owner := render.PersonKey(c.person.Subject)
	if !slices.ContainsFunc(st.cfg.Bindings.ForOwner(owner), func(b secretbind.Binding) bool { return b.Name == name }) {
		return nil
	}
	return st.cfg.Bindings.Update(ctx, func(d *secretbind.Doc) error {
		d.Bindings = slicesDeleteBinding(d.Bindings, owner, name)
		return nil
	})
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
