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
	"net/url"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
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
	substrateSecretMaxSize = 64 << 10
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
	return c, profile, st.cfg.Secrets
}

func (a *APIServer) substrateListSecrets(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, profile, secrets := a.substrateSecretLookup(st, r)
		mine := r.URL.Query().Get("mine") == "1"
		out := []map[string]any{}
		for _, sec := range secrets {
			if !substrateSecretBound(sec, profile, c.admin) {
				continue
			}
			perPerson := sec.Scope == render.ScopePerPerson
			if mine && !perPerson {
				continue
			}
			status := substrateSecretManaged
			if ns, name, key, ok := substrateK8sSource(substrateSecretFor(sec, c.person.Subject)); ok && st.cfg.SecretStore != nil {
				status = substrateSecretUnknown
				if found, err := st.cfg.SecretStore.Exists(r.Context(), ns, name, key); err == nil {
					status = map[bool]string{true: substrateSecretSet, false: substrateSecretNotSet}[found]
				}
			}
			if mine && status != substrateSecretSet {
				continue
			}
			scope := sec.Scope
			if scope == "" {
				scope = render.ScopeShared
			}
			out = append(out, map[string]any{"name": sec.Name, "scope": scope, "hosts": sec.Inject.Hosts, "mine": perPerson, "status": status})
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"secrets": out})
	}
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
		if err := st.cfg.SecretStore.Set(r.Context(), ns, name, key, []byte(in.Value)); err != nil {
			// The error names the Secret, never the value.
			fmt.Fprintf(os.Stderr, "[substrate] secret %s not stored: %v\n", r.PathValue("name"), err)
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_stored"))
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		fmt.Fprintf(os.Stderr, "[substrate] secret %s set by %s\n", r.PathValue("name"), sanitizeLLMEventUser(c.person.Principal))
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
			writeSubstrateJSONError(w, substrateSecretErrorStatus(err), substrateSecretErrorReason(err, "secret_not_removed"))
			return
		}
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
		c, profile, secrets := a.substrateSecretLookup(st, r)
		for _, sec := range secrets {
			if sec.Name != r.PathValue("name") || !substrateSecretBound(sec, profile, c.admin) {
				continue
			}
			ns, name, key, ok := substrateK8sSource(substrateSecretFor(sec, c.person.Subject))
			if !ok || st.cfg.SecretStore == nil {
				writeSubstrateJSON(w, http.StatusOK, map[string]any{"name": sec.Name, "status": substrateSecretManaged})
				return
			}
			found, err := st.cfg.SecretStore.Exists(r.Context(), ns, name, key)
			status := map[bool]string{true: substrateSecretSet, false: substrateSecretNotSet}[found]
			if err != nil {
				status = substrateSecretUnknown
			}
			writeSubstrateJSON(w, http.StatusOK, map[string]any{"name": sec.Name, "status": status, "hosts": sec.Inject.Hosts})
			return
		}
		writeSubstrateJSONError(w, http.StatusNotFound, "secret_not_found")
	}
}
