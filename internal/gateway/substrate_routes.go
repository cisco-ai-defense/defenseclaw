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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The admin listener: people sign in with OIDC (the launcher's device
// flow) or as a CI workload; users see only their own actors, asks,
// batches and usage, administrators everything. The callout reaches its
// verdict route here with its service token. Nothing here is reachable
// from an actor: the admin Service is never in an EgressPolicy (D15).

const (
	substrateAdminPrefix   = "/api/v1/substrate/"
	substrateCalloutPath   = calloutapi.Path
	substrateAdminMaxBody  = 1 << 20
	substrateSessionMaxTTL = identity.MaxSessionLifetime
)

// SubstrateCreate is a launcher create request.
type SubstrateCreate struct {
	Profile   string `json:"profile"`
	Template  string `json:"template"`
	Connector string `json:"connector,omitempty"`
	// Name is the actor name; empty lets the gateway choose one.
	Name      string             `json:"name,omitempty"`
	Workspace SubstrateWorkspace `json:"workspace,omitzero"`
	Task      string             `json:"task,omitempty"`
	BatchID   string             `json:"batch_id,omitempty"`
	// Unattended is a --task or --batch run (fail closed, D8).
	Unattended bool     `json:"unattended,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
	// Atespace is filled by the gateway from the profile; a request value
	// is refused unless it is one of the profile's launcher atespaces.
	Atespace string `json:"atespace,omitempty"`
	// Owner is filled by the gateway (the verified person).
	Owner registry.Person `json:"-"`
}

// SubstrateWorkspace is what the actor starts with.
type SubstrateWorkspace struct {
	// UploadID names a workspace archive the launcher uploaded.
	UploadID string `json:"upload_id,omitempty"`
	// Clone is a repository URL to clone at first resume.
	Clone string `json:"clone,omitempty"`
	Ref   string `json:"ref,omitempty"`
}

// SubstrateCreated is the actor the control API created, suspended.
type SubstrateCreated struct {
	Atespace       string
	Name           string
	UID            string
	Template       string
	TemplateDigest string
	Connector      string
	HarnessVersion string
	HookContract   string
	KitVersion     string
}

// SubstrateActorActions creates, resumes and deletes actors in launcher
// atespaces (the controller lane's ateapi client). Create leaves the actor
// suspended, so its registration is written before it can make a call.
type SubstrateActorActions interface {
	Create(ctx context.Context, req SubstrateCreate) (SubstrateCreated, error)
	Resume(ctx context.Context, atespace, name string) error
	Delete(ctx context.Context, atespace, name string) error
}

// SubstrateUsage answers usage for one owner ("" for every owner).
type SubstrateUsage interface {
	Usage(ctx context.Context, ownerID, batchID string) (any, error)
}

// SubstrateProfileResolver picks the profile and launcher atespace of a
// create for person, or refuses.
type SubstrateProfileResolver func(person identity.Person, requested string) (profile, atespace string, err error)

type substratePersonKey struct{}

func withSubstratePerson(ctx context.Context, p identity.Person, admin bool) context.Context {
	return context.WithValue(ctx, substratePersonKey{}, substrateCaller{person: p, admin: admin})
}

type substrateCaller struct {
	person identity.Person
	admin  bool
}

func substrateCallerFrom(ctx context.Context) (substrateCaller, bool) {
	c, ok := ctx.Value(substratePersonKey{}).(substrateCaller)
	return c, ok
}

// ownerOf is the registry owner key of a person.
func ownerOf(p identity.Person) registry.Person {
	return registry.Person{Kind: p.Kind, Issuer: p.Issuer, Subject: p.Subject, Principal: p.Principal, Groups: p.Groups}
}

func (a *APIServer) newSubstrateAdminHandler(st *substrateState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/substrate/actors", a.substrateCreateActor(st))
	mux.HandleFunc("GET /api/v1/substrate/actors", a.substrateListActors(st))
	mux.HandleFunc("GET /api/v1/substrate/actors/{atespace}/{name}", a.substrateGetActor(st))
	mux.HandleFunc("DELETE /api/v1/substrate/actors/{atespace}/{name}", a.substrateDeleteActor(st))
	mux.HandleFunc("POST /api/v1/substrate/session-cert", a.substrateSessionCert(st))
	mux.HandleFunc("GET /api/v1/substrate/batches", a.substrateListBatches(st))
	mux.HandleFunc("GET /api/v1/substrate/batches/{id}", a.substrateGetBatch(st))
	mux.HandleFunc("GET /api/v1/substrate/usage", a.substrateUsage(st))
	for _, p := range []string{"asks", "decisions", "policy/explain", "secrets"} {
		mux.HandleFunc("/api/v1/substrate/"+p, substrateNotYet)
	}
	mux.HandleFunc("/api/v1/substrate/asks/{id}", substrateNotYet)
	mux.HandleFunc("/api/v1/substrate/secrets/{name}", substrateNotYet)
	// The admin listener keeps the browser CSRF gate: people reach it from
	// the launcher and possibly from a browser session, so a state-changing
	// request must carry X-DefenseClaw-Client (the actor listener does not
	// apply it, GAP-0037).
	callout := a.apiCSRFProtect(a.substrateCalloutVerdict(st))
	people := a.apiCSRFProtect(a.substrateAdminAuthenticate(st, mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !strings.HasPrefix(r.URL.Path, substrateAdminPrefix) || r.URL.RawPath != "" {
			writeSubstrateJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, substrateAdminMaxBody)
		if r.URL.Path == substrateCalloutPath {
			callout.ServeHTTP(w, r)
			return
		}
		people.ServeHTTP(w, r)
	})
}

func writeSubstrateJSONError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q,\"reason\":%q}\n", http.StatusText(status), reason)
}

func writeSubstrateJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func substrateNotYet(w http.ResponseWriter, _ *http.Request) {
	writeSubstrateJSONError(w, http.StatusNotImplemented, "not_implemented")
}

func bearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

func (a *APIServer) substrateAdminAuthenticate(st *substrateState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeSubstrateJSONError(w, http.StatusUnauthorized, string(identity.ReasonMissing))
			return
		}
		p, err := st.cfg.People.Verify(r.Context(), tok)
		if err != nil {
			status := http.StatusUnauthorized
			if identity.Unavailable(err) {
				status = http.StatusServiceUnavailable
			}
			writeSubstrateJSONError(w, status, string(identity.ReasonOf(err)))
			return
		}
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r.WithContext(withSubstratePerson(r.Context(), p, st.cfg.IsAdmin(p))))
	})
}

// substrateVisible reports whether caller may see reg.
func substrateVisible(c substrateCaller, reg registry.Registration) bool {
	return c.admin || (reg.Person.Subject != "" && reg.Person.ID() == ownerOf(c.person).ID())
}

func substrateActorView(reg registry.Registration) map[string]any {
	return map[string]any{
		"atespace": reg.Atespace, "name": reg.Name, "uid": reg.UID, "registration_key": reg.Key,
		"profile": reg.Profile, "connector": reg.Connector, "template": reg.Template,
		"batch_id": reg.BatchID, "unattended": reg.Unattended, "created_at": reg.CreatedAt,
		"owner": reg.Person.Principal, "deleted": reg.Deleted,
	}
}

func (a *APIServer) substrateCreateActor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		if st.cfg.Actions == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "actions_unavailable")
			return
		}
		var req SubstrateCreate
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Template) == "" || strings.TrimSpace(req.Profile) == "" {
			writeSubstrateJSONError(w, http.StatusBadRequest, "profile_and_template_required")
			return
		}
		if len(req.Task) > 64<<10 {
			writeSubstrateJSONError(w, http.StatusRequestEntityTooLarge, "task_too_long")
			return
		}
		resolve := st.cfg.substrateProfiles()
		profile, atespace, err := resolve(c.person, req.Profile)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusForbidden, "profile_not_allowed")
			return
		}
		if req.Atespace != "" && req.Atespace != atespace {
			writeSubstrateJSONError(w, http.StatusForbidden, "atespace_not_allowed")
			return
		}
		req.Profile, req.Atespace, req.Owner = profile, atespace, ownerOf(c.person)
		created, err := st.cfg.Actions.Create(r.Context(), req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] create actor failed: %v\n", err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "create_failed")
			return
		}
		reg := registry.Registration{
			Atespace: created.Atespace, Name: created.Name, UID: created.UID, Person: req.Owner,
			Profile: profile, Template: created.Template, TemplateDigest: created.TemplateDigest,
			KitVersion: created.KitVersion, Connector: created.Connector, HarnessVersion: created.HarnessVersion,
			HookContract: created.HookContract, BatchID: req.BatchID, Unattended: req.Unattended,
			Secrets: append([]string(nil), req.Secrets...),
		}
		if req.Task != "" {
			sum := sha256.Sum256([]byte(req.Task))
			reg.TaskDigest = hex.EncodeToString(sum[:])
		}
		// The registration is written before the actor runs and before the
		// launcher hears back, so its first call is attributed.
		if err := st.cfg.Registrations.Put(r.Context(), reg); err != nil {
			_ = st.cfg.Actions.Delete(context.WithoutCancel(r.Context()), created.Atespace, created.Name)
			fmt.Fprintf(os.Stderr, "[substrate] registration failed, actor removed: %v\n", err)
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registration_failed")
			return
		}
		if err := st.cfg.Actions.Resume(r.Context(), created.Atespace, created.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] resume failed: %v\n", err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "resume_failed")
			return
		}
		out := substrateActorView(reg)
		if st.cfg.Sessions != nil && !req.Unattended {
			tok, exp, err := st.cfg.Sessions.Issue(c.person.Subject, identity.SessionActor{Atespace: reg.Atespace, Name: reg.Name, UID: reg.UID}, 0)
			if err == nil {
				out["session_token"], out["session_expires"] = tok, exp
			}
		}
		writeSubstrateJSON(w, http.StatusCreated, out)
	}
}

// substrateProfiles is the configured resolver, or a refusal of every
// create when none is set.
func (c SubstrateConfig) substrateProfiles() SubstrateProfileResolver {
	if c.Profiles != nil {
		return c.Profiles
	}
	return func(identity.Person, string) (string, string, error) {
		return "", "", errors.New("no launcher profiles are configured")
	}
}

func (a *APIServer) substrateListActors(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		f := registry.Filter{OwnerID: ownerOf(c.person).ID(), BatchID: r.URL.Query().Get("batch")}
		if c.admin && r.URL.Query().Get("all") == "1" {
			f.OwnerID = ""
		}
		regs, err := st.cfg.Registrations.List(r.Context(), f)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		out := make([]map[string]any, 0, len(regs))
		for _, reg := range regs {
			out = append(out, substrateActorView(reg))
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"actors": out})
	}
}

// substrateFind finds the live registration of atespace/name the caller
// may see. A miss and someone else's actor answer alike (no probing).
func (a *APIServer) substrateFind(st *substrateState, r *http.Request, atespace, name string) (registry.Registration, int, string) {
	c, _ := substrateCallerFrom(r.Context())
	if st.cfg.Lookup == nil {
		return registry.Registration{}, http.StatusServiceUnavailable, "lookup_unavailable"
	}
	live, err := st.cfg.Lookup.LookupActor(r.Context(), atespace, name)
	if errors.Is(err, identity.ErrActorNotFound) {
		return registry.Registration{}, http.StatusNotFound, "actor_not_found"
	}
	if err != nil {
		return registry.Registration{}, http.StatusServiceUnavailable, "control_api_unavailable"
	}
	reg, ok, err := st.cfg.Registrations.Get(r.Context(), atespace, live.UID)
	if err != nil {
		return registry.Registration{}, http.StatusServiceUnavailable, "registrations_unavailable"
	}
	if !ok || reg.Deleted || !substrateVisible(c, reg) {
		return registry.Registration{}, http.StatusNotFound, "actor_not_found"
	}
	return reg, http.StatusOK, ""
}

func (a *APIServer) substrateGetActor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		writeSubstrateJSON(w, http.StatusOK, substrateActorView(reg))
	}
}

func (a *APIServer) substrateDeleteActor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Actions == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "actions_unavailable")
			return
		}
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		if err := st.cfg.Actions.Delete(r.Context(), reg.Atespace, reg.Name); err != nil {
			writeSubstrateJSONError(w, http.StatusBadGateway, "delete_failed")
			return
		}
		reg.Deleted = true
		if err := st.cfg.Registrations.Put(r.Context(), reg); err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registration_failed")
			return
		}
		if inv, ok := st.cfg.Actors.(interface{ Invalidate(string, string) }); ok {
			inv.Invalidate(reg.Atespace, reg.Name)
		}
		writeSubstrateJSON(w, http.StatusOK, substrateActorView(reg))
	}
}

func (a *APIServer) substrateSessionCert(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		if st.cfg.Sessions == nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "sessions_unavailable")
			return
		}
		var in struct {
			Atespace   string `json:"atespace"`
			Name       string `json:"name"`
			TTLSeconds int    `json:"ttl_seconds,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Atespace == "" || in.Name == "" {
			writeSubstrateJSONError(w, http.StatusBadRequest, "atespace_and_name_required")
			return
		}
		reg, status, reason := a.substrateFind(st, r, in.Atespace, in.Name)
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		ttl := time.Duration(in.TTLSeconds) * time.Second
		if ttl > substrateSessionMaxTTL {
			ttl = substrateSessionMaxTTL
		}
		tok, exp, err := st.cfg.Sessions.Issue(c.person.Subject, identity.SessionActor{Atespace: reg.Atespace, Name: reg.Name, UID: reg.UID}, ttl)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "session_refused")
			return
		}
		if reg.Person.ID() != ownerOf(c.person).ID() {
			// An administrator attaching to someone else's actor is
			// recorded as themselves (E2).
			fmt.Fprintf(os.Stderr, "[substrate] administrator session for another person's actor %s/%s\n", reg.Atespace, reg.Name)
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{
			"token": tok, "expires": exp, "kid": st.cfg.Sessions.KeyID(), "public_key_pem": string(st.cfg.Sessions.PublicKeyPEM()),
		})
	}
}

func (a *APIServer) substrateBatches(st *substrateState, r *http.Request, batchID string) (map[string][]map[string]any, error) {
	c, _ := substrateCallerFrom(r.Context())
	f := registry.Filter{OwnerID: ownerOf(c.person).ID(), BatchID: batchID, IncludeDeleted: true}
	if c.admin && r.URL.Query().Get("all") == "1" {
		f.OwnerID = ""
	}
	regs, err := st.cfg.Registrations.List(r.Context(), f)
	if err != nil {
		return nil, err
	}
	out := map[string][]map[string]any{}
	for _, reg := range regs {
		if reg.BatchID != "" {
			out[reg.BatchID] = append(out[reg.BatchID], substrateActorView(reg))
		}
	}
	return out, nil
}

func (a *APIServer) substrateListBatches(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := a.substrateBatches(st, r, "")
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		ids := make([]string, 0, len(b))
		for id := range b {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			out = append(out, map[string]any{"batch_id": id, "actors": len(b[id])})
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"batches": out})
	}
}

func (a *APIServer) substrateGetBatch(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		b, err := a.substrateBatches(st, r, id)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		if len(b[id]) == 0 {
			writeSubstrateJSONError(w, http.StatusNotFound, "batch_not_found")
			return
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"batch_id": id, "actors": b[id]})
	}
}

func (a *APIServer) substrateUsage(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Usage == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "usage_unavailable")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		owner := ownerOf(c.person).ID()
		if c.admin && r.URL.Query().Get("all") == "1" {
			owner = ""
		}
		u, err := st.cfg.Usage.Usage(r.Context(), owner, r.URL.Query().Get("batch"))
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "usage_unavailable")
			return
		}
		writeSubstrateJSON(w, http.StatusOK, u)
	}
}

// substrateCalloutAuthorized compares the callout's service token in
// constant time.
func substrateCalloutAuthorized(st *substrateState, r *http.Request) bool {
	if st.cfg.CalloutToken == nil {
		return false
	}
	want, err := st.cfg.CalloutToken()
	got := bearer(r)
	if err != nil || len(want) < 16 || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// readAllLimited reads at most n bytes.
func readAllLimited(r io.Reader, n int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	return b, err == nil && int64(len(b)) <= n
}
