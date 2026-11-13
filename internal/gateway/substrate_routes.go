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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
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
	substrateInfoPath      = "/api/v1/substrate/info"
	substrateAdminMaxBody  = 1 << 20
	substrateSessionMaxTTL = identity.MaxSessionLifetime
)

// SubstrateCreate is a launcher create request.
type SubstrateCreate struct {
	Profile   string `json:"profile"`
	Template  string `json:"template"`
	Connector string `json:"connector,omitempty"`
	// Name is the actor name; empty lets the gateway choose one.
	Name    string `json:"name,omitempty"`
	Task    string `json:"task,omitempty"`
	BatchID string `json:"batch_id,omitempty"`
	// Unattended is a --task or --batch run (fail closed, D8).
	Unattended bool     `json:"unattended,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
	// Atespace is filled by the gateway from the profile; a request value
	// is refused unless it is one of the profile's launcher atespaces.
	Atespace string `json:"atespace,omitempty"`
	// Owner is filled by the gateway (the verified person).
	Owner registry.Person `json:"-"`
	// SandboxClass is filled by the gateway from the profile (never from
	// the request): the class the actor must run in (PLAN 7.3).
	SandboxClass string `json:"-"`
	// Kit is the template's attested kit as the create route read it, set
	// when the Actions reads kits (SubstrateTemplateKitReader). Non-nil
	// means the template was read already: Create uses it as is and reads
	// no second attestation. A zero kit is a template the attestor did not
	// positively attest (an open source create the route warned about).
	Kit *SubstrateTemplateKit `json:"-"`
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
// create for the verified caller, or refuses (SubstrateLauncherProfiles).
type SubstrateProfileResolver func(person identity.Person, requested, connector string, admin bool) (profile, atespace string, err error)

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
	mux.HandleFunc("POST /api/v1/substrate/actors/{atespace}/{name}/policy/reset", a.substratePolicyReset(st))
	mux.HandleFunc("POST /api/v1/substrate/session-cert", a.substrateSessionCert(st))
	mux.HandleFunc("/api/v1/substrate/actors/{atespace}/{name}/attach", a.substrateAttach(st))
	mux.HandleFunc("/api/v1/substrate/actors/{atespace}/{name}/attach/{rest...}", a.substrateAttach(st))
	mux.HandleFunc("GET /api/v1/substrate/batches", a.substrateListBatches(st))
	mux.HandleFunc("GET /api/v1/substrate/batches/{id}", a.substrateGetBatch(st))
	mux.HandleFunc("GET /api/v1/substrate/usage", a.substrateUsage(st))
	mux.HandleFunc("GET /api/v1/substrate/doctor", a.substrateDoctor(st))
	mux.HandleFunc("GET /api/v1/substrate/asks", a.substrateListAsks(st))
	mux.HandleFunc("POST /api/v1/substrate/asks/{id}", a.substrateDecideAsk(st))
	mux.HandleFunc("GET /api/v1/substrate/decisions", a.substrateDecisions(st))
	mux.HandleFunc("GET /api/v1/substrate/policy/explain", a.substratePolicyExplain(st))
	mux.HandleFunc("GET /api/v1/substrate/secrets", a.substrateListSecrets(st))
	mux.HandleFunc("PUT /api/v1/substrate/secrets/{name}", a.substrateSetSecret(st))
	mux.HandleFunc("DELETE /api/v1/substrate/secrets/{name}", a.substrateRemoveSecret(st))
	mux.HandleFunc("POST /api/v1/substrate/secrets/{name}/test", a.substrateTestSecret(st))
	mux.HandleFunc("POST /api/v1/substrate/bundle", a.substrateBundleApply(st))
	mux.HandleFunc("POST /api/v1/substrate/bundle/rollback", a.substrateBundleRollback(st))
	mux.HandleFunc("GET /api/v1/substrate/bundle/status", a.substrateBundleStatus(st))
	// The admin listener keeps the browser CSRF gate: people reach it from
	// the launcher and possibly from a browser session, so a state-changing
	// request must carry X-DefenseClaw-Client (the actor listener does not
	// apply it, GAP-0037).
	callout := a.apiCSRFProtect(a.substrateCalloutVerdict(st))
	calloutAsk := a.apiCSRFProtect(a.substrateCalloutAsk(st))
	info := a.substrateInfo(st)
	people := a.apiCSRFProtect(a.substrateAdminAuthenticate(st, mux))
	attach := substrateAttachCSRF(a.substrateAdminAuthenticate(st, mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !strings.HasPrefix(r.URL.Path, substrateAdminPrefix) || r.URL.RawPath != "" {
			writeSubstrateJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		if substrateAttachPath.MatchString(r.URL.Path) {
			// Attach and workspace traffic (GAP-0134): a WebSocket upgrade,
			// long-poll frames and a streaming tar upload. Person sign-in and
			// ownership are checked as for every admin route; the JSON body
			// gate and the 1 MiB cap do not fit it, so it has its own.
			r.Body = http.MaxBytesReader(w, r.Body, substrateAttachBodyCap(r, st.cfg.WorkspaceMaxBytes))
			attach.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, substrateAdminMaxBody)
		switch r.URL.Path {
		case substrateInfoPath:
			if r.Method != http.MethodGet {
				writeSubstrateJSONError(w, http.StatusMethodNotAllowed, "method")
				return
			}
			info(w, r)
			return
		case substrateCalloutPath:
			callout.ServeHTTP(w, r)
			return
		case substrateCalloutAskPath:
			calloutAsk.ServeHTTP(w, r)
			return
		}
		people.ServeHTTP(w, r)
	})
}

// writeSubstrateAttestationRefusal answers a managed create of a template
// that is not positively attested with a label (GAP-0181).
func writeSubstrateAttestationRefusal(w http.ResponseWriter, code, message, detail string, retryable bool) {
	body := map[string]any{"error": http.StatusText(http.StatusForbidden), "reason": code, "message": message}
	if detail != "" {
		body["detail"] = detail
	}
	if retryable {
		body["retryable"] = true
	}
	writeSubstrateJSON(w, http.StatusForbidden, body)
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
		// The profile may be empty: it comes from the caller's assignment
		// (GAP-0043); a request may only name that same one.
		if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Template) == "" {
			writeSubstrateJSONError(w, http.StatusBadRequest, "template_required")
			return
		}
		if len(req.Task) > 64<<10 {
			writeSubstrateJSONError(w, http.StatusRequestEntityTooLarge, "task_too_long")
			return
		}
		if req.BatchID != "" && !substrateBatchIDRE.MatchString(req.BatchID) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "batch_id_invalid")
			return
		}
		resolve := st.cfg.substrateProfiles()
		profile, atespace, err := resolve(c.person, req.Profile, req.Connector, c.admin)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusForbidden, "profile_not_allowed")
			return
		}
		if req.Atespace != "" && req.Atespace != atespace {
			writeSubstrateJSONError(w, http.StatusForbidden, "atespace_not_allowed")
			return
		}
		// One connector rule (GAP-0160): an omitted connector is the
		// template's own (its attested label); a named one must equal it;
		// a template that carries no label (or an Actions that cannot read
		// it) leaves the launcher's word, and no word is connector_required.
		tmplConnector, tmplKit, err := st.cfg.readTemplate(r.Context(), atespace, req.Template)
		if errors.Is(err, ErrSubstrateTemplateNotFound) {
			writeSubstrateJSONError(w, http.StatusNotFound, "template_not_found")
			return
		}
		var createWarnings []string
		if errors.Is(err, ErrSubstrateTemplateAttestation) {
			fmt.Fprintf(os.Stderr, "[substrate] template %s/%s: %v\n", atespace, req.Template, err)
			code, msg, detail, retryable := substrateAttestationRefusal(err)
			if st.cfg.Managed {
				// Fail closed (GAP-0181): the connector, and so the sign-in
				// check, comes from a positive attestation, never from the
				// launcher's word alone.
				writeSubstrateAttestationRefusal(w, code, msg, detail, retryable)
				return
			}
			createWarnings = append(createWarnings, msg+"; the connector you named decides the sign-in check")
			err = nil
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] template lookup failed: %v\n", err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "create_failed")
			return
		}
		if st.cfg.Managed && tmplConnector == "" {
			// Managed creates only from a positively attested, labelled
			// template (GAP-0181): an Actions that reads no label, or a
			// reader that answers none, is refused too.
			writeSubstrateAttestationRefusal(w, "template_connector_unlabeled", "the template attestation names no connector", "", false)
			return
		}
		named := strings.TrimSpace(req.Connector)
		switch {
		case named != "" && tmplConnector != "" && !sameSubstrateConnector(named, tmplConnector):
			writeSubstrateJSONError(w, http.StatusBadRequest, "connector_mismatch")
			return
		case named == "" && tmplConnector == "":
			writeSubstrateJSONError(w, http.StatusBadRequest, "connector_required")
			return
		case named == "":
			// The profile was picked without a connector; pick it again for the
			// template's, because a profile may be bound to one.
			req.Connector = tmplConnector
			if profile, atespace, err = resolve(c.person, req.Profile, req.Connector, c.admin); err != nil {
				writeSubstrateJSONError(w, http.StatusForbidden, "profile_not_allowed")
				return
			}
		}
		req.Profile, req.Atespace, req.Owner, req.Kit = profile, atespace, ownerOf(c.person), tmplKit
		if st.cfg.SandboxClass != nil {
			req.SandboxClass = st.cfg.SandboxClass(profile)
		}
		// E9: a managed deployment refuses an agent that signs in to a
		// vendor account, before any actor exists. The connector is now the
		// template's whenever the template has one; it is checked again
		// below on what the created actor runs.
		if d := st.cfg.signinDecision(req.Connector, req.Secrets); !d.Allowed {
			writeSubstrateSigninRefusal(w, d)
			return
		}
		created, err := st.cfg.Actions.Create(r.Context(), req)
		switch {
		case errors.Is(err, ErrSubstrateTemplateNotFound):
			writeSubstrateJSONError(w, http.StatusNotFound, "template_not_found")
			return
		case errors.Is(err, ErrSubstrateActorExists):
			writeSubstrateJSONError(w, http.StatusConflict, "actor_exists")
			return
		case err != nil:
			fmt.Fprintf(os.Stderr, "[substrate] create actor failed: %v\n", err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "create_failed")
			return
		}
		signinDecision := st.cfg.signinDecision(created.Connector, req.Secrets)
		if !signinDecision.Allowed {
			_ = st.cfg.Actions.Delete(context.WithoutCancel(r.Context()), created.Atespace, created.Name)
			writeSubstrateSigninRefusal(w, signinDecision)
			return
		}
		if signinDecision.Warn {
			fmt.Fprintf(os.Stderr, "[substrate] warning: %s/%s: %s\n", created.Atespace, created.Name, signinDecision.Message)
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
		if req.Task != "" && st.cfg.Chains != nil {
			// The task text is the run's verified intent for the tool judge
			// (registered before the actor runs). Without it the judge sees
			// only the agent's own prompts; the create goes on.
			if err := st.cfg.Chains.PutTask(r.Context(), chainstate.Actor{Atespace: reg.Atespace, UID: reg.UID}, req.Task); err != nil {
				fmt.Fprintf(os.Stderr, "[substrate] warning: task intent not registered for %s/%s: %v\n", reg.Atespace, reg.Name, err)
			}
		}
		if err := st.cfg.Actions.Resume(r.Context(), created.Atespace, created.Name); err != nil {
			if errors.Is(err, ErrSubstrateActorRefused) {
				// No policy, no actor: delete it and leave a tombstone.
				ctx := context.WithoutCancel(r.Context())
				_ = st.cfg.Actions.Delete(ctx, created.Atespace, created.Name)
				reg.Deleted = true
				_ = st.cfg.Registrations.Put(ctx, reg)
				fmt.Fprintf(os.Stderr, "[substrate] actor %s/%s uid %s refused and removed: %v\n", created.Atespace, created.Name, created.UID, err)
				writeSubstrateActorRefusal(w, created.Atespace, created.Name, created.UID, err)
				return
			}
			// GAP-0167: an actor that never ran holds nothing the person
			// wants and would sit SUSPENDED in their list: remove it.
			ctx := context.WithoutCancel(r.Context())
			_ = st.cfg.Actions.Delete(ctx, created.Atespace, created.Name)
			reg.Deleted = true
			_ = st.cfg.Registrations.Put(ctx, reg)
			fmt.Fprintf(os.Stderr, "[substrate] resume failed, actor %s/%s removed: %v\n", created.Atespace, created.Name, err)
			if errors.Is(err, ErrSubstrateNoWorker) {
				// No worker of the pool has room: the person can free one.
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "no_free_worker")
				return
			}
			writeSubstrateJSONError(w, http.StatusBadGateway, "resume_failed")
			return
		}
		out := substrateActorView(reg)
		if signinDecision.Warn {
			createWarnings = append(createWarnings, signinDecision.Message)
		}
		if len(createWarnings) > 0 {
			out["warnings"] = createWarnings
		}
		if st.cfg.Sessions != nil && !req.Unattended {
			tok, exp, err := st.cfg.Sessions.Issue(c.person.ID(), substrateSessionActor(reg), 0)
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
	return func(identity.Person, string, string, bool) (string, string, error) {
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
			v := substrateActorView(reg)
			// GAP-0167: the person sees which agents hold a worker.
			if st.cfg.Lookup != nil && !reg.Deleted {
				if live, err := st.cfg.Lookup.LookupActor(r.Context(), reg.Atespace, reg.Name); err == nil && live.UID == reg.UID {
					v["state"] = strings.ToLower(string(live.State))
				}
			}
			out = append(out, v)
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
		// The token names the person as issuer#subject: two issuers may
		// use the same subject (GAP-0061).
		tok, exp, err := st.cfg.Sessions.Issue(c.person.ID(), substrateSessionActor(reg), ttl)
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

// substrateBatchIDRE is a batch ID the launcher may send (GAP-0106).
var substrateBatchIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// substrateBatchKey is one owner's batch: two people may pick the same
// batch ID, and an administrator's all=1 view keeps them apart (GAP-0106).
type substrateBatchKey struct{ owner, id string }

func (a *APIServer) substrateBatches(st *substrateState, r *http.Request, batchID string) (map[substrateBatchKey][]map[string]any, error) {
	c, _ := substrateCallerFrom(r.Context())
	f := registry.Filter{OwnerID: ownerOf(c.person).ID(), BatchID: batchID, IncludeDeleted: true}
	if c.admin && r.URL.Query().Get("all") == "1" {
		f.OwnerID = r.URL.Query().Get("owner") // "" is every owner
	}
	regs, err := st.cfg.Registrations.List(r.Context(), f)
	if err != nil {
		return nil, err
	}
	out := map[substrateBatchKey][]map[string]any{}
	for _, reg := range regs {
		if reg.BatchID != "" {
			k := substrateBatchKey{owner: reg.Person.ID(), id: reg.BatchID}
			out[k] = append(out[k], substrateActorView(reg))
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
		keys := make([]substrateBatchKey, 0, len(b))
		for k := range b {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].id != keys[j].id {
				return keys[i].id < keys[j].id
			}
			return keys[i].owner < keys[j].owner
		})
		out := make([]map[string]any, 0, len(keys))
		for _, k := range keys {
			row := map[string]any{"batch_id": k.id, "actors": len(b[k])}
			if owner, _ := b[k][0]["owner"].(string); owner != "" {
				row["owner"] = owner
			}
			out = append(out, row)
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"batches": out})
	}
}

func (a *APIServer) substrateGetBatch(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !substrateBatchIDRE.MatchString(id) {
			writeSubstrateJSONError(w, http.StatusNotFound, "batch_not_found")
			return
		}
		b, err := a.substrateBatches(st, r, id)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		switch len(b) {
		case 0:
			writeSubstrateJSONError(w, http.StatusNotFound, "batch_not_found")
		case 1:
			for _, actors := range b {
				writeSubstrateJSON(w, http.StatusOK, map[string]any{"batch_id": id, "actors": actors})
			}
		default:
			// Several owners use this ID (all=1): name one with owner=.
			writeSubstrateJSONError(w, http.StatusConflict, "batch_id_ambiguous")
		}
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
