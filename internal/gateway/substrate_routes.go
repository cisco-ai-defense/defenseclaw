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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	// AcknowledgeSignin is the person's yes to the open-source sign-in
	// warning (GAP-0482). A create whose agent signs in to a vendor account
	// (or keeps the hook in a folder it owns) and does not carry it is
	// answered 428 signin_ack_required with the warning, before any actor
	// exists; the acknowledged create is audited.
	AcknowledgeSignin bool `json:"acknowledge_signin,omitempty"`
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
	RelayStreams   string
	// SandboxClass is the class the actor runs in (gvisor or microvm).
	SandboxClass string
}

// SubstrateActorActions creates, resumes and deletes actors in launcher
// atespaces (the controller lane's ateapi client). Create leaves the actor
// suspended, so its registration is written before it can make a call.
type SubstrateActorActions interface {
	Create(ctx context.Context, req SubstrateCreate) (SubstrateCreated, error)
	Resume(ctx context.Context, atespace, name string) error
	Delete(ctx context.Context, atespace, name string) error
}

// SubstrateSnapshotCounter is optional on SubstrateActorActions: how many
// snapshots the cluster holds for an actor. Status shows the count and a
// delete names how many it removed (GAP-0474).
type SubstrateSnapshotCounter interface {
	Snapshots(ctx context.Context, atespace, name string) (int, error)
}

// substrateSnapshots is the actor's snapshot count, ok false when the
// actions cannot count them or the cluster did not answer.
func (st *substrateState) substrateSnapshots(ctx context.Context, reg registry.Registration) (int, bool) {
	sc, ok := st.cfg.Actions.(SubstrateSnapshotCounter)
	if !ok {
		return 0, false
	}
	n, err := sc.Snapshots(ctx, reg.Atespace, reg.Name)
	return n, err == nil
}

// SubstrateUsage answers a usage query: one owner's rows, or every owner's
// for an administrator (SubstrateUsageQuery.All). The owner is set by the
// handler from the verified person, never by the request.
type SubstrateUsage interface {
	Usage(ctx context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error)
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
	return registry.Person{Kind: p.Kind, Issuer: p.Issuer, Subject: p.Subject, Principal: p.Principal, EmailUnverified: p.EmailUnverified, Groups: p.Groups}
}

func (a *APIServer) newSubstrateAdminHandler(st *substrateState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/substrate/actors", a.substrateCreateActor(st))
	mux.HandleFunc("GET /api/v1/substrate/actors", a.substrateListActors(st))
	mux.HandleFunc("GET /api/v1/substrate/actors/{atespace}/{name}", a.substrateGetActor(st))
	mux.HandleFunc("DELETE /api/v1/substrate/actors/{atespace}/{name}", a.substrateDeleteActor(st))
	mux.HandleFunc("POST /api/v1/substrate/actors/{atespace}/{name}/policy/reset", a.substratePolicyReset(st))
	mux.HandleFunc("POST /api/v1/substrate/actors/{atespace}/{name}/recover", a.substrateRecoverActor(st))
	mux.HandleFunc("POST /api/v1/substrate/actors/{atespace}/{name}/snapshot", a.substrateSnapshotActor(st))
	mux.HandleFunc("POST /api/v1/substrate/actors/{atespace}/{name}/push", a.substrateGitPush(st))
	mux.HandleFunc("POST /api/v1/substrate/session-cert", a.substrateSessionCert(st))
	mux.HandleFunc("/api/v1/substrate/actors/{atespace}/{name}/attach", a.substrateAttach(st))
	mux.HandleFunc("/api/v1/substrate/actors/{atespace}/{name}/attach/{rest...}", a.substrateAttach(st))
	mux.HandleFunc("GET /api/v1/substrate/batches", a.substrateListBatches(st))
	mux.HandleFunc("GET /api/v1/substrate/batches/{id}", a.substrateGetBatch(st))
	mux.HandleFunc("GET /api/v1/substrate/usage", a.substrateUsage(st))
	mux.HandleFunc("GET /api/v1/substrate/doctor", a.substrateDoctor(st))
	mux.HandleFunc("GET /api/v1/substrate/launcher", func(w http.ResponseWriter, _ *http.Request) {
		writeSubstrateJSON(w, http.StatusOK, map[string]any{
			"workspace_max_bytes": substrateWorkspaceMax(st.cfg.WorkspaceMaxBytes),
			"key_replay":          substrateKeyReplay(st.cfg.KeyReplay),
			"upload_scan":         substrateUploadScan(st.cfg.UploadScan),
			"files":               map[string]bool{"push": substrateSwitch(st.cfg.FilesPush), "sync": substrateSwitch(st.cfg.FilesSync)},
			"git":                 substrateLauncherGit(st.cfg.Git),
		})
	})
	mux.HandleFunc("POST /api/v1/substrate/signin/revoke", a.substrateSigninRevoke(st))
	mux.HandleFunc("/api/v1/substrate/admin/revocations", a.substrateAdminRevocations(st))
	mux.HandleFunc("GET /api/v1/substrate/asks", a.substrateListAsks(st))
	mux.HandleFunc("POST /api/v1/substrate/asks/{id}", a.substrateDecideAsk(st))
	mux.HandleFunc("GET /api/v1/substrate/approvals", a.substrateListApprovals(st))
	mux.HandleFunc("DELETE /api/v1/substrate/approvals/{atespace}/{name}/{host}", a.substrateRevokeApproval(st))
	mux.HandleFunc("GET /api/v1/substrate/decisions", a.substrateDecisions(st))
	mux.HandleFunc("GET /api/v1/substrate/policy/explain", a.substratePolicyExplain(st))
	mux.HandleFunc("GET /api/v1/substrate/secrets", a.substrateListSecrets(st))
	mux.HandleFunc("POST /api/v1/substrate/secrets", a.substrateAddSecret(st))
	mux.HandleFunc("GET /api/v1/substrate/secret-templates", a.substrateSecretTemplates(st))
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
			r.Body = http.MaxBytesReader(w, r.Body, substrateAttachBodyCap(r, substrateWorkspaceMax(st.cfg.WorkspaceMaxBytes)))
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

// writeSubstrateProfileRefusal answers a create whose profile cannot be
// used: profile_no_atespace (with the profile in detail) when the caller's
// profile has nowhere to run (GAP-0541), else profile_not_allowed.
func writeSubstrateProfileRefusal(w http.ResponseWriter, err error) {
	var none *ErrSubstrateProfileNoAtespace
	if errors.As(err, &none) {
		writeSubstrateJSON(w, http.StatusForbidden, map[string]any{"error": http.StatusText(http.StatusForbidden),
			"reason": "profile_no_atespace", "detail": none.Profile})
		return
	}
	writeSubstrateJSONError(w, http.StatusForbidden, "profile_not_allowed")
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
			st.authRefused(r, substrateListenerAdmin, identity.ReasonMissing)
			writeSubstrateJSONError(w, http.StatusUnauthorized, string(identity.ReasonMissing))
			return
		}
		p, err := st.cfg.People.Verify(r.Context(), tok)
		if err != nil {
			st.authRefused(r, substrateListenerAdmin, identity.ReasonOf(err))
			status := http.StatusUnauthorized
			reason := string(identity.ReasonOf(err))
			if identity.Unavailable(err) {
				status = http.StatusServiceUnavailable
				// The gateway could not verify any sign-in: name the cause
				// class of its last sign-in server check, never its detail
				// (GAP-0262).
				if cause := st.signIn.failing(); cause != "" {
					reason = cause
				}
			}
			writeSubstrateJSONError(w, status, reason)
			return
		}
		// An ended sign-in, or a list this replica cannot trust, is
		// refused before any route (B5.1).
		if status, reason := st.substrateRevocationRefusal(p.ID(), p.TokenKey, p.IssuedAt); status != 0 {
			st.authRefused(r, substrateListenerAdmin, identity.Reason(reason))
			writeSubstrateJSONError(w, status, reason)
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

// actorView is reg as the admin listener shows it. An unattended actor also
// says what its asks do (D12, GAP-0388): unattended_asks deny or queue from
// its profile, and with queue how long an ask waits for a person. An actor
// in policy_conflict carries the controller's mark (GAP-0398).
// readViewBudgets reads the budget keys of regs before their views.
func (st *substrateState) readViewBudgets(ctx context.Context, regs ...registry.Registration) {
	if st.readBudgets != nil {
		st.readBudgets(ctx, regs)
	}
}

// substrateActorRow is one actor of a list answer: the JSON of actorView
// as a typed struct, fields in key order as a map encodes them, so a list
// of 2,100 agents builds and key-sorts no map per agent (GAP-1019).
// TestSubstrateActorRowMatchesView pins the two to the same bytes.
type substrateActorRow struct {
	Activity          *substrateActivityOut `json:"activity,omitempty"`
	AskTimeoutSeconds *int64                `json:"ask_timeout_seconds,omitempty"`
	Atespace          string                `json:"atespace"`
	Attribution       string                `json:"attribution"`
	BatchID           string                `json:"batch_id"`
	Budget            string                `json:"budget,omitempty"`
	Connector         string                `json:"connector"`
	CreatedAt         time.Time             `json:"created_at"`
	Deleted           bool                  `json:"deleted"`
	Foreign           bool                  `json:"foreign"`
	Name              string                `json:"name"`
	Owner             string                `json:"owner"`
	PolicyConflict    map[string]any        `json:"policy_conflict,omitempty"`
	Profile           string                `json:"profile"`
	RegistrationKey   string                `json:"registration_key"`
	State             string                `json:"state,omitempty"`
	Template          string                `json:"template"`
	UID               string                `json:"uid"`
	Unattended        bool                  `json:"unattended"`
	UnattendedAsks    string                `json:"unattended_asks,omitempty"`
}

// actorRow is reg as list, status and the other actor answers show it.
func (st *substrateState) actorRow(reg registry.Registration) substrateActorRow {
	row := substrateActorRow{
		Atespace: reg.Atespace, Name: reg.Name, UID: reg.UID, RegistrationKey: reg.Key,
		Profile: reg.Profile, Connector: reg.Connector, Template: reg.Template,
		BatchID: reg.BatchID, Unattended: reg.Unattended, CreatedAt: reg.CreatedAt,
		Owner: reg.Person.Principal, Deleted: reg.Deleted,
		Attribution: substrateAttribution(reg), Foreign: reg.Attributed,
		PolicyConflict: substratePolicyConflictView(reg),
	}
	if reg.Unattended {
		var rule SubstrateUnattendedAsk // no rule: deny (D12)
		if st.cfg.UnattendedAsk != nil {
			rule = st.cfg.UnattendedAsk(reg.Profile)
		}
		row.UnattendedAsks = "deny"
		if rule.Queue {
			secs := int64(rule.Timeout / time.Second)
			row.UnattendedAsks, row.AskTimeoutSeconds = "queue", &secs
		}
	}
	if st.budget != nil && !reg.Deleted {
		row.Budget = st.budget(reg)
	}
	return row
}

// actorView is actorRow as a map, for the answers that add keys to it.
func (st *substrateState) actorView(reg registry.Registration) map[string]any {
	row := st.actorRow(reg)
	v := map[string]any{
		"atespace": row.Atespace, "name": row.Name, "uid": row.UID, "registration_key": row.RegistrationKey,
		"profile": row.Profile, "connector": row.Connector, "template": row.Template,
		"batch_id": row.BatchID, "unattended": row.Unattended, "created_at": row.CreatedAt,
		"owner": row.Owner, "deleted": row.Deleted,
		"attribution": row.Attribution, "foreign": row.Foreign,
	}
	if row.UnattendedAsks != "" {
		v["unattended_asks"] = row.UnattendedAsks
	}
	if row.AskTimeoutSeconds != nil {
		v["ask_timeout_seconds"] = *row.AskTimeoutSeconds
	}
	if row.PolicyConflict != nil {
		v["policy_conflict"] = row.PolicyConflict
	}
	if row.Budget != "" {
		v["budget"] = row.Budget
	}
	return v
}

// substratePolicyConflictView is the controller's policy_conflict mark as
// list, status, policy explain and doctor show it (GAP-0398), nil when the
// actor is not in conflict.
func substratePolicyConflictView(reg registry.Registration) map[string]any {
	if reg.PolicyConflict == nil {
		return nil
	}
	return map[string]any{
		"since": reg.PolicyConflict.Since, "reverts": reg.PolicyConflict.Reverts,
		"fix": "defenseclaw substrate policy reset " + reg.Atespace + "/" + reg.Name,
	}
}

// substrateAttribution is whom an actor is attributed to (GAP-0419): the
// person or CI workload the launcher verified at create, or, for an actor
// made outside DefenseClaw, only its atespace (D3).
func substrateAttribution(reg registry.Registration) string {
	switch {
	case reg.Attributed || reg.Person.Subject == "":
		return "atespace"
	case reg.Person.Kind == identity.PersonWorkload:
		return "workload"
	}
	return "person"
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
			writeSubstrateProfileRefusal(w, err)
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
				writeSubstrateProfileRefusal(w, err)
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
		preDecision := st.cfg.signinDecision(req.Connector, req.Secrets)
		if !preDecision.Allowed {
			writeSubstrateSigninRefusal(w, preDecision)
			return
		}
		if preDecision.Warn && !req.AcknowledgeSignin {
			// GAP-0482: open source asks first. The warning goes back
			// before anything is created or uploaded; the launcher asks the
			// person and sends the create again with their yes.
			writeSubstrateSigninAckRequired(w, preDecision)
			return
		}
		createStart := time.Now()
		created, err := st.cfg.Actions.Create(r.Context(), req)
		var classErr *SubstrateClassUnavailable
		switch {
		case errors.Is(err, ErrSubstrateTemplateNotFound):
			writeSubstrateJSONError(w, http.StatusNotFound, "template_not_found")
			return
		case errors.Is(err, ErrSubstrateActorExists):
			writeSubstrateJSONError(w, http.StatusConflict, "actor_exists")
			return
		case errors.As(err, &classErr):
			// GAP-0386: say which class is missing, before any actor exists.
			writeSubstrateJSON(w, http.StatusForbidden, map[string]any{"error": http.StatusText(http.StatusForbidden),
				"reason": "sandbox_class_unavailable", "message": classErr.Error()})
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
		if signinDecision.Warn && !req.AcknowledgeSignin {
			// The actor runs another connector than the one checked above
			// (a template with no label): it never ran, so remove it and
			// ask as above.
			_ = st.cfg.Actions.Delete(context.WithoutCancel(r.Context()), created.Atespace, created.Name)
			writeSubstrateSigninAckRequired(w, signinDecision)
			return
		}
		if signinDecision.Warn {
			fmt.Fprintf(os.Stderr, "[substrate] warning: %s/%s: %s\n", created.Atespace, created.Name, signinDecision.Message)
		}
		reg := registry.Registration{
			Atespace: created.Atespace, Name: created.Name, UID: created.UID, Person: req.Owner,
			Profile: profile, Template: created.Template, TemplateDigest: created.TemplateDigest,
			KitVersion: created.KitVersion, RelayStreams: created.RelayStreams, Connector: created.Connector, HarnessVersion: created.HarnessVersion,
			HookContract: created.HookContract, BatchID: req.BatchID, Unattended: req.Unattended,
			SandboxClass: created.SandboxClass,
			Secrets:      append([]string(nil), req.Secrets...),
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
			if errors.Is(err, ErrSubstrateResumeBusy) {
				// GAP-0468: busy, not broken; the person can retry.
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "resume_busy")
				return
			}
			writeSubstrateJSONError(w, http.StatusBadGateway, "resume_failed")
			return
		}
		a.recordSubstratePolicyLag(time.Since(createStart))
		out := st.actorView(reg)
		if signinDecision.Warn {
			createWarnings = append(createWarnings, signinDecision.Message)
			st.auditSigninAcknowledged(r.Context(), c, reg, signinDecision)
		}
		if len(createWarnings) > 0 {
			out["warnings"] = createWarnings
		}
		if st.cfg.Sessions != nil && !req.Unattended {
			// The token ends with the caller's sign-in, at the latest
			// (GAP-0588); with no time left the answer carries none and
			// the launcher attaches through the attach route.
			tok, exp, err := st.cfg.Sessions.IssueUntil(identity.SignInOf(c.person), substrateSessionActor(reg), 0, c.person.SessionBound())
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

// substrateRegistryReadWindow is how long list and status wait for the
// leader's registry. A leader change takes about 5 s to answer again, so the
// read retries inside this window; after it the call fails at once with
// registrations_unavailable and the plain "try again in a minute" message,
// instead of holding the person for the CLI's whole 30 s timeout
// (GAP-1089). A var so a test can shorten it.
var substrateRegistryReadWindow = 8 * time.Second

func (a *APIServer) substrateListActors(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		f := registry.Filter{OwnerID: ownerOf(c.person).ID(), BatchID: r.URL.Query().Get("batch")}
		everyone := c.admin && r.URL.Query().Get("all") == "1"
		if everyone {
			f.OwnerID = ""
		}
		readCtx, cancel := context.WithTimeout(r.Context(), substrateRegistryReadWindow)
		regs, err := st.cfg.Registrations.List(readCtx, f)
		cancel()
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		// GAP-0167: the person sees which agents hold a worker.
		states := substrateLiveStates(r.Context(), st.cfg.Lookup, regs)
		st.readViewBudgets(r.Context(), regs...)
		feed := st.activityFor(r.Context(), f.OwnerID, everyone, false)
		// Typed rows and one allocation for the activity (GAP-1019).
		var acts []substrateActivityOut
		if feed != nil {
			acts = make([]substrateActivityOut, len(regs))
		}
		out := make([]substrateActorRow, len(regs))
		for i, reg := range regs {
			out[i] = st.actorRow(reg)
			out[i].State = states[i]
			if feed != nil && !reg.Deleted {
				feed.fill(&acts[i], reg.UID, states[i])
				out[i].Activity = &acts[i]
			}
		}
		if f.OwnerID == "" {
			a.substrateAuditAdminRead(st, r, "actors", len(out), "")
		}
		resp := map[string]any{"actors": out}
		if everyone {
			// The answer is every person's agents: a person's all=1 is
			// narrowed to their own, and verify and status --cluster count
			// policy_conflict only over the cluster's (GAP-0398).
			resp["all"] = true
		}
		// GAP-0542: a workload caller learns which workloads entry its
		// verified subject matched ("" for none), so login --workload can
		// warn about an entry that never matches.
		if c.person.Kind == identity.PersonWorkload && st.cfg.WorkloadEntry != nil {
			entry, profile := st.cfg.WorkloadEntry(c.person.Subject)
			resp["workload"] = map[string]any{"subject": c.person.Subject, "entry": entry, "profile": profile}
		}
		writeSubstrateJSON(w, http.StatusOK, resp)
	}
}

// Live states for a list (GAP-0427). One control API call per agent made a
// person with 2,100 agents wait longer than the launcher does (30 s), so a
// lookup that can list reads each atespace in a few paged calls, and any
// other lookup runs substrateListLookups at a time. The states are left out
// past substrateListStateBudget: the list itself still answers.
const (
	substrateListLookups     = 16
	substrateListStateBudget = 10 * time.Second
)

// substrateLiveStates returns the lower-case live state of each live
// registration whose actor still has that UID, "" for the others.
func substrateLiveStates(ctx context.Context, lookup identity.ActorLookup, regs []registry.Registration) []string {
	states := make([]string, len(regs))
	if lookup == nil {
		return states
	}
	ctx, cancel := context.WithTimeout(ctx, substrateListStateBudget)
	defer cancel()
	set := func(i int, live identity.LiveActor) {
		if live.UID == regs[i].UID {
			states[i] = strings.ToLower(string(live.State))
		}
	}
	var single []int
	if lister, ok := lookup.(identity.ActorLister); ok {
		byAtespace := map[string][]int{}
		for i, reg := range regs {
			if !reg.Deleted {
				byAtespace[reg.Atespace] = append(byAtespace[reg.Atespace], i)
			}
		}
		for atespace, idx := range byAtespace {
			// One agent in an atespace is one call either way.
			if len(idx) == 1 {
				single = append(single, idx[0])
				continue
			}
			live, err := lister.ListLiveActors(ctx, atespace)
			if err != nil {
				single = append(single, idx...)
				continue
			}
			for _, i := range idx {
				if l, ok := live[regs[i].Name]; ok {
					set(i, l)
				}
			}
		}
	} else {
		for i, reg := range regs {
			if !reg.Deleted {
				single = append(single, i)
			}
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	next := make(chan int)
	for range min(substrateListLookups, len(single)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if live, err := lookup.LookupActor(ctx, regs[i].Atespace, regs[i].Name); err == nil {
					mu.Lock()
					set(i, live)
					mu.Unlock()
				}
			}
		}()
	}
	for _, i := range single {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	return states
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
	readCtx, cancel := context.WithTimeout(r.Context(), substrateRegistryReadWindow)
	reg, ok, err := st.cfg.Registrations.Get(readCtx, atespace, live.UID)
	cancel()
	if err != nil {
		return registry.Registration{}, http.StatusServiceUnavailable, "registrations_unavailable"
	}
	if !ok || reg.Deleted {
		return registry.Registration{}, http.StatusNotFound, "actor_not_found"
	}
	if !substrateVisible(c, reg) {
		// The same answer as a missing actor (no probing), audited as the
		// person who tried (GAP-0434).
		a.substrateAuditDenied(st, r, atespace+"/"+name, "not_owner")
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
		c, _ := substrateCallerFrom(r.Context())
		a.substrateAuditAdminTarget(st, r, reg, "actor", "INFO")
		st.readViewBudgets(r.Context(), reg)
		v := st.actorView(reg)
		// What a delete would remove with it (GAP-0474).
		if n, ok := st.substrateSnapshots(r.Context(), reg); ok {
			v["snapshots"] = n
		}
		// GAP-0410: status shows a crashed agent as crashed.
		if st.cfg.Lookup == nil {
			writeSubstrateJSON(w, http.StatusOK, v)
			return
		}
		if live, err := st.cfg.Lookup.LookupActor(r.Context(), reg.Atespace, reg.Name); err == nil && live.UID == reg.UID {
			v["state"] = strings.ToLower(string(live.State))
		}
		if feed := st.activityFor(r.Context(), ownerOf(c.person).ID(), c.admin, true); feed != nil {
			s, _ := v["state"].(string)
			v["activity"] = feed.view(reg, s)
		}
		writeSubstrateJSON(w, http.StatusOK, v)
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
		a.substrateAuditAdminTarget(st, r, reg, "delete", "HIGH")
		// The snapshots go with the actor: count them first, so the
		// launcher and the audit row say how many were removed (GAP-0474).
		snaps, counted := st.substrateSnapshots(r.Context(), reg)
		if err := st.cfg.Actions.Delete(r.Context(), reg.Atespace, reg.Name); err != nil {
			writeSubstrateJSONError(w, http.StatusBadGateway, "delete_failed")
			return
		}
		// The cluster has deleted the actor: record it now, so the row exists
		// even when the registration write below fails (GAP-0667).
		a.substrateAuditDeleted(st, r, reg, snaps, counted)
		reg.Deleted = true
		if err := st.cfg.Registrations.Put(r.Context(), reg); err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registration_failed")
			return
		}
		if inv, ok := st.cfg.Actors.(interface{ Invalidate(string, string) }); ok {
			inv.Invalidate(reg.Atespace, reg.Name)
		}
		v := st.actorView(reg)
		if counted {
			v["snapshots"] = snaps
		}
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}

// substrateAuditDeleted writes the person-level audit row of a delete: who
// deleted which actor (UID) and how many snapshots went with it, so the
// audit store, not only the controller's sandbox event, records the purge
// (GAP-0474). snapshots is -1 in the row when the cluster did not count
// them.
func (a *APIServer) substrateAuditDeleted(st *substrateState, r *http.Request, reg registry.Registration, snaps int, counted bool) {
	if st.audit == nil {
		return
	}
	c, _ := substrateCallerFrom(r.Context())
	who := c.person.Principal
	if who == "" {
		who = ownerOf(c.person).ID()
	}
	what := "the agent and its snapshots"
	if counted {
		what = fmt.Sprintf("the agent and %d snapshot(s)", snaps)
	} else {
		snaps = -1
	}
	summary := fmt.Sprintf("%s deleted %s/%s (uid %s): %s, with the checkpoints inside it", who, reg.Atespace, reg.Name, reg.UID, what)
	st.audit(context.WithoutCancel(r.Context()), "INFO", summary, map[string]any{
		"event": "actor_deleted", "atespace": reg.Atespace, "actor": reg.Atespace + "/" + reg.Name, "actor_uid": reg.UID,
		"principal": c.person.Principal, "person_id": ownerOf(c.person).ID(), "owner": reg.Person.Principal,
		"by_admin": c.admin && !substrateOwnedBy(c, reg), "snapshots": snaps, "batch_id": reg.BatchID,
	})
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
		reg, status, reason := a.substrateFindSession(st, r, in.Atespace, in.Name)
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		ttl := time.Duration(in.TTLSeconds) * time.Second
		if ttl > substrateSessionMaxTTL {
			ttl = substrateSessionMaxTTL
		}
		// The token names the person as issuer#subject: two issuers may
		// use the same subject (GAP-0061). It ends with the caller's
		// sign-in, at the latest (GAP-0588).
		tok, exp, err := st.cfg.Sessions.IssueUntil(identity.SignInOf(c.person), substrateSessionActor(reg), ttl, c.person.SessionBound())
		if errors.Is(err, identity.ErrSessionBound) {
			writeSubstrateRefusal(w, http.StatusUnauthorized, string(identity.ReasonExpired))
			return
		}
		if err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "session_refused")
			return
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
	if substrateAllView(r) {
		a.substrateAuditAdminRead(st, r, "batches", len(regs), "")
	}
	st.readViewBudgets(r.Context(), regs...)
	out := map[substrateBatchKey][]map[string]any{}
	for _, reg := range regs {
		if reg.BatchID != "" {
			k := substrateBatchKey{owner: reg.Person.ID(), id: reg.BatchID}
			out[k] = append(out[k], st.actorView(reg))
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
		if st.cfg.UsageDisabled {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "usage_disabled")
			return
		}
		if st.cfg.Usage == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "usage_unavailable")
			return
		}
		c, ok := substrateCallerFrom(r.Context())
		qs := r.URL.Query()
		all := ok && c.admin && qs.Get("all") == "1"
		owner := ""
		if !all {
			// "" means every owner: a caller with no person (or a route
			// without the person middleware) must not read it.
			if owner = substrateUsageOwner(ownerOf(c.person)); !ok || owner == "" {
				writeSubstrateJSONError(w, http.StatusForbidden, "usage_forbidden")
				return
			}
			if !c.admin && substrateUsersSeeNone(a.liveConfig()) {
				// routing.admin.visibility.users_see: none hides a person's own usage too.
				writeSubstrateJSONError(w, http.StatusForbidden, "usage_hidden")
				return
			}
		}
		since, err := parseSubstrateUsageSince(qs.Get("since"))
		limit, _ := strconv.Atoi(qs.Get("limit"))
		if err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "usage_bad_since")
			return
		}
		u, err := st.cfg.Usage.Usage(r.Context(), SubstrateUsageQuery{
			Owner: owner, All: all, By: qs.Get("by"), Since: since, Batch: qs.Get("batch"), Limit: limit})
		switch {
		case errors.Is(err, errSubstrateUsageBy):
			writeSubstrateJSONError(w, http.StatusBadRequest, "usage_bad_by")
			return
		case errors.Is(err, errSubstrateUsageAdminOnly):
			writeSubstrateJSONError(w, http.StatusForbidden, "usage_forbidden")
			return
		case err != nil:
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "usage_unavailable")
			return
		}
		if all {
			a.substrateAuditAdminRead(st, r, "usage", len(u.Rows), "")
		}
		writeSubstrateJSON(w, http.StatusOK, u)
	}
}

// substrateUsersSeeNone reports routing.admin.visibility.users_see: none.
func substrateUsersSeeNone(cfg *config.Config) bool {
	return cfg != nil && cfg.Routing.Admin != nil && cfg.Routing.Admin.Visibility.EffectiveUsersSee() == config.RoutingUsersSeeNone
}

var (
	errSubstrateUsageBy        = errors.New("usage: unknown rollup")
	errSubstrateUsageAdminOnly = errors.New("usage: administrators only")
)

// parseSubstrateUsageSince reads ?since= as a Go duration or Nd days ("" is
// the default of 24 h).
func parseSubstrateUsageSince(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil || n <= 0 {
			return 0, errors.New("bad since")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, errors.New("bad since")
	}
	return d, nil
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

// substrateSwitch reads a live admin switch; on when not wired.
func substrateSwitch(read func() bool) bool { return read == nil || read() }

// substrateLauncherGit is substrate.git as launchers use it: the effective
// rewrite map (the default when unset), the two switches and the
// cluster's push_branch (a profile can tighten it; the push route decides).
func substrateLauncherGit(read func() config.SubstrateGitConfig) map[string]any {
	var g config.SubstrateGitConfig
	if read != nil {
		g = read()
	}
	return map[string]any{"https_rewrite": g.EffectiveHTTPSRewrite(), "submodules": g.SubmodulesOn(), "lfs": g.LFSOn(),
		"push_branch_effective": g.EffectivePushBranch()}
}

// substrateUploadScan is substrate.launcher.upload_scan for launchers, its
// defaults filled in (replace, token, 8 MiB, 120s) when not wired or unset.
func substrateUploadScan(read func() config.SubstrateUploadScanConfig) map[string]any {
	var u config.SubstrateUploadScanConfig
	if read != nil {
		u = read()
	}
	return map[string]any{
		"max_file_bytes": u.EffectiveMaxFileBytes(), "time_budget": u.EffectiveTimeBudget().String(),
		"secret_action": u.EffectiveSecretAction(), "placeholder_form": u.EffectivePlaceholderForm(),
	}
}

// substrateKeyReplay is substrate.launcher.key_replay for launchers; ask when
// the listener has no live reader.
func substrateKeyReplay(read func() string) string {
	if read == nil {
		return config.SubstrateKeyReplayAsk
	}
	return read()
}
