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

package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// Actor is one Substrate actor as the admin listener shows it.
type Actor struct {
	Atespace        string `json:"atespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	RegistrationKey string `json:"registration_key,omitempty"`
	Profile         string `json:"profile"`
	Connector       string `json:"connector"`
	Template        string `json:"template"`
	BatchID         string `json:"batch_id,omitempty"`
	Unattended      bool   `json:"unattended,omitempty"`
	// UnattendedAsks is what an unattended actor's asks do, from its
	// profile: deny or queue (D12); AskTimeoutSeconds how long a queued
	// ask waits for a person.
	UnattendedAsks    string    `json:"unattended_asks,omitempty"`
	AskTimeoutSeconds int64     `json:"ask_timeout_seconds,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	Owner             string    `json:"owner,omitempty"`
	// Attribution is person, workload or atespace (an actor made outside
	// DefenseClaw, which Foreign marks too; GAP-0419).
	Attribution string `json:"attribution,omitempty"`
	Foreign     bool   `json:"foreign,omitempty"`
	Deleted     bool   `json:"deleted,omitempty"`
	State       string `json:"state,omitempty"`
	// SessionToken is present on create for an attended run.
	SessionToken   string    `json:"session_token,omitempty"`
	SessionExpires time.Time `json:"session_expires,omitempty"`
	// Warnings come with a create: what the cluster allowed but wants the
	// person to know (an open-source vendor sign-in, E9).
	Warnings []string `json:"warnings,omitempty"`
	// PolicyConflict is set while the actor is in policy_conflict: after
	// repeated foreign changes to its egress policy the controller keeps only
	// the DefenseClaw rule (deny-only) until an administrator resets it
	// (GAP-0398).
	PolicyConflict *PolicyConflict `json:"policy_conflict,omitempty"`
	// RecoveredFrom comes with a recover: "snapshot" (the actor's own last
	// snapshot) or "template" (it had none of its own, so the folder copied
	// into it is gone; GAP-0410). Empty from an older gateway.
	RecoveredFrom string `json:"recovered_from,omitempty"`
	// SnapshotGeneration comes with a snapshot: the generation stored.
	SnapshotGeneration int32 `json:"snapshot_generation,omitempty"`
	// ResumeError comes with a snapshot whose agent could not be started
	// again (state suspended): no_worker when the pool had no room.
	ResumeError string `json:"resume_error,omitempty"`
}

// PolicyConflict is an actor's policy_conflict as the cluster shows it.
type PolicyConflict struct {
	Since time.Time `json:"since"`
	// Reverts is how many foreign changes the controller reverted before
	// it marked the conflict.
	Reverts int `json:"reverts"`
	// Fix is the administrator's command that clears it.
	Fix string `json:"fix,omitempty"`
}

// shown returns a with every field a person reads made safe to print
// (safetext.Line): the cluster and the agent choose them, and they end up in
// tables, status lines, prompts and errors. The identifiers the launcher
// sends back (UID, registration key, session token) are left as they are.
func (a Actor) shown() Actor {
	for _, f := range []*string{&a.Atespace, &a.Name, &a.Profile, &a.Connector, &a.Template, &a.BatchID, &a.Owner, &a.Attribution, &a.State, &a.RecoveredFrom, &a.ResumeError} {
		*f = safetext.Line(*f)
	}
	if a.PolicyConflict != nil {
		pc := *a.PolicyConflict
		pc.Fix = safetext.Line(pc.Fix)
		a.PolicyConflict = &pc
	}
	if a.Warnings != nil {
		warnings := make([]string, len(a.Warnings))
		for i, w := range a.Warnings {
			warnings[i] = safetext.Line(w)
		}
		a.Warnings = warnings
	}
	return a
}

func (k Ask) shown() Ask {
	for _, f := range []*string{&k.ID, &k.Atespace, &k.Actor, &k.Tool, &k.Summary, &k.Reason, &k.Severity} {
		*f = safetext.Line(*f)
	}
	return k
}

func (s Secret) shown() Secret {
	for _, f := range []*string{&s.Name, &s.Scope, &s.Status} {
		*f = safetext.Line(*f)
	}
	if s.Hosts != nil {
		hosts := make([]string, len(s.Hosts))
		for i, h := range s.Hosts {
			hosts[i] = safetext.Line(h)
		}
		s.Hosts = hosts
	}
	return s
}

// CreateRequest is POST /actors.
type CreateRequest struct {
	Profile    string   `json:"profile"`
	Template   string   `json:"template"`
	Connector  string   `json:"connector,omitempty"`
	Name       string   `json:"name,omitempty"`
	Task       string   `json:"task,omitempty"`
	BatchID    string   `json:"batch_id,omitempty"`
	Unattended bool     `json:"unattended,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
	// AcknowledgeSignin is the person's yes to the cluster's sign-in
	// warning (GAP-0482). Without it an open-source cluster answers 428
	// signin_ack_required with the warning and creates nothing.
	AcknowledgeSignin bool `json:"acknowledge_signin,omitempty"`
}

// ListOptions filters ListActors.
type ListOptions struct {
	Batch string
	// All asks for every person's actors (administrators only).
	All bool
}

// SessionCert is the answer of POST /session-cert.
type SessionCert struct {
	Token        string    `json:"token"`
	Expires      time.Time `json:"expires"`
	KeyID        string    `json:"kid"`
	PublicKeyPEM string    `json:"public_key_pem"`
	// ClientCertificatePEM and ClientKeyPEM are the router mTLS material
	// when the cluster mints it for the launcher.
	ClientCertificatePEM string `json:"client_certificate_pem,omitempty"`
	ClientKeyPEM         string `json:"client_key_pem,omitempty"`
}

// Ask is a pending approval.
type Ask struct {
	ID       string    `json:"id"`
	Atespace string    `json:"atespace,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Created  time.Time `json:"created,omitempty"`
	// Expires is when a pending ask is denied if nobody answers.
	Expires time.Time `json:"expires,omitempty"`
	// Unattended marks an ask an unattended run (--task, --batch) queued
	// for a person because its profile sets unattended_asks: queue (D12).
	Unattended bool `json:"unattended,omitempty"`
}

// Create makes an actor (suspended, then resumed by the gateway).
func (c *Client) Create(ctx context.Context, r CreateRequest) (Actor, error) {
	var a Actor
	err := c.do(ctx, http.MethodPost, "actors", nil, r, &a)
	return a.shown(), err
}

// List returns the person's actors.
func (c *Client) List(ctx context.Context, o ListOptions) ([]Actor, error) {
	actors, _, _, err := c.list(ctx, o)
	return actors, err
}

// ErrNotAdministrator is ListEveryone's answer when the cluster listed only
// the caller's own agents: it gives every person's only to an administrator.
var ErrNotAdministrator = errors.New("the cluster lists only your own agents: you are not signed in as an administrator")

// ListEveryone returns every person's actors, or ErrNotAdministrator. The
// gateway narrows all=1 to the caller's own agents for a person and says
// "all": true only when it did not, so a count over the answer is the
// cluster's and not the caller's (GAP-0398).
func (c *Client) ListEveryone(ctx context.Context) ([]Actor, error) {
	actors, all, _, err := c.list(ctx, ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	if !all {
		return nil, ErrNotAdministrator
	}
	return actors, nil
}

// WorkloadMatch is the cluster's answer to a workload caller (GAP-0542):
// the subject it verified, the match.substrate.workloads entry that
// subject matched ("" for none) and that entry's profile.
type WorkloadMatch struct {
	Subject string `json:"subject"`
	Entry   string `json:"entry"`
	Profile string `json:"profile"`
}

// ListWithWorkload is List plus the workload answer, nil when the caller is
// a person or the cluster is older and sends none.
func (c *Client) ListWithWorkload(ctx context.Context, o ListOptions) ([]Actor, *WorkloadMatch, error) {
	actors, _, workload, err := c.list(ctx, o)
	return actors, workload, err
}

func (c *Client) list(ctx context.Context, o ListOptions) ([]Actor, bool, *WorkloadMatch, error) {
	q := url.Values{}
	if o.Batch != "" {
		q.Set("batch", o.Batch)
	}
	if o.All {
		q.Set("all", "1")
	}
	var out struct {
		Actors   []Actor        `json:"actors"`
		All      bool           `json:"all"`
		Workload *WorkloadMatch `json:"workload"`
	}
	if err := c.do(ctx, http.MethodGet, "actors", q, nil, &out); err != nil {
		return nil, false, nil, err
	}
	for i := range out.Actors {
		out.Actors[i] = out.Actors[i].shown()
	}
	return out.Actors, out.All, out.Workload, nil
}

// Get returns one actor.
func (c *Client) Get(ctx context.Context, atespace, name string) (Actor, error) {
	var a Actor
	err := c.do(ctx, http.MethodGet, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name), nil, nil, &a)
	return a.shown(), err
}

// Recover brings a crashed actor back to its last snapshot and starts it
// again (GAP-0410). The gateway answers 409 not_crashed for an actor that
// has not crashed.
func (c *Client) Recover(ctx context.Context, atespace, name string) (Actor, error) {
	var a Actor
	err := c.do(ctx, http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/recover", nil, map[string]any{}, &a)
	return a.shown(), err
}

// SnapshotTimeout bounds a Snapshot call: the upload of a large agent's
// memory takes longer than an ordinary request. The gateway finishes the
// snapshot and starts the agent again even when the launcher stops waiting.
const SnapshotTimeout = 6 * time.Minute

// Snapshot has the cluster store the running actor's state durably (it
// pauses for the seconds that takes), so a crash recovery returns to it
// rather than to the template's start (GAP-0410). The gateway answers 409
// not_running for an actor that is not running and 501 when it cannot.
func (c *Client) Snapshot(ctx context.Context, atespace, name string) (Actor, error) {
	var a Actor
	err := c.do(withLongCall(ctx, SnapshotTimeout), http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/snapshot", nil, map[string]any{}, &a)
	return a.shown(), err
}

// Delete removes an actor and its snapshots.
func (c *Client) Delete(ctx context.Context, atespace, name string) error {
	return c.do(ctx, http.MethodDelete, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name), nil, nil, nil)
}

// SessionCert mints a relay session token for an actor the person may
// attach to.
func (c *Client) SessionCert(ctx context.Context, atespace, name string, ttl time.Duration) (SessionCert, error) {
	in := map[string]any{"atespace": atespace, "name": name}
	if ttl > 0 {
		in["ttl_seconds"] = int(ttl.Seconds())
	}
	var s SessionCert
	return s, c.do(ctx, http.MethodPost, "session-cert", nil, in, &s)
}

// Batches lists the person's batches (batch id to actors).
func (c *Client) Batches(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "batches", nil, nil, &out)
}

// Batch returns one batch.
func (c *Client) Batch(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "batches/"+url.PathEscape(id), nil, nil, &out)
}

// Usage returns the person's usage (model calls, tokens, cost).
func (c *Client) Usage(ctx context.Context, batch string, all bool) (map[string]any, error) {
	q := url.Values{}
	if batch != "" {
		q.Set("batch", batch)
	}
	if all {
		q.Set("all", "1")
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "usage", q, nil, &out)
}

// Asks lists the person's pending approvals.
func (c *Client) Asks(ctx context.Context) ([]Ask, error) { return c.AsksOf(ctx, false) }

// AsksOf lists the pending approvals of the person, or with all every
// person's (administrators only; the gateway audits the read, GAP-0466).
func (c *Client) AsksOf(ctx context.Context, all bool) ([]Ask, error) {
	var out struct {
		Asks []Ask `json:"asks"`
	}
	var q url.Values
	if all {
		q = url.Values{"all": {"1"}}
	}
	if err := c.do(ctx, http.MethodGet, "asks", q, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Asks {
		out.Asks[i] = out.Asks[i].shown()
	}
	return out.Asks, nil
}

// Decide answers one ask: decision is approve or deny. An approval lets
// one request through; always keeps it for every later request of the
// agent (GAP-0484).
func (c *Client) Decide(ctx context.Context, id, decision string, always bool, reason string) error {
	in := map[string]any{"decision": decision}
	if always {
		in["always"] = true
	}
	if reason != "" {
		in["reason"] = reason
	}
	return c.do(ctx, http.MethodPost, "asks/"+url.PathEscape(id), nil, in, nil)
}

// StandingApproval is one approval given with approve --always that is
// still in force (GAP-0492): every later request of the agent to Host (in
// Scope) goes through without asking.
type StandingApproval struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	Host     string `json:"host"`
	// Scope is "host" for the whole host, else the url_rules rule and
	// methods the approval covers.
	Scope string `json:"scope,omitempty"`
	// ApprovedBy is "you", "owner" or "administrator"; empty, like
	// ApprovedAt, when the cluster no longer has the answer.
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	AskID      string    `json:"ask_id,omitempty"`
	// Owner is the agent's person, in an administrator's all view.
	Owner string `json:"owner,omitempty"`
}

func (s StandingApproval) shown() StandingApproval {
	for _, f := range []*string{&s.Atespace, &s.Actor, &s.Host, &s.Scope, &s.ApprovedBy, &s.AskID, &s.Owner} {
		*f = safetext.Line(*f)
	}
	return s
}

// StandingApprovals lists the always approvals in force on the person's
// agents, or with all every person's (administrators only; audited).
func (c *Client) StandingApprovals(ctx context.Context, all bool) ([]StandingApproval, error) {
	var out struct {
		Approvals []StandingApproval `json:"approvals"`
	}
	var q url.Values
	if all {
		q = url.Values{"all": {"1"}}
	}
	if err := c.do(ctx, http.MethodGet, "approvals", q, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Approvals {
		out.Approvals[i] = out.Approvals[i].shown()
	}
	return out.Approvals, nil
}

// Revoke takes back the always approvals of host on one agent: the agent's
// next request to it asks again (GAP-0492).
func (c *Client) Revoke(ctx context.Context, atespace, name, host string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodDelete, "approvals/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/"+url.PathEscape(host), nil, nil, &out)
}

// Decisions lists recent decisions on the person's actors.
func (c *Client) Decisions(ctx context.Context, actor string, limit int) ([]map[string]any, error) {
	q := url.Values{}
	if actor != "" {
		q.Set("actor", actor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out struct {
		Decisions []map[string]any `json:"decisions"`
	}
	if err := c.do(ctx, http.MethodGet, "decisions", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Decisions, nil
}

// Secret is a secret's name and where it applies (never its value).
type Secret struct {
	Name   string   `json:"name"`
	Scope  string   `json:"scope,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
	Mine   bool     `json:"mine,omitempty"`
	Status string   `json:"status,omitempty"`
}

// Secrets lists secret names; mine limits it to the person's own.
func (c *Client) Secrets(ctx context.Context, mine bool) ([]Secret, error) {
	q := url.Values{}
	if mine {
		q.Set("mine", "1")
	}
	var out struct {
		Secrets []Secret `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, "secrets", q, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Secrets {
		out.Secrets[i] = out.Secrets[i].shown()
	}
	return out.Secrets, nil
}

// SetSecret stores a per-person secret value; the value travels once, over
// TLS, and is never echoed.
func (c *Client) SetSecret(ctx context.Context, name, value string) error {
	return c.do(ctx, http.MethodPut, "secrets/"+url.PathEscape(name), nil, map[string]string{"value": value}, nil)
}

// RemoveSecret deletes a per-person secret.
func (c *Client) RemoveSecret(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "secrets/"+url.PathEscape(name), nil, nil, nil)
}

// TestSecret asks the gateway to check a secret against its bound host.
func (c *Client) TestSecret(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "secrets/"+url.PathEscape(name)+"/test", nil, map[string]any{}, &out)
}
