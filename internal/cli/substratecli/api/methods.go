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
	for _, f := range []*string{&a.Atespace, &a.Name, &a.Profile, &a.Connector, &a.Template, &a.BatchID, &a.Owner, &a.Attribution, &a.State} {
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
	for _, f := range []*string{&s.Name, &s.Scope, &s.Status, &s.Kind, &s.Template, &s.Reason, &s.AskID} {
		*f = safetext.Line(*f)
	}
	s.Hosts, s.Agents = safeLines(s.Hosts), safeLines(s.Agents)
	return s
}

func safeLines(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = safetext.Line(v)
	}
	return out
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
func (c *Client) Asks(ctx context.Context) ([]Ask, error) {
	var out struct {
		Asks []Ask `json:"asks"`
	}
	if err := c.do(ctx, http.MethodGet, "asks", nil, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Asks {
		out.Asks[i] = out.Asks[i].shown()
	}
	return out.Asks, nil
}

// Decide answers one ask: decision is approve or deny; always keeps an
// approval for later runs.
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

// PolicyExplain returns the effective policy of one actor.
func (c *Client) PolicyExplain(ctx context.Context, actor string) (map[string]any, error) {
	q := url.Values{}
	if actor != "" {
		q.Set("actor", actor)
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "policy/explain", q, nil, &out)
}

// Secret is a secret's name and where it applies (never its value).
type Secret struct {
	Name   string   `json:"name"`
	Scope  string   `json:"scope,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
	Mine   bool     `json:"mine,omitempty"`
	Status string   `json:"status,omitempty"`
	// Kind is template (the person's own binding, Template names it) or
	// admin (an administrator's entry).
	Kind     string `json:"kind,omitempty"`
	Template string `json:"template,omitempty"`
	// Reason is the reason code of a status that keeps the secret out of
	// every policy (expired, denied, waiting on admin, ...).
	Reason  string     `json:"reason,omitempty"`
	AskID   string     `json:"ask_id,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`
	// Agents are the person's agents that get it; nil when not known.
	Agents []string `json:"agents,omitempty"`
	// LastUsed is the newest request by one of the person's agents that
	// Substrate added the secret to: when, the host and the agent.
	LastUsed      *time.Time `json:"last_used,omitempty"`
	LastUsedHost  string     `json:"last_used_host,omitempty"`
	LastUsedAgent string     `json:"last_used_agent,omitempty"`
}

// SecretTest is the answer of secrets test: the secret as list shows it
// and, for --agent, whether that agent's policy carries it.
type SecretTest struct {
	Secret
	Agent *SecretTestAgent `json:"agent,omitempty"`
}

// SecretTestAgent says whether one agent's policy carries the secret.
// InPolicy is nil when DefenseClaw could not tell.
type SecretTestAgent struct {
	Actor    string `json:"actor"`
	InPolicy *bool  `json:"in_policy"`
	Reason   string `json:"reason,omitempty"`
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

// SecretTemplate is one admin-approved way to bind a secret of your own.
type SecretTemplate struct {
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	Header    string   `json:"header"`
	Form      string   `json:"form"`
	BasicUser string   `json:"basic_user,omitempty"`
}

func (t SecretTemplate) shown() SecretTemplate {
	for _, f := range []*string{&t.Name, &t.Header, &t.Form, &t.BasicUser} {
		*f = safetext.Line(*f)
	}
	hosts := make([]string, len(t.Hosts))
	for i, h := range t.Hosts {
		hosts[i] = safetext.Line(h)
	}
	t.Hosts = hosts
	return t
}

// SecretTemplates lists the templates your profile may use and the
// self-service mode (bindings or values_only).
func (c *Client) SecretTemplates(ctx context.Context) ([]SecretTemplate, string, error) {
	var out struct {
		Templates []SecretTemplate `json:"templates"`
		Mode      string           `json:"mode"`
	}
	if err := c.do(ctx, http.MethodGet, "secret-templates", nil, nil, &out); err != nil {
		return nil, "", err
	}
	for i := range out.Templates {
		out.Templates[i] = out.Templates[i].shown()
	}
	return out.Templates, safetext.Line(out.Mode), nil
}

// AddSecretRequest creates a binding of your own; Value is the plain
// token (the gateway forms a basic credential itself).
type AddSecretRequest struct {
	Name      string    `json:"name"`
	Template  string    `json:"template"`
	Host      string    `json:"host"`
	Value     string    `json:"value"`
	Expires   time.Time `json:"expires,omitzero"`
	AllowEcho bool      `json:"allow_echo,omitempty"`
	User      string    `json:"user,omitempty"`
}

// AddSecretResult is the new binding; Reason is set when it waits on an
// administrator (202).
type AddSecretResult struct {
	Name     string    `json:"name"`
	ID       string    `json:"id"`
	Template string    `json:"template"`
	Host     string    `json:"host"`
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	AskID    string    `json:"ask_id,omitempty"`
	Expires  time.Time `json:"expires,omitzero"`
}

// AddSecret stores a new secret of your own for one host; the value
// travels once, over TLS, and is never echoed.
func (c *Client) AddSecret(ctx context.Context, req AddSecretRequest) (AddSecretResult, error) {
	var out AddSecretResult
	if err := c.do(ctx, http.MethodPost, "secrets", nil, req, &out); err != nil {
		return AddSecretResult{}, err
	}
	for _, f := range []*string{&out.Name, &out.ID, &out.Template, &out.Host, &out.Status, &out.Reason} {
		*f = safetext.Line(*f)
	}
	return out, nil
}

// RemoveSecret deletes a per-person secret.
func (c *Client) RemoveSecret(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "secrets/"+url.PathEscape(name), nil, nil, nil)
}

// TestSecret asks the gateway whether a secret is stored and usable and,
// with agent (atespace/name), whether that agent's policy carries it.
func (c *Client) TestSecret(ctx context.Context, name, agent string) (SecretTest, error) {
	var out SecretTest
	body := map[string]any{}
	if agent != "" {
		body["agent"] = agent
	}
	if err := c.do(ctx, http.MethodPost, "secrets/"+url.PathEscape(name)+"/test", nil, body, &out); err != nil {
		return SecretTest{}, err
	}
	out.Secret = out.shown()
	if out.Agent != nil {
		out.Agent.Actor, out.Agent.Reason = safetext.Line(out.Agent.Actor), safetext.Line(out.Agent.Reason)
	}
	return out, nil
}
