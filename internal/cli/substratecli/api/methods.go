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
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// Actor is one Substrate actor as the admin listener shows it.
type Actor struct {
	Atespace        string    `json:"atespace"`
	Name            string    `json:"name"`
	UID             string    `json:"uid"`
	RegistrationKey string    `json:"registration_key,omitempty"`
	Profile         string    `json:"profile"`
	Connector       string    `json:"connector"`
	Template        string    `json:"template"`
	BatchID         string    `json:"batch_id,omitempty"`
	Unattended      bool      `json:"unattended,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	Owner           string    `json:"owner,omitempty"`
	Deleted         bool      `json:"deleted,omitempty"`
	State           string    `json:"state,omitempty"`
	// SessionToken is present on create for an attended run.
	SessionToken   string    `json:"session_token,omitempty"`
	SessionExpires time.Time `json:"session_expires,omitempty"`
}

// shown returns a with every field a person reads made safe to print
// (safetext.Line): the cluster and the agent choose them, and they end up in
// tables, status lines, prompts and errors. The identifiers the launcher
// sends back (UID, registration key, session token) are left as they are.
func (a Actor) shown() Actor {
	for _, f := range []*string{&a.Atespace, &a.Name, &a.Profile, &a.Connector, &a.Template, &a.BatchID, &a.Owner, &a.State} {
		*f = safetext.Line(*f)
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
	q := url.Values{}
	if o.Batch != "" {
		q.Set("batch", o.Batch)
	}
	if o.All {
		q.Set("all", "1")
	}
	var out struct {
		Actors []Actor `json:"actors"`
	}
	if err := c.do(ctx, http.MethodGet, "actors", q, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Actors {
		out.Actors[i] = out.Actors[i].shown()
	}
	return out.Actors, nil
}

// Get returns one actor.
func (c *Client) Get(ctx context.Context, atespace, name string) (Actor, error) {
	var a Actor
	err := c.do(ctx, http.MethodGet, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name), nil, nil, &a)
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
