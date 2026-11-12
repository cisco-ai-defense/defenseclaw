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

// Package usage keeps the model usage of Agent Substrate actors (PLAN §8,
// J30): one record per model call an actor makes through /llm, attributed
// to the verified person bound to the actor at create (never to a header),
// with token totals per person, actor, batch, atespace and model.
//
// The leader alone opens FileStore on its volume; gateways append and ask
// over the leader transport (Remote, Writer). A query names one owner or,
// for administrators only, every owner (Filter.AllOwners): an empty owner
// is never read as "everyone".
//
// Tokens only: there is no price table until stream 10 (tokenomics) lands,
// so no record carries a cost (absent cost stays absent, never 0). Stream
// 10's engine takes over the per-call parse in the gateway
// (gateway.SubstrateModelMeter); this store stays the source of the
// own-only usage view and the batch and atespace budgets.
package usage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tokens are the token counts a provider reported for one call.
type Tokens struct {
	Input         int64 `json:"input_tokens"`
	Output        int64 `json:"output_tokens"`
	CacheRead     int64 `json:"cache_read_tokens,omitempty"`
	CacheCreation int64 `json:"cache_creation_tokens,omitempty"`
}

// Total is every token the provider reported (input, output, cache read
// and cache write): what a budget counts.
func (t Tokens) Total() int64 { return t.Input + t.Output + t.CacheRead + t.CacheCreation }

func (t *Tokens) add(o Tokens) {
	t.Input += o.Input
	t.Output += o.Output
	t.CacheRead += o.CacheRead
	t.CacheCreation += o.CacheCreation
}

// Usage sources: where a record's tokens came from.
const (
	SourceHeader = "provider_header" // response headers (Bedrock InvokeModel)
	SourceBody   = "provider_body"   // the JSON response body
	SourceStream = "provider_stream" // the event stream (SSE or AWS eventstream)
	SourceAbsent = "absent"          // the provider reported none (refusal, error, cut stream)
)

// Record is one model call of an actor.
type Record struct {
	// RequestID is the gateway's request ID; the store keeps one record
	// per ID (a retried append is not counted twice).
	RequestID string    `json:"request_id"`
	At        time.Time `json:"at"`
	// OwnerID is registry.Person.ID() of the verified person; "" for an
	// attributed actor (D3: attributed to its atespace, never a person).
	OwnerID    string `json:"owner_id,omitempty"`
	Principal  string `json:"principal,omitempty"`
	OwnerKind  string `json:"owner_kind,omitempty"`
	Atespace   string `json:"atespace"`
	Actor      string `json:"actor"`
	ActorUID   string `json:"actor_uid"`
	Template   string `json:"template,omitempty"`
	BatchID    string `json:"batch_id,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Connector  string `json:"connector,omitempty"`
	Unattended bool   `json:"unattended,omitempty"`

	Provider string `json:"provider"`
	// API is the provider API family (invoke, invoke-stream, converse,
	// converse-stream, messages, chat, responses, generate, other).
	API            string `json:"api,omitempty"`
	RequestedModel string `json:"requested_model,omitempty"`
	// Model is the model that answered (the provider's word when it gives
	// one, else the routed model).
	Model string `json:"model,omitempty"`
	// Route is none (no router), kept or narrowed.
	Route     string `json:"route"`
	Status    int    `json:"status"`
	Streaming bool   `json:"streaming,omitempty"`
	Tokens
	UsageSource string `json:"usage_source"`
	DurationMS  int64  `json:"duration_ms"`
}

// Validate checks the fields a record must have.
func (r Record) Validate() error {
	switch {
	case strings.TrimSpace(r.RequestID) == "":
		return errors.New("usage: a record names its request")
	case r.Atespace == "" || r.ActorUID == "" || r.Provider == "":
		return errors.New("usage: a record names its atespace, actor UID and provider")
	case r.Input < 0 || r.Output < 0 || r.CacheRead < 0 || r.CacheCreation < 0:
		return errors.New("usage: negative token count")
	}
	return nil
}

// Filter selects records. Exactly one of OwnerID or AllOwners is set.
type Filter struct {
	OwnerID string `json:"owner_id,omitempty"`
	// AllOwners is every owner, attributed actors included (administrators
	// only; the gateway decides who may set it).
	AllOwners bool `json:"all_owners,omitempty"`
	// Principal narrows an AllOwners query to one person (administrators).
	Principal string    `json:"principal,omitempty"`
	BatchID   string    `json:"batch_id,omitempty"`
	Atespace  string    `json:"atespace,omitempty"`
	ActorUID  string    `json:"actor_uid,omitempty"`
	Since     time.Time `json:"since,omitzero"`
	// Records asks for up to this many of the newest matching records
	// (MaxRecords at most).
	Records int `json:"records,omitempty"`
}

// MaxRecords is the most per-call records one query returns.
const MaxRecords = 500

// ErrNoOwner is a filter with neither an owner nor AllOwners.
var ErrNoOwner = errors.New("usage: a query names its owner")

func (f Filter) check() error {
	if f.OwnerID == "" && !f.AllOwners {
		return ErrNoOwner
	}
	if f.OwnerID != "" && f.AllOwners {
		return errors.New("usage: a query names one owner or all owners")
	}
	return nil
}

func (f Filter) match(r *Record) bool {
	switch {
	case !f.AllOwners && r.OwnerID != f.OwnerID:
		return false
	case f.Principal != "" && !strings.EqualFold(r.Principal, f.Principal):
		return false
	case f.BatchID != "" && r.BatchID != f.BatchID:
		return false
	case f.Atespace != "" && r.Atespace != f.Atespace:
		return false
	case f.ActorUID != "" && r.ActorUID != f.ActorUID:
		return false
	case !f.Since.IsZero() && r.At.Before(f.Since):
		return false
	}
	return true
}

// Totals are the sums over some records.
type Totals struct {
	Calls int64 `json:"calls"`
	Tokens
	TotalTokens int64 `json:"total_tokens"`
	// Unmetered counts calls the provider reported no usage for.
	Unmetered int64 `json:"unmetered_calls,omitempty"`
}

func (t *Totals) add(r *Record) {
	t.Calls++
	t.Tokens.add(r.Tokens)
	t.TotalTokens += r.Tokens.Total()
	if r.UsageSource == SourceAbsent || r.UsageSource == "" {
		t.Unmetered++
	}
}

// ActorUsage is one actor's totals.
type ActorUsage struct {
	Atespace  string `json:"atespace"`
	Actor     string `json:"actor"`
	ActorUID  string `json:"actor_uid"`
	BatchID   string `json:"batch_id,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Connector string `json:"connector,omitempty"`
	Totals
}

// ModelUsage is one provider and model's totals.
type ModelUsage struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Route    string `json:"route"`
	Totals
}

// OwnerUsage is one person's totals (administrator views only).
type OwnerUsage struct {
	OwnerID   string `json:"owner_id"`
	Principal string `json:"principal,omitempty"`
	Totals
}

// Summary answers a query.
type Summary struct {
	Since  time.Time    `json:"since,omitzero"`
	Totals Totals       `json:"totals"`
	Actors []ActorUsage `json:"actors"`
	Models []ModelUsage `json:"models"`
	// Owners is present only for an AllOwners query.
	Owners []OwnerUsage `json:"owners,omitempty"`
	// CostBasis is none: no price table before stream 10, so no cost.
	CostBasis string   `json:"cost_basis"`
	Records   []Record `json:"records,omitempty"`
}

// Scope kinds of a budget.
const (
	ScopeBatch    = "batch"
	ScopeAtespace = "atespace"
)

// ScopeTotal is a budget scope's token total before and after an append.
// The store serializes appends, so exactly one append sees a threshold
// crossed (Before < limit <= After).
type ScopeTotal struct {
	Scope    string `json:"scope"`
	ID       string `json:"id"`
	OwnerID  string `json:"owner_id,omitempty"`
	Atespace string `json:"atespace,omitempty"`
	Before   int64  `json:"before"`
	After    int64  `json:"after"`
}

// AppendResult is what an append changed.
type AppendResult struct {
	Added  int          `json:"added"`
	Scopes []ScopeTotal `json:"scopes,omitempty"`
}

// ScopeQuery asks for the token totals of budget scopes.
type ScopeQuery struct {
	Scope string `json:"scope"`
	// OwnerID scopes a batch to its owner (batch IDs are per person).
	OwnerID string `json:"owner_id,omitempty"`
	ID      string `json:"id"`
}

// Store keeps usage records.
type Store interface {
	Append(ctx context.Context, recs []Record) (AppendResult, error)
	Summary(ctx context.Context, f Filter) (Summary, error)
	ScopeTotal(ctx context.Context, q ScopeQuery) (int64, error)
}

// Retention of FileStore (no config key: stream 10 brings the local store
// retention key, observability.tokenomics.local_store.retention_days).
const (
	DefaultRetention  = 31 * 24 * time.Hour
	DefaultMaxRecords = 200_000
)

// FileStore keeps records in an append-only JSON-lines file and the budget
// scope totals in a snapshot, both under Dir. Scope totals outlive record
// retention, so a budget threshold is crossed once even after old records
// age out or the leader restarts.
type FileStore struct {
	dir        string
	retention  time.Duration
	maxRecords int
	now        func() time.Time

	mu     sync.RWMutex
	recs   []Record
	ids    map[string]struct{}
	scopes map[string]*scopeState
	f      *os.File
	lines  int
}

type scopeState struct {
	Scope    string    `json:"scope"`
	ID       string    `json:"id"`
	OwnerID  string    `json:"owner_id,omitempty"`
	Atespace string    `json:"atespace,omitempty"`
	Tokens   int64     `json:"tokens"`
	Last     time.Time `json:"last"`
}

const (
	recordsFile = "records.jsonl"
	scopesFile  = "scopes.json"
)

// Options tune FileStore (tests).
type Options struct {
	Retention  time.Duration
	MaxRecords int
	Now        func() time.Time
}

// OpenFileStore loads the records under dir.
func OpenFileStore(dir string, opts ...Options) (*FileStore, error) {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Retention <= 0 {
		o.Retention = DefaultRetention
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = DefaultMaxRecords
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("usage: %w", err)
	}
	s := &FileStore{dir: dir, retention: o.Retention, maxRecords: o.MaxRecords, now: o.Now,
		ids: map[string]struct{}{}, scopes: map[string]*scopeState{}}
	if b, err := os.ReadFile(filepath.Join(dir, scopesFile)); err == nil {
		var list []*scopeState
		if json.Unmarshal(b, &list) == nil {
			for _, sc := range list {
				s.scopes[scopeKey(sc.Scope, sc.OwnerID, sc.ID)] = sc
			}
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	path := filepath.Join(s.dir, recordsFile)
	f, err := os.Open(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("usage: %w", err)
	}
	if err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			s.lines++
			var r Record
			if json.Unmarshal(sc.Bytes(), &r) != nil || r.Validate() != nil {
				continue
			}
			if _, dup := s.ids[r.RequestID]; dup {
				continue
			}
			s.ids[r.RequestID] = struct{}{}
			s.recs = append(s.recs, r)
		}
		_ = f.Close()
	}
	sort.SliceStable(s.recs, func(i, j int) bool { return s.recs[i].At.Before(s.recs[j].At) })
	trimmed := s.trimLocked()
	if trimmed || s.lines != len(s.recs) {
		return s.rewriteLocked()
	}
	return s.openAppendLocked()
}

// trimLocked drops records past retention or over the record cap.
func (s *FileStore) trimLocked() bool {
	cut := 0
	horizon := s.now().Add(-s.retention)
	for cut < len(s.recs) && s.recs[cut].At.Before(horizon) {
		cut++
	}
	if over := len(s.recs) - cut - s.maxRecords; over > 0 {
		cut += over
	}
	if cut == 0 {
		return false
	}
	for _, r := range s.recs[:cut] {
		delete(s.ids, r.RequestID)
	}
	s.recs = append([]Record(nil), s.recs[cut:]...)
	return true
}

func (s *FileStore) openAppendLocked() error {
	f, err := os.OpenFile(filepath.Join(s.dir, recordsFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	s.f = f
	return nil
}

// rewriteLocked writes the kept records to a new file and swaps it in.
func (s *FileStore) rewriteLocked() error {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	tmp, err := os.CreateTemp(s.dir, recordsFile+".*")
	if err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	w := bufio.NewWriter(tmp)
	for i := range s.recs {
		b, _ := json.Marshal(&s.recs[i])
		_, _ = w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("usage: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("usage: %w", err)
	}
	_ = tmp.Close()
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, recordsFile)); err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	s.lines = len(s.recs)
	return s.openAppendLocked()
}

func scopeKey(scope, owner, id string) string { return scope + "\x00" + owner + "\x00" + id }

// Close closes the record file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Append implements Store. Records already kept (same request ID) and
// invalid records are skipped.
func (s *FileStore) Append(_ context.Context, recs []Record) (AppendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return AppendResult{}, errors.New("usage: store closed")
	}
	var out AppendResult
	var buf []byte
	touched := map[string]*ScopeTotal{}
	var order []string
	bump := func(scope, owner, id, atespace string, n int64, at time.Time) {
		k := scopeKey(scope, owner, id)
		st := s.scopes[k]
		if st == nil {
			st = &scopeState{Scope: scope, ID: id, OwnerID: owner, Atespace: atespace}
			s.scopes[k] = st
		}
		t := touched[k]
		if t == nil {
			t = &ScopeTotal{Scope: scope, ID: id, OwnerID: owner, Atespace: atespace, Before: st.Tokens}
			touched[k] = t
			order = append(order, k)
		}
		st.Tokens += n
		st.Last = at
		t.After = st.Tokens
	}
	for _, r := range recs {
		if r.Validate() != nil {
			continue
		}
		if _, dup := s.ids[r.RequestID]; dup {
			continue
		}
		if r.At.IsZero() {
			r.At = s.now()
		}
		b, err := json.Marshal(&r)
		if err != nil {
			continue
		}
		buf = append(append(buf, b...), '\n')
		s.ids[r.RequestID] = struct{}{}
		s.recs = append(s.recs, r)
		out.Added++
		n := r.Tokens.Total()
		if r.BatchID != "" {
			bump(ScopeBatch, r.OwnerID, r.BatchID, r.Atespace, n, r.At)
		}
		bump(ScopeAtespace, "", r.Atespace, r.Atespace, n, r.At)
	}
	if out.Added == 0 {
		return out, nil
	}
	if _, err := s.f.Write(buf); err != nil {
		return AppendResult{}, fmt.Errorf("usage: %w", err)
	}
	_ = s.f.Sync()
	s.lines += out.Added
	if err := s.writeScopesLocked(); err != nil {
		return AppendResult{}, err
	}
	for _, k := range order {
		out.Scopes = append(out.Scopes, *touched[k])
	}
	if s.trimLocked() || s.lines > 2*s.maxRecords {
		if err := s.rewriteLocked(); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *FileStore) writeScopesLocked() error {
	horizon := s.now().Add(-s.retention)
	list := make([]*scopeState, 0, len(s.scopes))
	for k, sc := range s.scopes {
		// A batch scope idle past retention is done; atespaces stay.
		if sc.Scope == ScopeBatch && sc.Last.Before(horizon) {
			delete(s.scopes, k)
			continue
		}
		list = append(list, sc)
	}
	sort.Slice(list, func(i, j int) bool {
		return scopeKey(list[i].Scope, list[i].OwnerID, list[i].ID) < scopeKey(list[j].Scope, list[j].OwnerID, list[j].ID)
	})
	b, _ := json.Marshal(list)
	tmp, err := os.CreateTemp(s.dir, scopesFile+".*")
	if err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("usage: %w", err)
	}
	_ = tmp.Sync()
	_ = tmp.Close()
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, scopesFile)); err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	return nil
}

// ScopeTotal implements Store.
func (s *FileStore) ScopeTotal(_ context.Context, q ScopeQuery) (int64, error) {
	owner := q.OwnerID
	if q.Scope == ScopeAtespace {
		owner = ""
	} else if q.Scope != ScopeBatch {
		return 0, fmt.Errorf("usage: unknown scope %q", q.Scope)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sc := s.scopes[scopeKey(q.Scope, owner, q.ID)]; sc != nil {
		return sc.Tokens, nil
	}
	return 0, nil
}

// Summary implements Store.
func (s *FileStore) Summary(_ context.Context, f Filter) (Summary, error) {
	if err := f.check(); err != nil {
		return Summary{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Summary{Since: f.Since, CostBasis: "none", Actors: []ActorUsage{}, Models: []ModelUsage{}}
	actors := map[string]*ActorUsage{}
	models := map[string]*ModelUsage{}
	owners := map[string]*OwnerUsage{}
	var matched []int
	for i := range s.recs {
		r := &s.recs[i]
		if !f.match(r) {
			continue
		}
		matched = append(matched, i)
		out.Totals.add(r)
		ak := r.Atespace + "/" + r.ActorUID
		a := actors[ak]
		if a == nil {
			a = &ActorUsage{Atespace: r.Atespace, Actor: r.Actor, ActorUID: r.ActorUID, BatchID: r.BatchID,
				Profile: r.Profile, Connector: r.Connector}
			actors[ak] = a
		}
		a.Totals.add(r)
		model := r.Model
		if model == "" {
			model = r.RequestedModel
		}
		mk := r.Provider + "\x00" + model + "\x00" + r.Route
		m := models[mk]
		if m == nil {
			m = &ModelUsage{Provider: r.Provider, Model: model, Route: r.Route}
			models[mk] = m
		}
		m.Totals.add(r)
		if f.AllOwners {
			o := owners[r.OwnerID]
			if o == nil {
				o = &OwnerUsage{OwnerID: r.OwnerID, Principal: r.Principal}
				owners[r.OwnerID] = o
			}
			o.Totals.add(r)
		}
	}
	for _, a := range actors {
		out.Actors = append(out.Actors, *a)
	}
	sort.Slice(out.Actors, func(i, j int) bool {
		if out.Actors[i].Atespace != out.Actors[j].Atespace {
			return out.Actors[i].Atespace < out.Actors[j].Atespace
		}
		return out.Actors[i].Actor < out.Actors[j].Actor
	})
	for _, m := range models {
		out.Models = append(out.Models, *m)
	}
	sort.Slice(out.Models, func(i, j int) bool {
		if out.Models[i].Provider != out.Models[j].Provider {
			return out.Models[i].Provider < out.Models[j].Provider
		}
		return out.Models[i].Model < out.Models[j].Model
	})
	if f.AllOwners {
		out.Owners = []OwnerUsage{}
		for _, o := range owners {
			out.Owners = append(out.Owners, *o)
		}
		sort.Slice(out.Owners, func(i, j int) bool { return out.Owners[i].OwnerID < out.Owners[j].OwnerID })
	}
	if n := min(f.Records, MaxRecords); n > 0 {
		if len(matched) > n {
			matched = matched[len(matched)-n:]
		}
		for _, i := range matched {
			out.Records = append(out.Records, s.recs[i])
		}
	}
	return out, nil
}
