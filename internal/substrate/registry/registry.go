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

// Package registry holds the registrations of Agent Substrate actors
// (PLAN §6.1): who an actor belongs to and what it runs under, keyed by
// sandboxreg.SubstrateKey(atespace, actorUID). The launcher route writes a
// registration before it answers a create; the controller writes the
// attribution of an actor created elsewhere (D3). The gateway reads one on
// every actor request, after the actor token verified.
//
// The leader keeps them in FileStore on its volume; the other replicas
// reach it through Remote, which forwards over the leader transport and
// caches reads briefly.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// Person is who an actor belongs to: a verified person (OIDC) or a
// workload. Attributed registrations (actors DefenseClaw did not create)
// have none and name their atespace instead.
type Person struct {
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	Principal string `json:"principal,omitempty"`
	// EmailUnverified: the sign-in carried an email its issuer marked
	// unverified, so it was not used as the principal (GAP-0640). Shown as
	// lower assurance.
	EmailUnverified bool     `json:"email_unverified,omitempty"`
	Groups          []string `json:"groups,omitempty"`
}

// Assurance names the person's sign-in assurance when it is lower than a
// verified one ("email_unverified"), "" otherwise.
func (p Person) Assurance() string {
	if p.EmailUnverified {
		return AssuranceEmailUnverified
	}
	return ""
}

// AssuranceEmailUnverified is the assurance mark of a sign-in whose email
// the issuer did not verify.
const AssuranceEmailUnverified = "email_unverified"

// ID is the owner key (issuer#subject), "" for no person.
func (p Person) ID() string {
	if p.Subject == "" {
		return ""
	}
	return p.Issuer + "#" + p.Subject
}

// Registration is one actor incarnation's record.
type Registration struct {
	V        int    `json:"v"`
	Key      string `json:"key"`
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	// Person is the verified owner; empty for an attributed actor.
	Person Person `json:"person,omitzero"`
	// Attributed marks an actor DefenseClaw did not create (D3): it is
	// attributed to its atespace and template, never to a person.
	Attributed bool `json:"attributed,omitempty"`

	Profile        string `json:"profile"`
	ProfileDigest  string `json:"profile_digest,omitempty"`
	Generation     uint64 `json:"generation,omitempty"`
	Template       string `json:"template,omitempty"`
	TemplateDigest string `json:"template_digest,omitempty"`
	KitVersion     string `json:"kit_version,omitempty"`
	// RelayStreams are the relay features the template's signed kit names,
	// comma-joined ("tls": dial the relay with TLS, B3.5). Empty for kits
	// built before 1.0.11.
	RelayStreams   string `json:"relay_streams,omitempty"`
	Connector      string `json:"connector"`
	HarnessVersion string `json:"harness_version,omitempty"`
	HookContract   string `json:"hook_contract,omitempty"`
	BatchID        string `json:"batch_id,omitempty"`
	ParentUID      string `json:"parent_uid,omitempty"`
	// Unattended is a --task or --batch run: fail closed, asks per
	// substrate.unattended.asks (D8, D12).
	Unattended bool `json:"unattended,omitempty"`
	// TaskDigest is the SHA-256 of the --task text (the text itself goes to
	// the intent store, a verified source of the run's intent).
	TaskDigest string `json:"task_digest,omitempty"`
	// Secrets are the names of the per-person secrets bound to the actor.
	Secrets []string `json:"secrets,omitempty"`
	// Approved are the hosts asks approved for this actor (the controller
	// adds them to its policy).
	Approved []string `json:"approved,omitempty"`
	// ForkedBy is unknown for a fork (ParentUID set): DefenseClaw makes none.
	ForkedBy string `json:"forked_by,omitempty"`
	// SandboxClass is the class the actor runs in (gvisor or microvm), as
	// the launcher create chose it; the defenseclaw.sandbox.driver of its
	// records. Empty for an actor DefenseClaw did not create.
	SandboxClass string    `json:"sandbox_class,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// Deleted is a tombstone: the actor was deleted (E10).
	Deleted bool `json:"deleted,omitempty"`
	// PolicyConflict is set by the controller while the actor is in
	// policy_conflict (repeated foreign changes to its egress policy; it
	// keeps only the DefenseClaw rule until an admin resets it), so list,
	// status, policy explain and doctor show it (GAP-0398). Nil otherwise.
	PolicyConflict *PolicyConflict `json:"policy_conflict,omitempty"`
}

// PolicyConflict is the controller's policy_conflict mark on a registration.
type PolicyConflict struct {
	// Since is when the controller marked the conflict.
	Since time.Time `json:"since"`
	// Reverts is how many foreign changes it reverted in the conflict
	// window before it marked the conflict.
	Reverts int `json:"reverts"`
}

// olderLeaderForm is r without the fields a leader older than 1.0.11 does
// not decode (its RegistrationWrite refuses unknown fields), and whether r
// set any. Person.EmailUnverified (GAP-0640) is the only one; such a leader
// keeps the record without the lower-assurance mark, as 1.0.10 did. Kept
// while a rolling upgrade from a 1.0.10 leader is supported (GAP-0943).
func (r Registration) olderLeaderForm() (Registration, bool) {
	if !r.Person.EmailUnverified {
		return r, false
	}
	r.Person.EmailUnverified = false
	return r, true
}

// Version is the record version.
const Version = 1

// namePattern is an atespace or actor name: printable, bounded, no
// separators, so a name can't smuggle a path segment into a key or a
// refusal.
var namePattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// ValidName reports whether s is a well-formed atespace or actor name (the
// segments of an actor's SPIFFE ID the callout accepts).
func ValidName(s string) bool { return namePattern.MatchString(s) }

// Validate checks the identity fields and fills Key.
func (r *Registration) Validate() error {
	key, err := sandboxreg.SubstrateKey(r.Atespace, r.UID)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if r.Key != "" && r.Key != key {
		return errors.New("registry: key does not name the atespace and UID")
	}
	r.Key = key
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("registry: a registration names its actor")
	}
	// An attributed actor (made outside DefenseClaw) has no launcher to
	// name its connector; every launched one has.
	if !r.Attributed && strings.TrimSpace(r.Connector) == "" {
		return errors.New("registry: a launched actor names its connector")
	}
	if !r.Attributed && r.Person.Subject == "" {
		return errors.New("registry: a launched actor has a verified person")
	}
	if r.Attributed && r.Person.Subject != "" {
		return errors.New("registry: an attributed actor has no person")
	}
	if r.V == 0 {
		r.V = Version
	}
	return nil
}

// Filter selects registrations for List.
type Filter struct {
	// OwnerID limits to one person (Person.ID()); "" is every owner
	// (administrators only).
	OwnerID  string `json:"owner_id,omitempty"`
	Atespace string `json:"atespace,omitempty"`
	BatchID  string `json:"batch_id,omitempty"`
	// IncludeDeleted keeps tombstones.
	IncludeDeleted bool `json:"include_deleted,omitempty"`
}

func (f Filter) match(r Registration) bool {
	switch {
	case f.OwnerID != "" && r.Person.ID() != f.OwnerID:
		return false
	case f.Atespace != "" && r.Atespace != f.Atespace:
		return false
	case f.BatchID != "" && r.BatchID != f.BatchID:
		return false
	case r.Deleted && !f.IncludeDeleted:
		return false
	}
	return true
}

// Lookup is what the callout learns of an actor from its name, the only
// identity atenet-egress gives it (GAP-0090): the newest incarnation's
// UID, profile and attendance. No person, secret or approval leaves the
// leader this way.
type Lookup struct {
	Found bool `json:"found"`
	// Deleted is a tombstone for the newest incarnation: the actor is gone.
	Deleted    bool   `json:"deleted,omitempty"`
	UID        string `json:"uid,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Unattended bool   `json:"unattended,omitempty"`
	// Person is the bound person's ID (issuer#subject) and Principal their
	// principal, for records that name who used the actor (GAP-0513);
	// empty for an actor with no bound person.
	Person    string `json:"person,omitempty"`
	Principal string `json:"principal,omitempty"`
}

// LookupName finds the newest registration of atespace/name. An actor name
// is reused only after a delete (the launcher never reuses one, GAP-0133),
// so the newest record is the running incarnation, or its tombstone.
func LookupName(ctx context.Context, s Store, atespace, name string) (Lookup, error) {
	if atespace == "" || name == "" {
		return Lookup{}, errors.New("registry: a lookup names the atespace and the actor")
	}
	var best *Registration
	if fs, ok := s.(*FileStore); ok {
		if r, found := fs.newestByName(atespace, name); found {
			best = &r
		}
	} else {
		rs, err := s.List(ctx, Filter{Atespace: atespace, IncludeDeleted: true})
		if err != nil {
			return Lookup{}, err
		}
		for i := range rs {
			if rs[i].Name == name && (best == nil || newer(rs[i], *best)) {
				best = &rs[i]
			}
		}
	}
	if best == nil {
		return Lookup{}, nil
	}
	l := Lookup{Found: true, Deleted: best.Deleted, UID: best.UID, Profile: best.Profile, Unattended: best.Unattended}
	if !best.Attributed && best.Person.Subject != "" {
		l.Person, l.Principal = best.Person.ID(), best.Person.Principal
	}
	return l, nil
}

// Current reports whether uid is atespace/name's live incarnation: the
// name's newest registration, not deleted. The leader asks it on every
// egress chain check, so a callout that still holds a deleted or replaced
// incarnation's UID is never answered for it (GAP-0234).
func Current(ctx context.Context, s Store, atespace, name, uid string) (bool, error) {
	l, err := LookupName(ctx, s, atespace, name)
	if err != nil {
		return false, err
	}
	return l.Found && !l.Deleted && l.UID == uid, nil
}

// newer orders two registrations of one name: the later CreatedAt, then
// the smaller key (List's order).
func newer(a, b Registration) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.Key < b.Key
}

// Store is a registration store.
type Store interface {
	Get(ctx context.Context, atespace, uid string) (Registration, bool, error)
	Put(ctx context.Context, r Registration) error
	List(ctx context.Context, f Filter) ([]Registration, error)
}

// FileStore keeps one JSON file per registration under Dir, written
// atomically. The leader alone opens it.
type FileStore struct {
	dir string
	mu  sync.RWMutex
	mem map[string]Registration
	// newest is the key of each name's newest registration (atespace and
	// name), so LookupName reads one entry: the leader answers one for
	// every egress chain check (GAP-0234).
	newest map[string]string
	// certs is the live relay certificate per registration key
	// (relaycert.go, GAP-0861).
	certs map[string]RelayCert
	// born is the keys this process registered for the first time. The leader
	// alone opens the store and its term lasts as long as the process, so this
	// is "registered in my term" without comparing clocks of two nodes
	// (GAP-1148). It stops growing at maxBornKeys: the chain start grace that
	// reads it lasts seconds, and a key it lacks only keeps the grace.
	born map[string]struct{}
}

// maxBornKeys bounds the set of registrations RegisteredThisTerm knows.
const maxBornKeys = 65536

// RegisteredThisTerm reports whether this process, the leader, wrote the
// first registration of atespace/uid itself, as opposed to loading it from
// disk at start. It is the leader's own state, not a timestamp another node
// wrote (GAP-1148).
func (s *FileStore) RegisteredThisTerm(atespace, uid string) bool {
	key, err := sandboxreg.SubstrateKey(atespace, uid)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.born[key]
	return ok
}

// OpenFileStore loads every registration under dir.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	s := &FileStore{dir: dir, mem: map[string]Registration{}, newest: map[string]string{}, certs: map[string]RelayCert{}, born: map[string]struct{}{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		var r Registration
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("registry: %s: %w", e.Name(), err)
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("registry: %s: %w", e.Name(), err)
		}
		s.mem[r.Key] = r
		s.indexLocked(r)
	}
	if err := s.loadRelayCerts(); err != nil {
		return nil, err
	}
	return s, nil
}

func nameKey(atespace, name string) string { return atespace + "\x00" + name }

// indexLocked makes r its name's newest registration if it is newer than
// the one indexed. s.mu is held for writing (or s is not shared yet) and
// r is in s.mem.
func (s *FileStore) indexLocked(r Registration) {
	n := nameKey(r.Atespace, r.Name)
	if k, ok := s.newest[n]; ok && k != r.Key && !newer(r, s.mem[k]) {
		return
	}
	s.newest[n] = r.Key
}

func (s *FileStore) newestByName(atespace, name string) (Registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.newest[nameKey(atespace, name)]
	if !ok {
		return Registration{}, false
	}
	return s.mem[k], true
}

func fileName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".json"
}

// Get implements Store.
func (s *FileStore) Get(_ context.Context, atespace, uid string) (Registration, bool, error) {
	key, err := sandboxreg.SubstrateKey(atespace, uid)
	if err != nil {
		return Registration{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.mem[key]
	return r, ok, nil
}

// KitFillable reports whether r is an attributed record of an actor made
// outside DefenseClaw (no fork parent, not deleted) that names no kit: the
// controller could not attest its template when it first attributed it.
// Such a record may take its attested kit (connector, harness version, hook
// contract, kit version, template digest) once (GAP-0351).
// JoinStreams is the registry form of a kit's relay streams: sorted,
// deduplicated and comma-joined, so records compare as strings.
func JoinStreams(s []string) string {
	out := slices.Clone(s)
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ",")
}

// RelayServesTLS reports whether the actor's signed kit serves TLS.
func (r Registration) RelayServesTLS() bool { return r.RelayServes("tls") }

// RelayServes reports whether the actor's signed kit names a relay stream
// (kit.StreamTLS, kit.StreamPort, kit.StreamMCP).
func (r Registration) RelayServes(stream string) bool {
	return stream != "" && slices.Contains(strings.Split(r.RelayStreams, ","), stream)
}

func KitFillable(r Registration) bool {
	return r.Attributed && !r.Deleted && r.ParentUID == "" && r.Connector == "" && r.HarnessVersion == "" &&
		r.HookContract == "" && r.KitVersion == "" && r.TemplateDigest == ""
}

// Put implements Store. A registration is written once per incarnation;
// only the tombstone, the profile re-match (Profile, ProfileDigest,
// Generation), the secret names, and the kit of a KitFillable record may
// change after that.
func (s *FileStore) Put(_ context.Context, r Registration) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.mem[r.Key]
	if existed {
		kitFill := KitFillable(old) && r.Connector != ""
		if old.Person.ID() != r.Person.ID() || old.Name != r.Name || (old.Connector != r.Connector && !kitFill) ||
			old.Attributed != r.Attributed || old.Unattended != r.Unattended || old.BatchID != r.BatchID {
			return errors.New("registry: a registration's owner, actor, connector and run mode do not change")
		}
		if old.Deleted && !r.Deleted {
			return errors.New("registry: a deleted actor's registration stays deleted")
		}
		if !old.CreatedAt.IsZero() {
			r.CreatedAt = old.CreatedAt
		}
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.dir, fileName(r.Key), b); err != nil {
		return err
	}
	s.mem[r.Key] = r
	s.indexLocked(r)
	if !existed && len(s.born) < maxBornKeys {
		s.born[r.Key] = struct{}{}
	}
	return nil
}

// List implements Store, newest first.
func (s *FileStore) List(_ context.Context, f Filter) ([]Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Registration
	for _, r := range s.mem {
		if f.match(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}
