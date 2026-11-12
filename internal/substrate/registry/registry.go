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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// Person is who an actor belongs to: a verified person (OIDC) or a
// workload. Attributed registrations (actors DefenseClaw did not create)
// have none and name their atespace instead.
type Person struct {
	Kind      string   `json:"kind"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Principal string   `json:"principal,omitempty"`
	Groups    []string `json:"groups,omitempty"`
}

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
	// ForkedBy is defenseclaw or unknown for a fork (ParentUID set).
	ForkedBy  string    `json:"forked_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Deleted is a tombstone: the actor was deleted (E10).
	Deleted bool `json:"deleted,omitempty"`
}

// Version is the record version.
const Version = 1

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
}

// OpenFileStore loads every registration under dir.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	s := &FileStore{dir: dir, mem: map[string]Registration{}}
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
	}
	return s, nil
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

// Put implements Store. A registration is written once per incarnation;
// only the tombstone, the profile re-match (Profile, ProfileDigest,
// Generation) and the secret names may change after that.
func (s *FileStore) Put(_ context.Context, r Registration) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.mem[r.Key]; ok {
		if old.Person.ID() != r.Person.ID() || old.Name != r.Name || old.Connector != r.Connector ||
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
	path := filepath.Join(s.dir, fileName(r.Key))
	tmp, err := os.CreateTemp(s.dir, ".reg-*")
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	_, werr := tmp.Write(b)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("registry: write: %v", errors.Join(werr, serr, cerr))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("registry: %w", err)
	}
	s.mem[r.Key] = r
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
