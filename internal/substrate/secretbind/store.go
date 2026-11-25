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

// Package secretbind is the store of self-service secret bindings: which
// person bound which of their own secrets to which hosts, under which
// admin template, and whether it is active, waiting on an administrator or
// denied. It never holds a value (values are Kubernetes Secrets in the
// self-service namespace). The gateway alone writes it; the gateway, the
// controller and the callout read it.
//
// The store is one ConfigMap (key bindings.json) behind the Backend
// interface. Writes are read-modify-write at the resourceVersion that was
// read, so two gateway replicas never lose each other's change. A read
// that does not parse keeps the last good document, as configwatch does
// for config. Every entry is checked again on read, because an
// administrator can edit the ConfigMap by hand.
package secretbind

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Version is the bindings.json format version.
const Version = 1

// Limits of the store (B1 2.6): a ConfigMap holds at most 1 MiB, which is
// about 2,500 bindings; the store refuses past MaxBindings.
const (
	MaxBindings = 2000
	MaxDocBytes = 1 << 20
	MaxHosts    = 8
)

// State of a binding.
type State string

const (
	Active  State = "active"
	Waiting State = "waiting"
	Denied  State = "denied"
)

// Binding is one person's binding of one of their secrets. No value.
type Binding struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"` // the owner's person key
	Template  string    `json:"template"`
	Hosts     []string  `json:"hosts"`
	State     State     `json:"state"`
	AskID     string    `json:"ask_id,omitempty"`
	Expires   time.Time `json:"expires,omitzero"`
	AllowEcho bool      `json:"allow_echo,omitempty"`
	// BasicUser is the user of a basic-form binding when its template has
	// none (generic-basic) or the person names another one.
	BasicUser string `json:"basic_user,omitempty"`
	// StoredForm is how the stored value was formed at add or at the last
	// set (Template.FormStamp). A template edit that changes the form leaves
	// the stored value in the old form (RV3 P4-3).
	StoredForm string    `json:"stored_form,omitempty"`
	Created    time.Time `json:"created"`
}

// Expired reports whether the binding has passed its expiry at now.
func (b Binding) Expired(now time.Time) bool {
	return !b.Expires.IsZero() && !now.Before(b.Expires)
}

// Doc is the bindings.json document.
type Doc struct {
	Version  int       `json:"version"`
	Bindings []Binding `json:"bindings"`
}

var (
	idRE    = regexp.MustCompile(`^b-[0-9a-f]{10}$`)
	nameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	ownerRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	tmplRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// basicUserRE is a basic-auth user: printable ASCII without space or
	// ":" (RFC 7617 splits user and password at the first ":").
	basicUserRE = regexp.MustCompile(`^[!-9;-~]{1,128}$`)
	// hostRE is the shape only; the controller checks the host against the
	// template patterns, the echo list and the egress rules when it
	// renders.
	hostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$`)
)

// NewID returns a new binding id, b-<10 hex>.
func NewID() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secretbind: no randomness: " + err.Error())
	}
	return "b-" + hex.EncodeToString(b[:])
}

// Check returns why an entry is malformed, or nil. It is the shape check
// every reader runs on every entry.
func (b Binding) Check() error {
	switch {
	case !idRE.MatchString(b.ID):
		return errors.New("id")
	case !nameRE.MatchString(b.Name):
		return errors.New("name")
	case !ownerRE.MatchString(b.Owner):
		return errors.New("owner")
	case !tmplRE.MatchString(b.Template):
		return errors.New("template")
	case len(b.Hosts) == 0 || len(b.Hosts) > MaxHosts:
		return errors.New("hosts")
	case b.State != Active && b.State != Waiting && b.State != Denied:
		return errors.New("state")
	case b.Created.IsZero():
		return errors.New("created")
	case b.BasicUser != "" && !basicUserRE.MatchString(b.BasicUser):
		return errors.New("basic_user")
	}
	for _, h := range b.Hosts {
		if len(h) > 253 || !hostRE.MatchString(h) {
			return errors.New("hosts")
		}
	}
	return nil
}

// Decode parses bindings.json and drops every malformed entry, a second
// entry with an id already seen, and a second entry of one owner with a
// name already seen (the first wins). dropped names each dropped entry's
// id (or index) and the field.
func Decode(raw []byte) (doc Doc, dropped []string, err error) {
	if len(raw) > MaxDocBytes {
		return Doc{}, nil, fmt.Errorf("secretbind: bindings.json is over %d bytes", MaxDocBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Doc{Version: Version}, nil, nil
	}
	var in Doc
	if err := json.Unmarshal(raw, &in); err != nil {
		return Doc{}, nil, fmt.Errorf("secretbind: bindings.json does not parse: %w", err)
	}
	if in.Version != Version {
		return Doc{}, nil, fmt.Errorf("secretbind: bindings.json version %d, want %d", in.Version, Version)
	}
	out := Doc{Version: Version, Bindings: make([]Binding, 0, len(in.Bindings))}
	ids, names := map[string]bool{}, map[string]bool{}
	for i, b := range in.Bindings {
		what := b.ID
		if !idRE.MatchString(what) {
			what = fmt.Sprintf("#%d", i)
		}
		if err := b.Check(); err != nil {
			dropped = append(dropped, what+": "+err.Error())
			continue
		}
		if ids[b.ID] || names[b.Owner+"\x00"+b.Name] {
			dropped = append(dropped, what+": duplicate")
			continue
		}
		if len(out.Bindings) >= MaxBindings {
			dropped = append(dropped, what+": over the limit")
			continue
		}
		ids[b.ID], names[b.Owner+"\x00"+b.Name] = true, true
		out.Bindings = append(out.Bindings, b)
	}
	return out, dropped, nil
}

// Encode writes the document in a stable order (owner, name).
func (d Doc) Encode() ([]byte, error) {
	d.Version = Version
	sort.SliceStable(d.Bindings, func(i, j int) bool {
		if d.Bindings[i].Owner != d.Bindings[j].Owner {
			return d.Bindings[i].Owner < d.Bindings[j].Owner
		}
		return d.Bindings[i].Name < d.Bindings[j].Name
	})
	raw, err := json.Marshal(d)
	if err == nil && len(raw) > MaxDocBytes {
		err = ErrFull
	}
	return raw, err
}

// Errors of the store.
var (
	// ErrConflict is a write whose resourceVersion is no longer current.
	ErrConflict = errors.New("secretbind: the store changed under the write")
	// ErrFull is a document over MaxBindings or MaxDocBytes.
	ErrFull = errors.New("secretbind: the store is full")
	// ErrNoStore is a write to a store that is off or not deployed.
	ErrNoStore = errors.New("secretbind: no binding store")
)

// Backend reads and writes the raw document. Get returns found=false when
// the key does not exist (version is still the object's), and ErrNoStore
// when the ConfigMap itself does not (a chart from before the store). Put
// writes at version (the resourceVersion Get returned) and returns
// ErrConflict when it is not current.
type Backend interface {
	Get(ctx context.Context) (raw []byte, version string, found bool, err error)
	Put(ctx context.Context, raw []byte, version string) error
}

// Store is the cached reader and the writer. A nil *Store is the store of
// a cluster with self-service off: it reads as empty and refuses writes,
// and nothing polls.
type Store struct {
	backend Backend

	mu      sync.RWMutex
	doc     Doc
	version string
	loaded  bool
	dropped []string
	lastErr error
}

// New returns a store over backend. It reads nothing until Refresh.
func New(backend Backend) *Store {
	return &Store{backend: backend, doc: Doc{Version: Version}}
}

// Refresh reads the document. A read or parse failure keeps the last good
// document and is returned (and kept for Health).
func (s *Store) Refresh(ctx context.Context) error {
	if s == nil {
		return nil
	}
	raw, version, found, err := s.backend.Get(ctx)
	var doc Doc
	var dropped []string
	if err == nil {
		if !found {
			raw = nil
		}
		doc, dropped, err = Decode(raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err
		return err
	}
	s.doc, s.version, s.loaded, s.dropped, s.lastErr = doc, version, true, dropped, nil
	return nil
}

// Health says whether the last read worked and which entries it dropped.
func (s *Store) Health() (loaded bool, dropped []string, err error) {
	if s == nil {
		return false, nil, ErrNoStore
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded, append([]string(nil), s.dropped...), s.lastErr
}

// ByID returns a copy of the binding with the id.
func (s *Store) ByID(id string) (Binding, bool) {
	if s == nil || id == "" {
		return Binding{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.doc.Bindings {
		if b.ID == id {
			return cloneBinding(b), true
		}
	}
	return Binding{}, false
}

// All returns a copy of every binding.
func (s *Store) All() []Binding {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneBindings(s.doc.Bindings)
}

// ForOwner returns a copy of the bindings of one person key.
func (s *Store) ForOwner(owner string) []Binding {
	if s == nil || owner == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Binding
	for _, b := range s.doc.Bindings {
		if b.Owner == owner {
			out = append(out, cloneBinding(b))
		}
	}
	return out
}

// Update reads the current document, applies fn and writes it at the
// version read, retrying a conflict up to three times. fn sees and edits a
// copy; an error from fn is returned unchanged and nothing is written.
func (s *Store) Update(ctx context.Context, fn func(*Doc) error) error {
	if s == nil {
		return ErrNoStore
	}
	for try := 0; ; try++ {
		raw, version, found, err := s.backend.Get(ctx)
		if err != nil {
			return err
		}
		if !found {
			// The ConfigMap exists without the key: write at its version.
			raw = nil
		}
		doc, _, err := Decode(raw)
		if err != nil {
			// Never overwrite a document a reader cannot parse: an
			// administrator edit must be fixed, not lost.
			return err
		}
		if err := fn(&doc); err != nil {
			return err
		}
		if len(doc.Bindings) > MaxBindings {
			return ErrFull
		}
		for _, b := range doc.Bindings {
			if err := b.Check(); err != nil {
				return fmt.Errorf("secretbind: binding %s: bad %s", b.ID, err)
			}
		}
		out, err := doc.Encode()
		if err != nil {
			return err
		}
		err = s.backend.Put(ctx, out, version)
		if errors.Is(err, ErrConflict) && try < 2 {
			continue
		}
		if err != nil {
			return err
		}
		_ = s.Refresh(ctx)
		return nil
	}
}

// Watch refreshes the store every interval until ctx ends. It is started
// only when self-service is on (a nil store has no watcher).
func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if s == nil {
		return
	}
	_ = s.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Refresh(ctx)
		}
	}
}

func cloneBinding(b Binding) Binding {
	b.Hosts = append([]string(nil), b.Hosts...)
	return b
}

func cloneBindings(in []Binding) []Binding {
	out := make([]Binding, len(in))
	for i, b := range in {
		out[i] = cloneBinding(b)
	}
	return out
}
