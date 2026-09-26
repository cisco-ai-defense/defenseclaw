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

package sandboxauth

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	storeFileVersion = 1
	// StoreFileName is the binding table's basename under DefaultStoreDir.
	StoreFileName = "bindings.json"
	// maxStoreBytes bounds the table read; 1024 bindings are well under it.
	maxStoreBytes = 4 << 20
	// maxBindings bounds the table so a runaway caller cannot grow it
	// without limit.
	maxBindings = 1024
	// defaultRefreshInterval is how stale the in-memory table may be relative
	// to disk. A revoke written by another process takes effect within it.
	defaultRefreshInterval = time.Second
)

// Matcher authenticates a presented credential. The ingress needs only this.
type Matcher interface {
	Match(token string) (Binding, error)
}

// DefaultStorePath returns <dataDir>/sandboxes/bindings.json.
func DefaultStorePath(dataDir string) string {
	return filepath.Join(dataDir, "sandboxes", StoreFileName)
}

type storeFile struct {
	Version  int       `json:"version"`
	Bindings []Binding `json:"bindings"`
}

// FileStore is the durable binding table. The DefenseClaw daemon is its
// single writer in normal operation; the advisory lock still serialises any
// second process (a CLI repair, a restarted daemon overlapping its
// predecessor), and every write is an atomic owner-only replacement.
type FileStore struct {
	path     string
	lockPath string
	now      func() time.Time
	refresh  time.Duration

	// writeMu serialises in-process mutations before the cross-process lock.
	writeMu sync.Mutex
	// refreshMu lets exactly one goroutine revalidate the file; others keep
	// serving the current table instead of queueing on disk I/O.
	refreshMu sync.Mutex

	mu        sync.RWMutex
	byID      map[string]Binding
	byHash    map[string]string
	loaded    fs.FileInfo
	checkedAt time.Time
}

// StoreOption customises a FileStore.
type StoreOption func(*FileStore)

// WithClock sets the store clock. Tests use it for expiry and refresh.
func WithClock(now func() time.Time) StoreOption {
	return func(s *FileStore) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRefreshInterval sets how often Match revalidates the file on disk.
func WithRefreshInterval(d time.Duration) StoreOption {
	return func(s *FileStore) {
		if d >= 0 {
			s.refresh = d
		}
	}
}

// OpenFileStore opens (or prepares) the binding table at path. The parent
// directory is created owner-only. An existing table must be an owner-only
// regular file in an owner-only directory and must parse cleanly; anything
// else fails closed rather than being silently replaced.
func OpenFileStore(path string, opts ...StoreOption) (*FileStore, error) {
	if !lockSupported {
		return nil, ErrUnsupportedPlatform
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("sandboxauth: store path %q must be absolute and clean", path)
	}
	dir := filepath.Dir(path)
	if err := safefile.ProtectDirectory(dir); err != nil {
		return nil, fmt.Errorf("sandboxauth: prepare store directory: %w", err)
	}
	s := &FileStore{
		path:     path,
		lockPath: filepath.Join(dir, "."+filepath.Base(path)+".lock"),
		now:      time.Now,
		refresh:  defaultRefreshInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	state, info, err := s.readState()
	if err != nil {
		return nil, err
	}
	s.install(state, info)
	return s, nil
}

// Path returns the table location.
func (s *FileStore) Path() string { return s.path }

// Mint creates a binding for spec and returns it with its credential. The
// credential is returned exactly once; only its hash is stored.
func (s *FileStore) Mint(spec Spec) (Binding, string, error) {
	spec, err := spec.normalize()
	if err != nil {
		return Binding{}, "", err
	}
	token, err := newToken()
	if err != nil {
		return Binding{}, "", err
	}
	id, err := newBindingID()
	if err != nil {
		return Binding{}, "", err
	}
	now := s.now().UTC()
	b := bindingFromSpec(id, spec)
	b.TokenHash = HashToken(token)
	b.Generation = 1
	b.CreatedAt = now
	b.RotatedAt = now
	b.ExpiresAt = expiry(now, spec.TTL)
	err = s.mutate(func(state *storeFile) error {
		if len(state.Bindings) >= maxBindings {
			return fmt.Errorf("sandboxauth: binding table is full (%d bindings)", maxBindings)
		}
		if conflict := identityConflict(state.Bindings, b); conflict != "" {
			return fmt.Errorf("%w: %s", ErrExists, conflict)
		}
		state.Bindings = append(state.Bindings, b)
		return nil
	})
	if err != nil {
		return Binding{}, "", err
	}
	return cloneBinding(b), token, nil
}

// Rotate replaces a binding's credential. The previous credential stops
// authenticating as soon as the new table is published; the manager rotates
// while the sandbox is stopped, before re-attaching the provider.
func (s *FileStore) Rotate(id string) (Binding, string, error) {
	token, err := newToken()
	if err != nil {
		return Binding{}, "", err
	}
	var rotated Binding
	err = s.mutate(func(state *storeFile) error {
		i := indexOf(state.Bindings, id)
		if i < 0 {
			return ErrNotFound
		}
		now := s.now().UTC()
		b := state.Bindings[i]
		b.TokenHash = HashToken(token)
		b.Generation++
		b.RotatedAt = now
		b.ExpiresAt = expiry(now, time.Duration(b.TTLSeconds)*time.Second)
		state.Bindings[i] = b
		rotated = b
		return nil
	})
	if err != nil {
		return Binding{}, "", err
	}
	return cloneBinding(rotated), token, nil
}

// Revoke deletes a binding; its credential stops authenticating
// immediately in this process and within the refresh interval elsewhere.
func (s *FileStore) Revoke(id string) error {
	return s.mutate(func(state *storeFile) error {
		i := indexOf(state.Bindings, id)
		if i < 0 {
			return ErrNotFound
		}
		state.Bindings = slices.Delete(state.Bindings, i, i+1)
		return nil
	})
}

// Update applies fn to a binding's spec, e.g. to record the sandbox id once
// OpenShell has assigned it or the contract of a rebuilt image. The
// credential, connector and sandbox name are fixed for a binding's life:
// changing what a live credential may call requires a new binding.
func (s *FileStore) Update(id string, fn func(*Spec) error) (Binding, error) {
	var updated Binding
	err := s.mutate(func(state *storeFile) error {
		i := indexOf(state.Bindings, id)
		if i < 0 {
			return ErrNotFound
		}
		current := state.Bindings[i]
		spec := current.Spec()
		if err := fn(&spec); err != nil {
			return err
		}
		spec, err := spec.normalize()
		if err != nil {
			return err
		}
		if spec.Connector != current.Connector || spec.SandboxName != current.SandboxName {
			return invalid("connector and sandbox name cannot change; mint a new binding")
		}
		next := bindingFromSpec(current.ID, spec)
		next.TokenHash = current.TokenHash
		next.Generation = current.Generation
		next.CreatedAt = current.CreatedAt
		next.RotatedAt = current.RotatedAt
		next.ExpiresAt = current.ExpiresAt
		if next.TTLSeconds != current.TTLSeconds {
			next.ExpiresAt = expiry(current.RotatedAt, spec.TTL)
		}
		others := slices.Delete(slices.Clone(state.Bindings), i, i+1)
		if conflict := identityConflict(others, next); conflict != "" {
			return fmt.Errorf("%w: %s", ErrExists, conflict)
		}
		state.Bindings[i] = next
		updated = next
		return nil
	})
	if err != nil {
		return Binding{}, err
	}
	return cloneBinding(updated), nil
}

// Get returns one binding.
func (s *FileStore) Get(id string) (Binding, error) {
	s.maybeRefresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.byID[id]
	if !ok {
		return Binding{}, ErrNotFound
	}
	return cloneBinding(b), nil
}

// Lookup returns the binding for an OpenShell sandbox name.
func (s *FileStore) Lookup(sandboxName string) (Binding, error) {
	s.maybeRefresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.byID {
		if b.SandboxName == sandboxName {
			return cloneBinding(b), nil
		}
	}
	return Binding{}, ErrNotFound
}

// List returns every binding ordered by sandbox name.
func (s *FileStore) List() []Binding {
	s.maybeRefresh()
	s.mu.RLock()
	out := make([]Binding, 0, len(s.byID))
	for _, b := range s.byID {
		out = append(out, cloneBinding(b))
	}
	s.mu.RUnlock()
	slices.SortFunc(out, func(a, b Binding) int { return strings.Compare(a.SandboxName, b.SandboxName) })
	return out
}

// Match authenticates token. It is the ingress hot path: a hash, a map
// lookup and a constant-time comparison against in-memory state, with disk
// revalidation at most once per refresh interval.
func (s *FileStore) Match(token string) (Binding, error) {
	if !LooksLikeToken(token) {
		return Binding{}, ErrUnauthenticated
	}
	s.maybeRefresh()
	digest := HashToken(token)
	s.mu.RLock()
	id, ok := s.byHash[digest]
	b := s.byID[id]
	s.mu.RUnlock()
	if !ok || subtle.ConstantTimeCompare([]byte(b.TokenHash), []byte(digest)) != 1 {
		return Binding{}, ErrUnauthenticated
	}
	if b.Expired(s.now()) {
		return Binding{}, ErrUnauthenticated
	}
	return cloneBinding(b), nil
}

func (s *FileStore) maybeRefresh() {
	s.mu.RLock()
	due := s.now().Sub(s.checkedAt) >= s.refresh
	s.mu.RUnlock()
	if !due || !s.refreshMu.TryLock() {
		return
	}
	defer s.refreshMu.Unlock()

	current, statErr := os.Lstat(s.path)
	s.mu.RLock()
	previous := s.loaded
	s.mu.RUnlock()
	if statErr == nil && previous != nil && sameFileVersion(previous, current) {
		s.mu.Lock()
		s.checkedAt = s.now()
		s.mu.Unlock()
		return
	}
	if errors.Is(statErr, fs.ErrNotExist) && previous == nil {
		s.mu.Lock()
		s.checkedAt = s.now()
		s.mu.Unlock()
		return
	}
	state, info, err := s.readState()
	if err != nil {
		// A table that no longer validates (permissions broadened, file
		// swapped, content corrupted) authenticates nobody until repaired.
		fmt.Fprintf(os.Stderr, "[sandboxauth] binding table rejected, refusing all sandbox credentials: %v\n", err)
		s.install(storeFile{Version: storeFileVersion}, nil)
		return
	}
	s.install(state, info)
}

func (s *FileStore) mutate(fn func(*storeFile) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	unlock, err := lockExclusive(s.lockPath)
	if err != nil {
		return err
	}
	defer unlock()

	state, _, err := s.readState()
	if err != nil {
		return err
	}
	if err := fn(&state); err != nil {
		return err
	}
	state.Version = storeFileVersion
	if state.Bindings == nil {
		state.Bindings = []Binding{}
	}
	slices.SortFunc(state.Bindings, func(a, b Binding) int { return strings.Compare(a.ID, b.ID) })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("sandboxauth: encode binding table: %w", err)
	}
	data = append(data, '\n')
	if err := safefile.Write(s.path, data); err != nil {
		return fmt.Errorf("sandboxauth: write binding table: %w", err)
	}
	info, err := os.Lstat(s.path)
	if err != nil {
		return fmt.Errorf("sandboxauth: stat binding table: %w", err)
	}
	s.install(state, info)
	return nil
}

// readState loads and validates the table. A missing file is an empty
// table; every other irregularity is an error.
func (s *FileStore) readState() (storeFile, fs.FileInfo, error) {
	empty := storeFile{Version: storeFileVersion}
	if _, err := os.Lstat(s.path); errors.Is(err, fs.ErrNotExist) {
		return empty, nil, nil
	} else if err != nil {
		return storeFile{}, nil, fmt.Errorf("sandboxauth: stat binding table: %w", err)
	}
	if err := safefile.ValidatePrivateDirectory(filepath.Dir(s.path)); err != nil {
		return storeFile{}, nil, fmt.Errorf("sandboxauth: binding table directory is not private: %w", err)
	}
	if err := safefile.ValidatePrivateFile(s.path); err != nil {
		return storeFile{}, nil, fmt.Errorf("sandboxauth: binding table is not a private regular file: %w", err)
	}
	data, err := safefile.ReadRegularFileBounded(s.path, maxStoreBytes)
	if err != nil {
		return storeFile{}, nil, fmt.Errorf("sandboxauth: read binding table: %w", err)
	}
	info, err := os.Lstat(s.path)
	if err != nil {
		return storeFile{}, nil, fmt.Errorf("sandboxauth: stat binding table: %w", err)
	}
	state, err := decodeStore(data)
	if err != nil {
		return storeFile{}, nil, err
	}
	return state, info, nil
}

func decodeStore(data []byte) (storeFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state storeFile
	if err := dec.Decode(&state); err != nil {
		return storeFile{}, fmt.Errorf("sandboxauth: decode binding table: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return storeFile{}, errors.New("sandboxauth: binding table has trailing data")
	}
	if state.Version != storeFileVersion {
		return storeFile{}, fmt.Errorf("sandboxauth: binding table version %d is not supported", state.Version)
	}
	if len(state.Bindings) > maxBindings {
		return storeFile{}, errors.New("sandboxauth: binding table exceeds the binding limit")
	}
	ids := make(map[string]bool, len(state.Bindings))
	hashes := make(map[string]bool, len(state.Bindings))
	for i, b := range state.Bindings {
		if err := b.validate(); err != nil {
			return storeFile{}, fmt.Errorf("sandboxauth: binding table entry %d: %w", i, err)
		}
		if ids[b.ID] || hashes[b.TokenHash] {
			return storeFile{}, fmt.Errorf("sandboxauth: binding table entry %d duplicates an id or credential", i)
		}
		if conflict := identityConflict(state.Bindings[:i], b); conflict != "" {
			return storeFile{}, fmt.Errorf("sandboxauth: binding table entry %d: %s", i, conflict)
		}
		ids[b.ID] = true
		hashes[b.TokenHash] = true
	}
	return state, nil
}

func (s *FileStore) install(state storeFile, info fs.FileInfo) {
	byID := make(map[string]Binding, len(state.Bindings))
	byHash := make(map[string]string, len(state.Bindings))
	for _, b := range state.Bindings {
		byID[b.ID] = b
		byHash[b.TokenHash] = b.ID
	}
	s.mu.Lock()
	s.byID = byID
	s.byHash = byHash
	s.loaded = info
	s.checkedAt = s.now()
	s.mu.Unlock()
}

func bindingFromSpec(id string, spec Spec) Binding {
	return Binding{
		ID:             id,
		SandboxID:      spec.SandboxID,
		SandboxName:    spec.SandboxName,
		Connector:      spec.Connector,
		AgentVersion:   spec.AgentVersion,
		HookContractID: spec.HookContractID,
		PolicyProfile:  spec.PolicyProfile,
		Routes:         slices.Clone(spec.Routes),
		Workdir:        spec.Workdir.clone(),
		HostUser:       spec.HostUser,
		RateLimit:      spec.RateLimit,
		TTLSeconds:     int64(spec.TTL / time.Second),
	}
}

func cloneBinding(b Binding) Binding {
	b.Routes = slices.Clone(b.Routes)
	b.Workdir = b.Workdir.clone()
	return b
}

func identityConflict(existing []Binding, candidate Binding) string {
	for _, b := range existing {
		if b.ID == candidate.ID {
			continue
		}
		if b.SandboxName == candidate.SandboxName {
			return fmt.Sprintf("sandbox %q already has binding %s", candidate.SandboxName, b.ID)
		}
		if candidate.SandboxID != "" && b.SandboxID == candidate.SandboxID {
			return fmt.Sprintf("sandbox id %q already has binding %s", candidate.SandboxID, b.ID)
		}
	}
	return ""
}

func indexOf(bindings []Binding, id string) int {
	return slices.IndexFunc(bindings, func(b Binding) bool { return b.ID == id })
}

func expiry(from time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return from.Add(ttl)
}

// sameFileVersion decides whether the table can be trusted without a
// re-read. Mode is part of it so a permission change alone forces the
// revalidation that rejects a broadened table.
func sameFileVersion(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}
