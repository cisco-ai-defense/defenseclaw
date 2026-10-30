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

package sandboxreg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// DecisionIDPrefix prefixes a saved decision's id, followed by
// IDRandomChars lowercase base32 characters.
const DecisionIDPrefix = "dec-"

// MaxDecisionsPerUID caps one uid's saved decisions; the oldest go first.
const MaxDecisionsPerUID = 1024

// maxDecisionHostBytes bounds a decision's host.
const maxDecisionHostBytes = 253

var decisionHostPattern = lazyregexp.New(`^[A-Za-z0-9*][A-Za-z0-9.*:_\[\]-]*$`)

// DecisionsDir is the decision store under the gateway's data directory:
// <DataDir>/sandbox/decisions.
func DecisionsDir(dataDir string) string {
	return filepath.Join(dataDir, "sandbox", "decisions")
}

// ValidDecision checks the shape of a decision record: a known kind and
// scope, a bounded host name or pattern and the registration it came from.
func ValidDecision(d Decision) error {
	switch d.Kind {
	case sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionUnblock:
	default:
		return fmt.Errorf("%w: unknown decision kind", ErrInvalid)
	}
	switch d.Scope {
	case sandboxrelay.DecisionScopeSession, sandboxrelay.DecisionScopeAlways:
	default:
		return fmt.Errorf("%w: unknown decision scope", ErrInvalid)
	}
	if d.Host == "" || len(d.Host) > maxDecisionHostBytes || !decisionHostPattern.MatchString(d.Host) {
		return fmt.Errorf("%w: decision host is malformed", ErrInvalid)
	}
	if !ValidID(d.Registration) {
		return fmt.Errorf("%w: decision registration is malformed", ErrInvalid)
	}
	return nil
}

// FileDecisionStore is the DecisionStore kept like FileStore: one private
// JSON file per uid under DecisionsDir, written atomically.
type FileDecisionStore struct {
	dir string
	// Now is the store's clock; nil means time.Now.
	Now func() time.Time

	mu   sync.Mutex
	uids map[int][]Decision
}

var _ DecisionStore = (*FileDecisionStore)(nil)

// NewFileDecisionStore returns the decision store kept under dir.
func NewFileDecisionStore(dir string) *FileDecisionStore {
	return &FileDecisionStore{dir: dir, uids: make(map[int][]Decision)}
}

type decisionFile struct {
	V         int        `json:"v"`
	Decisions []Decision `json:"decisions"`
}

func (s *FileDecisionStore) path(uid int) string {
	return filepath.Join(s.dir, strconv.Itoa(uid)+".json")
}

func (s *FileDecisionStore) loadLocked(uid int) ([]Decision, error) {
	if uid < 0 {
		return nil, fmt.Errorf("%w: negative uid", ErrInvalid)
	}
	if ds, ok := s.uids[uid]; ok {
		return ds, nil
	}
	var file decisionFile
	if err := readStoreFile(s.path(uid), &file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.uids[uid] = nil
			return nil, nil
		}
		return nil, err
	}
	if file.V != storeFileVersion {
		return nil, fmt.Errorf("%w: uid %d: unsupported version %d", ErrCorrupt, uid, file.V)
	}
	for _, d := range file.Decisions {
		if d.Actor.UID != uid || !strings.HasPrefix(d.ID, DecisionIDPrefix) {
			return nil, fmt.Errorf("%w: uid %d: a decision names another uid or a malformed id", ErrCorrupt, uid)
		}
	}
	s.uids[uid] = file.Decisions
	return file.Decisions, nil
}

// Add stores d for uid. The id, version and actor uid are the store's; a
// decision for the same registration, kind, host and scope replaces the
// earlier one, and past MaxDecisionsPerUID the oldest is dropped.
func (s *FileDecisionStore) Add(uid int, d Decision) error {
	if err := ValidDecision(d); err != nil {
		return err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("sandboxreg: decision id: %w", err)
	}
	d.V, d.ID, d.Actor.UID = RecordVersion, DecisionIDPrefix+idEncoding.EncodeToString(raw[:]), uid
	if d.CreatedAt.IsZero() {
		if s.Now != nil {
			d.CreatedAt = s.Now().UTC()
		} else {
			d.CreatedAt = time.Now().UTC()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, err := s.loadLocked(uid)
	if err != nil {
		return err
	}
	next := slices.DeleteFunc(slices.Clone(ds), func(have Decision) bool {
		return have.Registration == d.Registration && have.Kind == d.Kind &&
			strings.EqualFold(have.Host, d.Host) && have.Scope == d.Scope
	})
	next = append(next, d)
	if over := len(next) - MaxDecisionsPerUID; over > 0 {
		next = slices.Delete(next, 0, over)
	}
	if err := writeStoreFile(s.dir, s.path(uid), decisionFile{V: storeFileVersion, Decisions: next}); err != nil {
		return err
	}
	s.uids[uid] = next
	return nil
}

// List returns uid's decisions, oldest first; a registration other than
// "" keeps only that registration's.
func (s *FileDecisionStore) List(uid int, registration string) ([]Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, err := s.loadLocked(uid)
	if err != nil {
		return nil, err
	}
	if registration == "" {
		return slices.Clone(ds), nil
	}
	var out []Decision
	for _, d := range ds {
		if d.Registration == registration {
			out = append(out, d)
		}
	}
	return out, nil
}

// Purge removes the whole store.
func (s *FileDecisionStore) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uids = make(map[int][]Decision)
	if err := os.RemoveAll(s.dir); err != nil {
		return fmt.Errorf("sandboxreg: purge %s: %w", s.dir, err)
	}
	return nil
}
