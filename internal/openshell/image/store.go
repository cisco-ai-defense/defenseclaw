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

package image

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	storeVersion  = 1
	storeMaxBytes = 4 << 20
)

// Record is one verified overlay image.
type Record struct {
	Tag                string    `json:"tag"`
	ImageID            string    `json:"image_id"`
	ContentHash        string    `json:"content_hash"`
	Connector          string    `json:"connector"`
	HarnessVersion     string    `json:"harness_version"`
	HookContract       string    `json:"hook_contract"`
	BaseImage          string    `json:"base_image"`
	UID                int       `json:"uid"`
	GID                int       `json:"gid"`
	IngressPort        int       `json:"ingress_port"`
	DefenseClawVersion string    `json:"defenseclaw_version"`
	BuiltAt            time.Time `json:"built_at"`
	// Binaries maps the required commands to their in-image realpaths.
	Binaries []Binary `json:"binaries"`
	// NetworkBinaries are the realpaths LLM credential profiles pin.
	NetworkBinaries []Binary `json:"network_binaries"`
	// HookFireVerified is set once the hook-fire probe passed.
	HookFireVerified bool `json:"hook_fire_verified,omitempty"`
}

// NetworkRealpaths lists the realpaths for profiles.Input.Binaries.
func (r Record) NetworkRealpaths() []string {
	out := make([]string, 0, len(r.NetworkBinaries))
	for _, b := range r.NetworkBinaries {
		out = append(out, b.Realpath)
	}
	return out
}

// Store persists records in <data_dir>/sandboxes/images.json (owner-only,
// atomically replaced, cross-process locked).
type Store struct {
	path string
	mu   sync.Mutex
}

type storeDoc struct {
	Version int      `json:"version"`
	Images  []Record `json:"images"`
}

// NewStore opens the store under dataDir.
func NewStore(dataDir string) *Store {
	return &Store{path: filepath.Join(dataDir, "sandboxes", "images.json")}
}

// Path is the store file.
func (s *Store) Path() string { return s.path }

// List returns every record sorted by tag.
func (s *Store) List() ([]Record, error) {
	var out []Record
	err := s.locked(func() error {
		doc, err := s.read()
		out = doc.Images
		return err
	})
	return out, err
}

// Get returns the record for tag.
func (s *Store) Get(tag string) (Record, bool, error) {
	records, err := s.List()
	if err != nil {
		return Record{}, false, err
	}
	for _, r := range records {
		if r.Tag == tag {
			return r, true, nil
		}
	}
	return Record{}, false, nil
}

// Current returns the most recently built record for an identity.
func (s *Store) Current(connectorName string, uid, gid, ingressPort int) (Record, bool, error) {
	records, err := s.List()
	if err != nil {
		return Record{}, false, err
	}
	var best Record
	found := false
	for _, r := range records {
		if r.Connector != connectorName || r.UID != uid || r.GID != gid || r.IngressPort != ingressPort {
			continue
		}
		if !found || r.BuiltAt.After(best.BuiltAt) {
			best, found = r, true
		}
	}
	return best, found, nil
}

// Put inserts or replaces the record with r.Tag.
func (s *Store) Put(r Record) error {
	if r.Tag == "" {
		return errors.New("openshell image store: record has no tag")
	}
	return s.locked(func() error {
		doc, err := s.read()
		if err != nil {
			return err
		}
		replaced := false
		for i := range doc.Images {
			if doc.Images[i].Tag == r.Tag {
				doc.Images[i] = r
				replaced = true
			}
		}
		if !replaced {
			doc.Images = append(doc.Images, r)
		}
		return s.write(doc)
	})
}

// Remove deletes the records for tags.
func (s *Store) Remove(tags ...string) error {
	drop := map[string]bool{}
	for _, t := range tags {
		drop[t] = true
	}
	return s.locked(func() error {
		doc, err := s.read()
		if err != nil {
			return err
		}
		kept := doc.Images[:0]
		for _, r := range doc.Images {
			if !drop[r.Tag] {
				kept = append(kept, r)
			}
		}
		doc.Images = kept
		return s.write(doc)
	})
}

func (s *Store) locked(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := safefile.ProtectDirectory(filepath.Dir(s.path)); err != nil {
		return fmt.Errorf("openshell image store: %w", err)
	}
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return fmt.Errorf("openshell image store: lock: %w", err)
	}
	defer unlock()
	return fn()
}

func (s *Store) read() (storeDoc, error) {
	data, err := safefile.ReadRegularFileBounded(s.path, storeMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return storeDoc{Version: storeVersion}, nil
	}
	if err != nil {
		return storeDoc{}, fmt.Errorf("openshell image store: read %s: %w", s.path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc storeDoc
	if err := dec.Decode(&doc); err != nil {
		return storeDoc{}, fmt.Errorf("openshell image store: parse %s: %w", s.path, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return storeDoc{}, fmt.Errorf("openshell image store: %s holds trailing data", s.path)
	}
	if doc.Version != storeVersion {
		return storeDoc{}, fmt.Errorf("openshell image store: %s has unsupported version %d", s.path, doc.Version)
	}
	sort.Slice(doc.Images, func(i, j int) bool { return doc.Images[i].Tag < doc.Images[j].Tag })
	return doc, nil
}

func (s *Store) write(doc storeDoc) error {
	doc.Version = storeVersion
	sort.Slice(doc.Images, func(i, j int) bool { return doc.Images[i].Tag < doc.Images[j].Tag })
	if doc.Images == nil {
		doc.Images = []Record{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("openshell image store: encode: %w", err)
	}
	if err := safefile.WritePrivate(s.path, append(data, '\n')); err != nil {
		return fmt.Errorf("openshell image store: write %s: %w", s.path, err)
	}
	return nil
}
