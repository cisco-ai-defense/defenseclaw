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
	"regexp"
	"slices"
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
	Tag                string `json:"tag"`
	ImageID            string `json:"image_id"`
	ContentHash        string `json:"content_hash"`
	Connector          string `json:"connector"`
	HarnessVersion     string `json:"harness_version"`
	HookContract       string `json:"hook_contract"`
	BaseImage          string `json:"base_image"`
	UID                int    `json:"uid"`
	GID                int    `json:"gid"`
	IngressPort        int    `json:"ingress_port"`
	DefenseClawVersion string `json:"defenseclaw_version"`
	// FailMode is the fail mode baked into the image's hooks.
	FailMode string `json:"fail_mode"`
	// Owner is the Store.Owner of the data dir that built the image; Prune
	// removes only images this store recorded under its own owner.
	Owner string `json:"owner"`
	// MicroVM marks an image built for the MicroVM driver
	// (BuildSpec.MicroVM).
	MicroVM bool      `json:"microvm,omitempty"`
	BuiltAt time.Time `json:"built_at"`
	// Binaries maps the required commands to their in-image realpaths.
	Binaries []Binary `json:"binaries"`
	// NetworkBinaries are the realpaths LLM credential profiles pin.
	NetworkBinaries []Binary `json:"network_binaries"`
	// HookFireVerified is set only by Builder.VerifyHooks (which Build runs
	// for every fresh image), once the hook-fire probe proved that the
	// managed hooks of ImageID fire. Build records every new image
	// unverified first, so a rebuild clears an earlier verdict.
	HookFireVerified bool `json:"hook_fire_verified,omitempty"`
	// HookFireVerifiedAt is when that probe passed.
	HookFireVerifiedAt time.Time `json:"hook_fire_verified_at,omitzero"`
	// MicroVMVerified is set by VerifyHooks with HookFireVerified when the
	// probe's MicroVM scenario passed as well: the harness started and its
	// hooks fired with an OpenShell MicroVM's name resolution (no
	// localhost in /etc/hosts). A driver without a hosts file
	// (openshell.Driver.HostsFile) boots only an image that has it.
	MicroVMVerified bool `json:"microvm_verified,omitempty"`
	// MicroVMProblem says why the MicroVM scenario failed.
	MicroVMProblem string `json:"microvm_problem,omitempty"`
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
	Version int `json:"version"`
	// Owner identifies this data dir to the Docker daemon: every image it
	// builds carries it in its content hash (so in its tag) and in the
	// LabelOwner label. It is random, created on first use, so two data dirs
	// sharing one daemon never share, select or prune each other's images,
	// and a lost images.json makes every earlier image foreign rather than
	// removable.
	Owner  string   `json:"owner,omitempty"`
	Images []Record `json:"images"`
	// RunImages are the run images and aliases made from those images for
	// a driver that is sent its own image names (RunImage). Absent until
	// the first one is made, so a store on a docker gateway keeps its
	// shape.
	RunImages []RunImage `json:"run_images,omitempty"`
}

// ownerRE is the shape of a store owner.
var ownerRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// NewStore opens the store under dataDir.
func NewStore(dataDir string) *Store {
	return &Store{path: filepath.Join(dataDir, "sandboxes", "images.json")}
}

// Path is the store file.
func (s *Store) Path() string { return s.path }

// Owner returns this store's owner, creating and persisting it on first use.
func (s *Store) Owner() (string, error) {
	var owner string
	err := s.locked(func() error {
		doc, err := s.read()
		if err != nil {
			return err
		}
		if doc.Owner == "" {
			if doc.Owner, err = randomHex(8); err != nil {
				return err
			}
			if err := s.write(doc); err != nil {
				return err
			}
		}
		owner = doc.Owner
		return nil
	})
	return owner, err
}

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

// Current returns the image a sandbox built from want's spec must run: the
// record of exactly want's tag and content hash, whose every recorded input
// (connector, harness version, hook contract, base image, run-as identity,
// ingress port, DefenseClaw version and fail mode) matches want, and whose
// hooks were proven to fire (HookFireVerified). There is no fallback to an
// older image: after an upgrade or a changed input the old image carries
// stale hooks, so a missing or unverified exact match means build (or
// verify) first. A built but unverified image is never selected either:
// Claude silently ignores a managed-settings drop-in with one schema-invalid
// field, and only the hook-fire probe tells such an image apart from one
// that enforces.
func (s *Store) Current(want *Context) (Record, bool, error) {
	if want == nil {
		return Record{}, false, errors.New("openshell image store: Current needs the expected build context")
	}
	r, ok, err := s.Get(want.Tag)
	if err != nil || !ok {
		return Record{}, false, err
	}
	if !r.HookFireVerified || !recordMatches(r, want) {
		return Record{}, false, nil
	}
	return r, true, nil
}

// recordMatches reports whether r was built from exactly c's inputs.
func recordMatches(r Record, c *Context) bool {
	return r.Tag == c.Tag &&
		r.ContentHash == c.ContentHash &&
		r.Connector == c.Spec.Harness.Name &&
		r.HarnessVersion == c.HarnessVersion &&
		r.HookContract == c.Contract &&
		r.BaseImage == c.Spec.BaseImage &&
		r.UID == c.Spec.UID &&
		r.GID == c.Spec.GID &&
		r.IngressPort == c.Spec.IngressPort &&
		r.DefenseClawVersion == c.Spec.DefenseClawVersion &&
		r.FailMode == c.Spec.FailMode &&
		r.Owner == c.Spec.Owner &&
		r.MicroVM == c.Spec.MicroVM
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

// update applies fn to the record with tag and persists the result under
// the store lock, so a concurrent Put cannot interleave with it.
func (s *Store) update(tag string, fn func(*Record) error) (Record, error) {
	var out Record
	err := s.locked(func() error {
		doc, err := s.read()
		if err != nil {
			return err
		}
		for i := range doc.Images {
			if doc.Images[i].Tag != tag {
				continue
			}
			if err := fn(&doc.Images[i]); err != nil {
				return err
			}
			out = doc.Images[i]
			return s.write(doc)
		}
		return fmt.Errorf("openshell image store: no record for %s", tag)
	})
	return out, err
}

// RunImages returns every run image and alias record, sorted by tag.
func (s *Store) RunImages() ([]RunImage, error) {
	var out []RunImage
	err := s.locked(func() error {
		doc, err := s.read()
		out = doc.RunImages
		return err
	})
	return out, err
}

// runImage returns the run image or alias record for tag.
func (s *Store) runImage(tag string) (RunImage, bool, error) {
	records, err := s.RunImages()
	if err != nil {
		return RunImage{}, false, err
	}
	for _, r := range records {
		if r.Tag == tag {
			return r, true, nil
		}
	}
	return RunImage{}, false, nil
}

// putRunImage inserts or replaces the run image or alias record with r.Tag.
func (s *Store) putRunImage(r RunImage) error {
	if r.Tag == "" {
		return errors.New("openshell image store: run image record has no tag")
	}
	return s.locked(func() error {
		doc, err := s.read()
		if err != nil {
			return err
		}
		doc.RunImages = slices.DeleteFunc(doc.RunImages, func(o RunImage) bool { return o.Tag == r.Tag })
		doc.RunImages = append(doc.RunImages, r)
		return s.write(doc)
	})
}

// Remove deletes the records for tags: overlay images, run images and
// aliases alike.
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
		doc.RunImages = slices.DeleteFunc(doc.RunImages, func(r RunImage) bool { return drop[r.Tag] })
		return s.write(doc)
	})
}

// runImageLock serializes the making and pruning of run images and aliases
// across processes (the daemon's creates and a CLI prune), apart from the
// store lock, which a build must not hold while docker runs.
func (s *Store) runImageLock() (func(), error) {
	if err := safefile.ProtectDirectory(filepath.Dir(s.path)); err != nil {
		return nil, fmt.Errorf("openshell image store: %w", err)
	}
	unlock, err := lockFile(s.path + ".run.lock")
	if err != nil {
		return nil, fmt.Errorf("openshell image store: lock the run images: %w", err)
	}
	return unlock, nil
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
	if doc.Owner != "" && !ownerRE.MatchString(doc.Owner) {
		return storeDoc{}, fmt.Errorf("openshell image store: %s has a malformed owner", s.path)
	}
	sort.Slice(doc.Images, func(i, j int) bool { return doc.Images[i].Tag < doc.Images[j].Tag })
	sort.Slice(doc.RunImages, func(i, j int) bool { return doc.RunImages[i].Tag < doc.RunImages[j].Tag })
	return doc, nil
}

func (s *Store) write(doc storeDoc) error {
	doc.Version = storeVersion
	sort.Slice(doc.Images, func(i, j int) bool { return doc.Images[i].Tag < doc.Images[j].Tag })
	sort.Slice(doc.RunImages, func(i, j int) bool { return doc.RunImages[i].Tag < doc.RunImages[j].Tag })
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
