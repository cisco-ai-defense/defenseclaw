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

// Package configwatch is the one way a running Substrate component sees a
// config.yaml change (GAP-0276). Every component used to load config.yaml
// once at start, so an edit of the defenseclaw-config ConfigMap reached
// nothing until a pod restart. A Watcher reads the ConfigMap through the
// Kubernetes API (no kubelet volume delay, and it works for the managed
// subPath mount, which the kubelet never updates in place), falls back to
// the mounted file, and loads a changed source with the strict reload
// loader. Each loaded source has a digest; a source that does not load is
// refused once per digest and the last good config stays in force, so a
// broken edit neither crashes a component nor loosens anything.
package configwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// DefaultInterval is how often Refresh reads the source at most: the bound
// on how long a change takes to be seen.
const DefaultInterval = 2 * time.Second

// ConfigMapKey is the key of config.yaml in the defenseclaw-config ConfigMap.
const ConfigMapKey = "config.yaml"

// Fetch reads config.yaml from the ConfigMap. found false means the
// ConfigMap or its key is gone.
type Fetch func(ctx context.Context) (raw []byte, found bool, err error)

// Watcher tracks config.yaml. It is safe for concurrent use.
type Watcher struct {
	// Path is the mounted config.yaml: the loader's file name (the managed
	// trust check runs on it) and the source when Fetch is nil or fails.
	Path string
	// Fetch, when set, reads the ConfigMap through the API.
	Fetch Fetch
	// Interval bounds how often the source is read (DefaultInterval).
	Interval time.Duration
	// Load decodes a source (config.LoadRuntimeV8CandidateFromBytes).
	Load func(path string, raw []byte) (*config.Config, error)
	Now  func() time.Time

	mu       sync.Mutex
	cur      *config.Config
	digest   string
	readAt   time.Time
	badHash  string
	fetchErr string
}

// New returns a watcher whose current config is boot, the config the
// component started with, and bootRaw its source.
func New(path string, boot *config.Config, bootRaw []byte) *Watcher {
	return &Watcher{Path: path, cur: boot, digest: Digest(bootRaw)}
}

// Start reads path and returns a watcher over it, with the config the
// component loaded from it.
func Start(path string, boot *config.Config) (*Watcher, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("configwatch: %w", err)
	}
	return New(path, boot, raw), nil
}

// Digest is the short SHA-256 of a config.yaml source: the config_digest
// events carry.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Current returns the config in force and its digest.
func (w *Watcher) Current() (*config.Config, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur, w.digest
}

// Change is what Refresh saw.
type Change struct {
	Config *config.Config
	Digest string
	// Previous is the digest before a change.
	Previous string
	// Changed: a new source loaded and is now in force.
	Changed bool
	// Refused is set once per source that does not load; the last good
	// config stays in force.
	Refused error
	// FetchWarning is set once when the API read fails and the file is
	// used instead (and again if the reason changes).
	FetchWarning string
}

// Refresh reads the source if Interval has passed since the last read and
// loads it if its digest changed.
func (w *Watcher) Refresh(ctx context.Context) Change {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	out := Change{Config: w.cur, Digest: w.digest}
	t := now()
	if !w.readAt.IsZero() && t.Sub(w.readAt) < interval {
		return out
	}
	w.readAt = t
	raw, warn, err := w.read(ctx)
	if warn != w.fetchErr {
		w.fetchErr = warn
		out.FetchWarning = warn
	}
	if err != nil {
		// Nothing readable: keep the config in force (the next read tries
		// again). Reported like a source that does not load, once.
		if w.badHash != "read:"+err.Error() {
			w.badHash = "read:" + err.Error()
			out.Refused = err
		}
		return out
	}
	d := Digest(raw)
	if d == w.digest {
		w.badHash = ""
		return out
	}
	if d == w.badHash {
		return out
	}
	load := w.Load
	if load == nil {
		load = config.LoadRuntimeV8CandidateFromBytes
	}
	cfg, err := load(w.Path, raw)
	if err == nil && cfg != nil && !cfg.Substrate.Enabled {
		err = errors.New("substrate.enabled is false")
	}
	if err != nil {
		w.badHash = d
		out.Refused = fmt.Errorf("config.yaml %s does not load, %s stays in force: %w", d, w.digest, err)
		return out
	}
	w.badHash = ""
	out.Previous, out.Changed = w.digest, true
	w.cur, w.digest = cfg, d
	out.Config, out.Digest = cfg, d
	return out
}

// read returns the source: the ConfigMap, else the file. warn names why
// the ConfigMap was not used ("" when it was, or when there is none).
func (w *Watcher) read(ctx context.Context) (raw []byte, warn string, err error) {
	if w.Fetch != nil {
		b, found, ferr := w.Fetch(ctx)
		switch {
		case ferr == nil && found:
			return b, "", nil
		case ferr == nil:
			warn = "the defenseclaw-config ConfigMap or its config.yaml key is missing: reading the mounted file"
		default:
			warn = "cannot read the defenseclaw-config ConfigMap (" + ferr.Error() + "): reading the mounted file, which the kubelet updates on its own schedule"
		}
	}
	b, err := os.ReadFile(w.Path)
	if err != nil {
		return nil, warn, fmt.Errorf("read %s: %w", w.Path, err)
	}
	return b, warn, nil
}
