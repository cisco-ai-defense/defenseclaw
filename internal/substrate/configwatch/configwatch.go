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

// Package configwatch is how the Substrate code of a running component (the
// controller, the leader, and the gateway's Substrate settings) sees a
// config.yaml change (GAP-0276). The gateway's guardrail (hook and /llm
// modes, rules, profiles) does not follow it: the gateway's config manager
// reloads the mounted file, on a directory mount when the kubelet swaps its
// ..data link (GAP-0579), on a managed subPath mount at the pod's restart
// (GAP-0590). Every component used to load config.yaml
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
	// Load decodes a source (LoadSource).
	Load func(path string, raw []byte) (*config.Config, error)
	Now  func() time.Time

	// mu guards the fields below and is never held across a read of the
	// source, so Current never waits on the API server (GAP-0296).
	mu       sync.Mutex
	cur      *config.Config
	digest   string
	readAt   time.Time
	reading  bool
	badHash  string
	fetchErr string
	// gen counts the sources put in force (0 = boot): Change.Gen.
	gen uint64
	// apiOK: the ConfigMap read has answered at least once. From then on
	// a failed or empty read keeps the config in force and never falls
	// back to the mounted file, which a managed subPath mount never
	// updates: a tightening must not revert on an API blip (GAP-0293).
	apiOK bool
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
	// Gen is the generation of Config: 0 for the boot config, one more for
	// each source put in force. A caller holding a Change older than the
	// one it applied must not apply it (GAP-0305).
	Gen uint64
	// Refused is set once per source that does not load; the last good
	// config stays in force.
	Refused error
	// FetchWarning is set once when the API read fails and the file is
	// used instead (and again if the reason changes).
	FetchWarning string
}

// Refresh reads the source if Interval has passed since the last read and
// loads it if its digest changed. A Refresh while another one reads the
// source returns the config in force at once.
func (w *Watcher) Refresh(ctx context.Context) Change {
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	w.mu.Lock()
	out := Change{Config: w.cur, Digest: w.digest, Gen: w.gen}
	t := now()
	if w.reading || (!w.readAt.IsZero() && t.Sub(w.readAt) < interval) {
		w.mu.Unlock()
		return out
	}
	w.readAt, w.reading = t, true
	apiOK := w.apiOK
	w.mu.Unlock()

	raw, answered, warn, err := w.read(ctx, apiOK)
	var cfg *config.Config
	var loadErr error
	d := ""
	if err == nil && raw != nil {
		d = Digest(raw)
		w.mu.Lock()
		same := d == w.digest || d == w.badHash
		cur := w.cur
		w.mu.Unlock()
		if !same {
			cfg, loadErr = w.loadCandidate(cur, raw)
			if loadErr == nil && cfg != nil && !cfg.Substrate.Enabled {
				loadErr = errors.New("substrate.enabled is false")
			}
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.reading = false
	if answered {
		w.apiOK = true
	}
	out = Change{Config: w.cur, Digest: w.digest, Gen: w.gen}
	if warn != w.fetchErr {
		w.fetchErr = warn
		out.FetchWarning = warn
	}
	switch {
	case err != nil:
		// Nothing readable: keep the config in force (the next read tries
		// again). Reported like a source that does not load, once.
		if w.badHash != "read:"+err.Error() {
			w.badHash = "read:" + err.Error()
			out.Refused = err
		}
		return out
	case raw == nil:
		// The API answered before and failed now: keep the config in force.
		return out
	case d == w.digest:
		w.badHash = ""
		return out
	case d == w.badHash:
		return out
	case cfg == nil && loadErr == nil:
		// Another Refresh applied a change while this one loaded.
		return out
	}
	if loadErr == nil {
		if reason, rerr := config.LiveReloadRefusal(w.cur, cfg); rerr != nil {
			loadErr = liveRefusal(reason, rerr)
		}
	}
	if loadErr != nil {
		w.badHash = d
		out.Refused = fmt.Errorf("config.yaml %s is refused, %s stays in force: %w", d, w.digest, loadErr)
		return out
	}
	w.badHash = ""
	out.Previous, out.Changed = w.digest, true
	w.gen++
	w.cur, w.digest = cfg, d
	out.Config, out.Digest, out.Gen = cfg, d, w.gen
	return out
}

// LoadSource decodes a config.yaml source the way a component's start does:
// the v8 schema pass first, then the runtime loader. Without the schema pass
// a key the schema does not declare (a misspelling such as egres:) was put
// in force live, its intended change lost and no alert raised, while the
// next pod start refused the same source and crash-looped (GAP-0324).
func LoadSource(path string, raw []byte) (*config.Config, error) {
	if err := config.ValidateV8SchemaBytes(path, raw); err != nil {
		return nil, err
	}
	return config.LoadRuntimeV8CandidateFromBytes(path, raw)
}

// loadCandidate decodes a changed source with Load (LoadSource). A change of
// deployment_mode is refused for that reason before the load: the loader's
// managed trust check on the mounted path answers first, and on a ConfigMap
// mount it named a symlink instead of the mode change (GAP-0323).
func (w *Watcher) loadCandidate(cur *config.Config, raw []byte) (*config.Config, error) {
	if reason, err := config.LiveReloadSourceRefusal(cur, raw); err != nil {
		return nil, liveRefusal(reason, err)
	}
	load := w.Load
	if load == nil {
		load = LoadSource
	}
	return load(w.Path, raw)
}

// liveRefusal is the refusal of a change no running component takes live.
func liveRefusal(reason string, err error) error {
	return fmt.Errorf("%s: %w; it applies only when the pods restart with it (helm upgrade)", reason, err)
}

// read returns the source: the ConfigMap, else the mounted file. answered
// is set when the ConfigMap read answered. Once it has (apiOK), a failed or
// empty read returns no source, so the config in force stays (GAP-0293);
// before that, and with no ConfigMap read configured, the mounted file is
// the source. warn names why the ConfigMap was not used.
func (w *Watcher) read(ctx context.Context, apiOK bool) (raw []byte, answered bool, warn string, err error) {
	if w.Fetch != nil {
		b, found, ferr := w.Fetch(ctx)
		switch {
		case ferr == nil && found:
			return b, true, "", nil
		case ferr == nil && apiOK:
			return nil, false, "the defenseclaw-config ConfigMap or its config.yaml key is missing: the config in force stays", nil
		case ferr == nil:
			warn = "the defenseclaw-config ConfigMap or its config.yaml key is missing: reading the mounted file"
		case apiOK:
			return nil, false, "cannot read the defenseclaw-config ConfigMap (" + ferr.Error() + "): the config in force stays until it answers again", nil
		default:
			warn = "cannot read the defenseclaw-config ConfigMap (" + ferr.Error() + "): reading the mounted file, which the kubelet updates on its own schedule"
		}
	}
	b, err := os.ReadFile(w.Path)
	if err != nil {
		return nil, false, warn, fmt.Errorf("read %s: %w", w.Path, err)
	}
	return b, false, warn, nil
}
