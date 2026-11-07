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

package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// hermesManifestLoader reports the entrypoints the plugin scanner reads from
// manifests: a candidate path (slash-separated) mapped to the bytes read once
// by the caller. The scanner is the reader of the manifest grammar, and while
// it answers nothing else is asked. An error means the scanner could not
// answer (it did not run, or its reply was not a complete list); the caller
// then falls back by policy: every cache file counts as declared, or, under
// errHermesManifestFailOpen, the entrypoints a parsed tree of the manifests
// declares (hermesManifestCandidates). A manifest the scanner refuses is not
// an error: it declares nothing, as in a scan.
type hermesManifestLoader func(manifests map[string][]byte) ([]string, error)

// errHermesManifestFailOpen marks a loader error under a policy that lets
// ordinary activity continue while the scanner cannot answer (the per-user
// default and permissive tiers, the same rule as a hook during an outage). The
// caller then binds the cache files that the entrypoints read from the
// manifests resolve to (hermesManifestCandidates), not every cache file; without the mark
// (strict, managed) every cache file counts as declared.
var errHermesManifestFailOpen = errors.New("shipped Hermes plugin manifest reader unavailable, failing open")

const (
	// hermesManifestCacheMax bounds the remembered failures. Past it the
	// cache starts over.
	hermesManifestCacheMax = 256
	// hermesManifestFailureTTL is how long a failed answer is remembered, so
	// a scanner that cannot run is not started for every file event.
	hermesManifestFailureTTL = 30 * time.Second
)

// hermesManifestFailure is a remembered failed answer.
type hermesManifestFailure struct {
	err error
	at  time.Time
}

// hermesManifestCache remembers when the plugin scanner could not answer, so
// a scanner that cannot run is not started for every file event. It never
// remembers an answer: what the scanner declares depends on the scanner
// itself, its modules, data and interpreter, which no digest of the launcher
// names, so a remembered answer could outlive a change to any of them and
// leave a protected entrypoint unbound. Each snapshot that needs the
// declared entrypoints asks the scanner, once per plugin.
type hermesManifestCache struct {
	mu       sync.Mutex
	failures map[string]hermesManifestFailure
	warned   map[string]bool
}

func newHermesManifestCache() *hermesManifestCache {
	return &hermesManifestCache{failures: map[string]hermesManifestFailure{}, warned: map[string]bool{}}
}

// loader asks ps for the entrypoints of the manifests, at each call. A
// failure is remembered briefly for the same scanner configuration and
// manifest bytes.
func (c *hermesManifestCache) loader(ps *scanner.PluginScanner) hermesManifestLoader {
	settings := hermesScannerSettings(ps)
	return func(manifests map[string][]byte) ([]string, error) {
		key := settings + ":" + hermesManifestKey(manifests)
		c.mu.Lock()
		failed, ok := c.failures[key]
		c.mu.Unlock()
		if ok && time.Since(failed.at) < hermesManifestFailureTTL {
			return nil, failed.err
		}
		entrypoints, err := ps.DeclaredEntrypoints(context.Background(), manifests)
		c.mu.Lock()
		defer c.mu.Unlock()
		if err == nil {
			delete(c.failures, key)
			return entrypoints, nil
		}
		if len(c.failures) >= hermesManifestCacheMax {
			clear(c.failures)
		}
		c.failures[key] = hermesManifestFailure{err: err, at: time.Now()}
		return nil, err
	}
}

// byPolicy marks a failure of base with errHermesManifestFailOpen when
// failOpen says the policy lets ordinary activity continue, and prints the
// warning once for each distinct failure and policy. It is the one place the
// policy is applied, so it holds for any loader. failOpen is read at each
// call, so a policy change applies at once; nil is closed.
func (c *hermesManifestCache) byPolicy(base hermesManifestLoader, failOpen func() bool) hermesManifestLoader {
	return func(manifests map[string][]byte) ([]string, error) {
		entrypoints, err := base(manifests)
		if err == nil {
			return entrypoints, nil
		}
		open := failOpen != nil && failOpen()
		c.warn(err, open)
		if open {
			return nil, fmt.Errorf("%w: %w", errHermesManifestFailOpen, err)
		}
		return nil, err
	}
}

// warn prints a failure once for each distinct text and policy.
func (c *hermesManifestCache) warn(err error, open bool) {
	text := fmt.Sprintf("%t:%s", open, err)
	c.mu.Lock()
	seen := c.warned[text]
	c.warned[text] = true
	c.mu.Unlock()
	if seen {
		return
	}
	if open {
		fmt.Fprintf(os.Stderr, "[watcher] the plugin scanner could not read a shipped Hermes plugin manifest, so only the cache files its declared entrypoints resolve to are treated as declared: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[watcher] the plugin scanner could not read a shipped Hermes plugin manifest, so every cache file of that plugin is treated as declared: %v\n", err)
}

// hermesScannerSettings is a digest of everything that selects and configures
// the scanner process (launcher path, policy, profile, judge settings), so a
// remembered failure is never reused for another configuration.
func hermesScannerSettings(ps *scanner.PluginScanner) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%+v", *ps)))
	return hex.EncodeToString(sum[:])
}

// hermesManifestKey is the digest of the names and bytes of manifests.
func hermesManifestKey(manifests map[string][]byte) string {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		fmt.Fprintf(digest, "%s\x00%d\x00", name, len(manifests[name]))
		_, _ = digest.Write(manifests[name])
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// manifestLoader is the loader this watcher asks. It is bound to the scanner
// the current configuration selects, at each call, because a scan reads the
// configuration at each event and the two must not disagree after a reload;
// failures are shared across calls, and a failure falls back by policy
// (byPolicy). A test may set hermesManifests.
func (w *InstallWatcher) manifestLoader() hermesManifestLoader {
	w.hermesManifestOnce.Do(func() { w.hermesManifestAnswers = newHermesManifestCache() })
	cfg := w.scanConfig()
	base := w.hermesManifests
	if base == nil {
		ps := scanner.NewPluginScanner(cfg.Scanners.PluginScanner)
		ps.LLM = cfg.ResolveLLM("scanners.plugin")
		base = w.hermesManifestAnswers.loader(ps)
	}
	return w.hermesManifestAnswers.byPolicy(base, func() bool { return hermesManifestFailsOpen(cfg) })
}

// hermesManifestFailsOpen reports whether a manifest reader outage lets
// ordinary activity continue: a per-user install, outside the strict tier,
// whose hook outage mode is open. A managed install and the strict tier are
// closed whatever mode was saved, so an explicit open there does not leave a
// named protected file unbound.
func hermesManifestFailsOpen(cfg *config.Config) bool {
	return cfg != nil && !managed.IsManagedEnterprise(cfg.DeploymentMode) &&
		cfg.HookPolicyTierForConnector("hermes") != config.HookPolicyTierStrict &&
		cfg.EffectiveHookOutageFailModeForConnector("hermes") == "open"
}
