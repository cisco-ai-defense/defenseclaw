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
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// hermesManifestLoader reports the entrypoints the plugin scanner reads from
// manifests: a candidate path (slash-separated) mapped to the bytes read once
// by the caller. The scanner is the only reader of the manifest grammar (YAML
// and JSON, with every directive, tag, merge key and spelling it accepts), so
// this package never parses a manifest itself: a second reader of that
// grammar was a false block (a valid manifest called undecidable, every cache
// write rejecting an admission) or a protected allow (a declared entrypoint
// missed) for each spelling it did not know. An error means the scanner could
// not answer (it did not run, or its reply was not a complete list); the
// caller then falls back by policy (errHermesManifestFailOpen). A manifest the
// scanner refuses is not an error: it declares nothing, as in a scan.
type hermesManifestLoader func(manifests map[string][]byte) ([]string, error)

// errHermesManifestFailOpen marks a loader error under a policy that lets
// ordinary activity continue while the scanner cannot answer (the per-user
// default and permissive tiers, the same rule as a hook during an outage). The
// caller then binds the cache files that any string of the manifests resolves
// to (hermesManifestCandidates), not every cache file; without the mark
// (strict, managed) every cache file counts as declared.
var errHermesManifestFailOpen = errors.New("shipped Hermes plugin manifest reader unavailable, failing open")

const (
	// hermesManifestCacheMax bounds the remembered answers. Past it the
	// cache starts over.
	hermesManifestCacheMax = 256
	// hermesManifestFailureTTL is how long a failed answer is remembered, so
	// a scanner that cannot run is not started for every file event.
	hermesManifestFailureTTL = 30 * time.Second
)

type hermesManifestAnswer struct {
	entrypoints []string
	err         error
	at          time.Time
}

// hermesManifestCache remembers what the plugin scanner answered, by the
// scanner that was asked and the manifest bytes.
type hermesManifestCache struct {
	mu      sync.Mutex
	answers map[string]hermesManifestAnswer
	warned  map[string]bool
}

func newHermesManifestCache() *hermesManifestCache {
	return &hermesManifestCache{answers: map[string]hermesManifestAnswer{}, warned: map[string]bool{}}
}

// executableStamp names the state of the executable ps runs: the path it
// resolves to and the digest of its bytes. File metadata cannot name the
// state: a file rewritten in place keeps its identity, and a writer can keep
// its size and modification time as well, so an answer is reused only for the
// same bytes. The launcher is a small shim, so reading it is cheap.
func (c *hermesManifestCache) executableStamp(ps *scanner.PluginScanner) string {
	binary := strings.TrimSpace(ps.BinaryPath)
	if binary == "" {
		binary = "defenseclaw"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return binary + ":unresolved"
	}
	file, err := os.Open(resolved)
	if err != nil {
		return resolved + ":unreadable"
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return resolved + ":unreadable"
	}
	return resolved + ":" + hex.EncodeToString(digest.Sum(nil))
}

// loader asks ps, once per distinct scanner and set of manifest bytes: the
// answer is a function of those two alone, so it is remembered by their
// digests, and a changed manifest or a changed scanner (a configuration
// reload that points at another launcher, or the executable at the same path
// replaced) is asked again. A failed answer is remembered briefly.
func (c *hermesManifestCache) loader(ps *scanner.PluginScanner) hermesManifestLoader {
	settings := hermesScannerSettings(ps)
	return func(manifests map[string][]byte) ([]string, error) {
		stamp := c.executableStamp(ps)
		key := settings + ":" + stamp + ":" + hermesManifestKey(manifests)
		c.mu.Lock()
		cached, ok := c.answers[key]
		c.mu.Unlock()
		if !ok || (cached.err != nil && time.Since(cached.at) >= hermesManifestFailureTTL) {
			entrypoints, err := ps.DeclaredEntrypoints(context.Background(), manifests)
			cached = hermesManifestAnswer{entrypoints: entrypoints, err: err, at: time.Now()}
			// An executable that changed while it ran gave an answer for
			// neither state: it is not remembered.
			if c.executableStamp(ps) == stamp {
				c.mu.Lock()
				if len(c.answers) >= hermesManifestCacheMax {
					clear(c.answers)
				}
				c.answers[key] = cached
				c.mu.Unlock()
			}
		}
		return cached.entrypoints, cached.err
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
		fmt.Fprintf(os.Stderr, "[watcher] the plugin scanner could not read a shipped Hermes plugin manifest, so only the cache files a string of the manifest resolves to are treated as declared: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[watcher] the plugin scanner could not read a shipped Hermes plugin manifest, so every cache file of that plugin is treated as declared: %v\n", err)
}

// hermesScannerSettings is a digest of everything that selects and configures
// the scanner process (launcher path, policy, profile, judge settings), so an
// answer is never reused for another configuration. The executable is named
// by executableStamp.
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
// the answers are shared across calls, and a failure falls back by policy
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
