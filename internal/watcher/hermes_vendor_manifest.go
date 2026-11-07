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
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

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
// not answer; the caller then treats every cache file as declared, which
// scans more and never less. A manifest the scanner refuses is not an error:
// it declares nothing, as in a scan.
type hermesManifestLoader func(manifests map[string][]byte) ([]string, error)

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

// newHermesManifestLoader asks the plugin scanner, once per distinct set of
// manifest bytes: the answer is a function of those bytes alone, so it is
// remembered by their digest and a changed manifest is asked again. A failed
// answer is remembered briefly; a warning is printed once for each distinct
// failure.
func newHermesManifestLoader(ps *scanner.PluginScanner) hermesManifestLoader {
	var (
		mu     sync.Mutex
		cache  = map[string]hermesManifestAnswer{}
		warned = map[string]bool{}
	)
	return func(manifests map[string][]byte) ([]string, error) {
		key := hermesManifestKey(manifests)
		mu.Lock()
		if cached, ok := cache[key]; ok && (cached.err == nil || time.Since(cached.at) < hermesManifestFailureTTL) {
			mu.Unlock()
			return cached.entrypoints, cached.err
		}
		mu.Unlock()
		entrypoints, err := ps.DeclaredEntrypoints(context.Background(), manifests)
		mu.Lock()
		defer mu.Unlock()
		if len(cache) >= hermesManifestCacheMax {
			clear(cache)
		}
		cache[key] = hermesManifestAnswer{entrypoints: entrypoints, err: err, at: time.Now()}
		if err != nil && !warned[err.Error()] {
			warned[err.Error()] = true
			fmt.Fprintf(os.Stderr, "[watcher] the plugin scanner could not read a shipped Hermes plugin manifest, so every cache file of that plugin is treated as declared: %v\n", err)
		}
		return entrypoints, err
	}
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

// manifestLoader is the loader this watcher asks, made on first use from the
// configured plugin scanner unless a test set one.
func (w *InstallWatcher) manifestLoader() hermesManifestLoader {
	w.hermesManifestOnce.Do(func() {
		if w.hermesManifests == nil {
			w.hermesManifests = newHermesManifestLoader(scanner.NewPluginScanner(w.scanConfig().Scanners.PluginScanner))
		}
	})
	return w.hermesManifests
}
