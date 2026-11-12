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
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// hermesManifestLoader reports the entrypoints the plugin scanner reads from
// manifests: a candidate path (slash-separated) mapped to the bytes read once
// by the caller. The scanner is the only reader of the manifest grammar; no
// other parser stands in for it. An error means no answer is known (the
// scanner did not run or its reply was not a complete list, and no earlier
// answer exists for these manifest bytes); the caller then applies the outage
// rule: every cache file counts as declared, or, under errHermesManifestFailOpen,
// none does. A manifest the scanner refuses is not an error: it declares
// nothing, as in a scan.
type hermesManifestLoader func(manifests map[string][]byte) ([]string, error)

// errHermesManifestFailOpen marks a loader error under a policy that lets
// ordinary activity continue while the manifests are unknown (the per-user
// default and permissive tiers, the same rule as a hook during an outage).
// The caller then treats no cache file as declared and writes proceed, with a
// warning and an audit row naming the outage; without the mark (strict,
// managed) every cache file counts as declared and a write in the plugin
// folder is scanned.
var errHermesManifestFailOpen = errors.New("shipped Hermes plugin manifest reader unavailable, failing open")

// hermesManifestPolicy applies the outage rule to the answers of the plugin
// scanner:
//
//	(a) a scanner that answers is believed, and its answer is kept with the
//	    digest of the manifests it was given;
//	(b) when it cannot answer, the last kept answer for the same manifest
//	    digest is applied exactly;
//	(c) with no such answer the manifests are unknown: the per-user default
//	    and permissive tiers treat no cache file as declared, and strict and
//	    managed treat every cache file as declared. Each distinct outage is
//	    printed and audited once.
//
// No manifest is parsed outside the scanner, so what a manifest declares is
// never guessed.
type hermesManifestPolicy struct {
	mu     sync.Mutex
	warned map[string]bool
	store  *hermesAnswerStore
	audit  func(details string)
}

// newHermesManifestPolicy keeps answers in dataDir (in memory only when it is
// empty) and records outages through audit (nil records none).
func newHermesManifestPolicy(dataDir string, audit func(details string)) *hermesManifestPolicy {
	return &hermesManifestPolicy{warned: map[string]bool{}, store: newHermesAnswerStore(dataDir), audit: audit}
}

// hermesManifestsFrom is the loader that asks ps for the entrypoints of the
// manifests, at each call.
func hermesManifestsFrom(ps *scanner.PluginScanner) hermesManifestLoader {
	return func(manifests map[string][]byte) ([]string, error) {
		return ps.DeclaredEntrypoints(context.Background(), manifests)
	}
}

// byPolicy wraps base with the outage rule. failOpen says whether the policy
// lets ordinary activity continue; it is read at each call, so a policy change
// applies at once, and nil is closed.
func (c *hermesManifestPolicy) byPolicy(base hermesManifestLoader, failOpen func() bool) hermesManifestLoader {
	return func(manifests map[string][]byte) ([]string, error) {
		digest := hermesManifestDigest(manifests)
		entrypoints, err := base(manifests)
		if err == nil {
			if storeErr := c.store.remember(digest, entrypoints); storeErr != nil {
				c.note("store:"+storeErr.Error(), "could not keep the plugin scanner answer for a later outage: "+storeErr.Error())
			}
			return entrypoints, nil
		}
		if last, ok := c.store.recall(digest); ok {
			c.note("last:"+err.Error(), "the plugin scanner could not read a shipped Hermes plugin manifest, so its last answer for these manifest bytes is applied: "+err.Error())
			return last, nil
		}
		if failOpen != nil && failOpen() {
			c.note("open:"+err.Error(), "the plugin scanner could not read a shipped Hermes plugin manifest and has no earlier answer for it, so no cache file of that plugin is treated as declared: "+err.Error())
			return nil, fmt.Errorf("%w: %w", errHermesManifestFailOpen, err)
		}
		c.note("closed:"+err.Error(), "the plugin scanner could not read a shipped Hermes plugin manifest and has no earlier answer for it, so every cache file of that plugin is treated as declared: "+err.Error())
		return nil, err
	}
}

// note prints and audits a message once for each distinct key.
func (c *hermesManifestPolicy) note(key, message string) {
	c.mu.Lock()
	seen := c.warned[key]
	c.warned[key] = true
	c.mu.Unlock()
	if seen {
		return
	}
	fmt.Fprintf(os.Stderr, "[watcher] %s\n", message)
	if c.audit != nil {
		c.audit("reason=hermes plugin manifest reader outage: " + message)
	}
}

// manifestLoader is the loader this watcher asks. It is bound to the scanner
// the current configuration selects, at each call, because a scan reads the
// configuration at each event and the two must not disagree after a reload; a
// failure follows the outage rule (byPolicy). A test may set hermesManifests.
func (w *InstallWatcher) manifestLoader() hermesManifestLoader {
	cfg := w.scanConfig()
	w.hermesManifestOnce.Do(func() {
		var record func(string)
		if w.logger != nil {
			record = func(details string) {
				_ = w.logger.LogAction(string(audit.ActionInstallWarning), "hermes-plugin-manifest-reader", "type=plugin "+details)
			}
		}
		dataDir := ""
		if cfg != nil {
			dataDir = cfg.DataDir
		}
		w.hermesManifestPolicy = newHermesManifestPolicy(dataDir, record)
	})
	base := w.hermesManifests
	if base == nil {
		ps := scanner.NewPluginScanner(cfg.Scanners.PluginScanner)
		ps.LLM = cfg.ResolveLLM("scanners.plugin")
		base = hermesManifestsFrom(ps)
	}
	return w.hermesManifestPolicy.byPolicy(base, func() bool { return hermesManifestFailsOpen(cfg) })
}

// hermesManifestFailsOpen reports whether a manifest reader outage lets
// ordinary activity continue: a per-user install, outside the strict tier,
// whose hook outage mode is open. A managed install and the strict tier are
// closed whatever mode was saved.
func hermesManifestFailsOpen(cfg *config.Config) bool {
	return cfg != nil && !managed.IsManagedEnterprise(cfg.DeploymentMode) &&
		cfg.HookPolicyTierForConnector("hermes") != config.HookPolicyTierStrict &&
		cfg.EffectiveHookOutageFailModeForConnector("hermes") == "open"
}
