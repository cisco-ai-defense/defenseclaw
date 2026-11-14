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

package config

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SubstrateBundlesConfig is substrate.bundles: signed policy bundles for the
// cluster (PLAN §9). A bundle carries guardrail profiles (their sandbox
// sections) and match.substrate assignments, is signed with the enterprise
// bundle format and verified against trust anchors from an admin-only
// Secret, and is applied to a stage: a list of atespaces, or every atespace.
type SubstrateBundlesConfig struct {
	// Enabled turns bundle mode on in the controller.
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// AnchorsFile is bundle-anchors.json, mounted from the admin-only
	// Secret.
	AnchorsFile string `mapstructure:"anchors_file" yaml:"anchors_file,omitempty"`
	// Inbox is the ConfigMap a GitOps tool writes signed bundles to
	// (<stage>.dcbundle and <stage>.atespaces); the controller applies what
	// verifies and records a receipt for every change.
	Inbox string `mapstructure:"inbox" yaml:"inbox,omitempty"`
	// RefreshInterval is how often the controller re-reads the bundle
	// state, the inbox and the anchors.
	RefreshInterval string `mapstructure:"refresh_interval" yaml:"refresh_interval,omitempty"`
}

// substrate.bundles defaults.
const (
	DefaultSubstrateBundleAnchors = "/etc/defenseclaw-substrate/bundle-anchors/bundle-anchors.json"
	DefaultSubstrateBundleInbox   = "defenseclaw-bundle-inbox"
	DefaultSubstrateBundleRefresh = 10 * time.Second
)

var substrateConfigMapNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// EffectiveAnchorsFile is AnchorsFile or the chart's mount path.
func (b SubstrateBundlesConfig) EffectiveAnchorsFile() string {
	return orDefault(b.AnchorsFile, DefaultSubstrateBundleAnchors)
}

// EffectiveInbox is Inbox or defenseclaw-bundle-inbox.
func (b SubstrateBundlesConfig) EffectiveInbox() string {
	return orDefault(b.Inbox, DefaultSubstrateBundleInbox)
}

// EffectiveRefreshInterval is RefreshInterval or 10 s.
func (b SubstrateBundlesConfig) EffectiveRefreshInterval() time.Duration {
	return durationOr(b.RefreshInterval, DefaultSubstrateBundleRefresh)
}

func (b SubstrateBundlesConfig) validate(bad func(key, format string, a ...any)) {
	if f := strings.TrimSpace(b.AnchorsFile); f != "" && !filepath.IsAbs(f) {
		bad("bundles.anchors_file", "%q must be an absolute path", b.AnchorsFile)
	}
	if n := strings.TrimSpace(b.Inbox); n != "" && !substrateConfigMapNameRe.MatchString(n) {
		bad("bundles.inbox", "%q is not a ConfigMap name", b.Inbox)
	}
	if v := strings.TrimSpace(b.RefreshInterval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second || d > 10*time.Minute {
			bad("bundles.refresh_interval", "%q must be a duration from 1s to 10m", b.RefreshInterval)
		}
	}
}
