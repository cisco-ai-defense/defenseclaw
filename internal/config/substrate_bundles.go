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
	"fmt"
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
	// OCI pulls stage bundles from an OCI registry by digest (GAP-0437,
	// Preview). Off by default: it is new egress from the controller.
	OCI SubstrateBundleOCIConfig `mapstructure:"oci" yaml:"oci,omitempty"`
}

// SubstrateBundleOCIConfig is substrate.bundles.oci.
type SubstrateBundleOCIConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// CredentialsFile is a mounted kubernetes.io/dockerconfigjson Secret;
	// empty pulls anonymously.
	CredentialsFile string `mapstructure:"credentials_file" yaml:"credentials_file,omitempty"`
	// CAFile is a PEM bundle trusted besides the system roots (a private
	// registry CA).
	CAFile string `mapstructure:"ca_file" yaml:"ca_file,omitempty"`
	// AuthHosts are the hosts a registry may name as its token realm besides
	// itself (auth.docker.io for Docker Hub); a realm on any other host is
	// refused, so registry credentials never go there (GAP-0950).
	AuthHosts []string `mapstructure:"auth_hosts" yaml:"auth_hosts,omitempty"`
	// Timeout bounds one pull (token, manifest and layer).
	Timeout string `mapstructure:"timeout" yaml:"timeout,omitempty"`
	// Stages are the stages whose bundle comes from a registry.
	Stages []SubstrateBundleOCIStage `mapstructure:"stages" yaml:"stages,omitempty"`
}

// SubstrateBundleOCIStage is one stage pulled from a registry.
type SubstrateBundleOCIStage struct {
	Stage string `mapstructure:"stage" yaml:"stage"`
	// Ref is host/repository@sha256:<64 hex>; tags are refused.
	Ref string `mapstructure:"ref" yaml:"ref"`
	// Atespaces of the stage; empty for the stage "all".
	Atespaces []string `mapstructure:"atespaces" yaml:"atespaces,omitempty"`
}

// DefaultSubstrateBundleOCITimeout bounds one OCI pull.
const DefaultSubstrateBundleOCITimeout = 30 * time.Second

// EffectiveTimeout is Timeout or 30 s.
func (o SubstrateBundleOCIConfig) EffectiveTimeout() time.Duration {
	return durationOr(o.Timeout, DefaultSubstrateBundleOCITimeout)
}

var (
	// SubstrateOCIDigestRe is the only digest form accepted.
	SubstrateOCIDigestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	substrateOCIHostRe   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)
	substrateOCIRepoRe   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
)

// ParseSubstrateOCIRef splits host/repository@sha256:<hex>. The host is
// explicit (no default registry) and a tag is refused: only a digest pins
// the content.
func ParseSubstrateOCIRef(ref string) (host, repo, digest string, err error) {
	name, digest, ok := strings.Cut(strings.TrimSpace(ref), "@")
	if !ok {
		return "", "", "", fmt.Errorf("%q is not pinned by digest (host/repository@sha256:<64 hex>; tags are not trusted)", ref)
	}
	if !SubstrateOCIDigestRe.MatchString(digest) {
		return "", "", "", fmt.Errorf("%q: digest must be sha256:<64 lowercase hex>", ref)
	}
	host, repo, ok = strings.Cut(name, "/")
	if !ok || !substrateOCIHostRe.MatchString(host) || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return "", "", "", fmt.Errorf("%q must start with an explicit registry host", ref)
	}
	if strings.Contains(repo, ":") {
		return "", "", "", fmt.Errorf("%q names a tag; use only the digest", ref)
	}
	if len(repo) > 255 || !substrateOCIRepoRe.MatchString(repo) {
		return "", "", "", fmt.Errorf("%q: %q is not a repository name", ref, repo)
	}
	return host, repo, digest, nil
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
	b.OCI.validate(bad)
}

func (o SubstrateBundleOCIConfig) validate(bad func(key, format string, a ...any)) {
	for key, f := range map[string]string{"credentials_file": o.CredentialsFile, "ca_file": o.CAFile} {
		if f = strings.TrimSpace(f); f != "" && !filepath.IsAbs(f) {
			bad("bundles.oci."+key, "%q must be an absolute path", f)
		}
	}
	if len(o.AuthHosts) > 16 {
		bad("bundles.oci.auth_hosts", "at most 16 hosts")
	}
	for i, h := range o.AuthHosts {
		if !substrateOCIHostRe.MatchString(h) || !strings.Contains(h, ".") {
			bad(fmt.Sprintf("bundles.oci.auth_hosts[%d]", i), "%q must be a host name (host or host:port)", h)
		}
	}
	if v := strings.TrimSpace(o.Timeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 5*time.Second || d > 2*time.Minute {
			bad("bundles.oci.timeout", "%q must be a duration from 5s to 2m", o.Timeout)
		}
	}
	if len(o.Stages) > 8 {
		bad("bundles.oci.stages", "at most 8 stages (the bundle stage limit)")
	}
	seen := map[string]bool{}
	for i, st := range o.Stages {
		key := fmt.Sprintf("bundles.oci.stages[%d]", i)
		if st.Stage == "" || seen[st.Stage] {
			bad(key+".stage", "%q must be set and unique", st.Stage)
		}
		seen[st.Stage] = true
		if _, _, _, err := ParseSubstrateOCIRef(st.Ref); err != nil {
			bad(key+".ref", "%v", err)
		}
	}
	if o.Enabled && len(o.Stages) == 0 {
		bad("bundles.oci.stages", "oci is enabled but lists no stage")
	}
}
