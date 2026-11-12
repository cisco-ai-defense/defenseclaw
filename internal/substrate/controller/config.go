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

package controller

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// SettingsFromConfig builds the render settings from the substrate section.
// Provider hosts are the configured custom LLM providers' domains and base
// URL hosts, on top of render's built-in list.
func SettingsFromConfig(cfg *config.Config) render.Settings {
	s := cfg.Substrate
	var providers []string
	for _, p := range cfg.LLMProviders.Custom {
		providers = append(providers, p.Domains...)
		if u, err := url.Parse(p.BaseURL); err == nil && u.Hostname() != "" {
			providers = append(providers, u.Hostname())
		}
	}
	return render.Settings{
		ActorService:         s.EffectiveActorService(),
		AdminService:         s.EffectiveAdminService(),
		Audience:             s.EffectiveAudience(),
		TokenLifetimeSeconds: s.EffectiveTokenLifetime(),
		AllowHosts:           s.Egress.Allow,
		EcosystemPacks:       s.EffectiveEcosystemPacks(),
		MCPHosts:             s.Extproc.MCPHosts,
		RegistryHosts:        s.Egress.Registries,
		PassthroughFor:       s.AllowPassthroughFor,
		ProviderHosts:        providers,
	}
}

// SecretsFromConfig converts substrate.secrets.
func SecretsFromConfig(cfg *config.Config) []render.Secret {
	out := make([]render.Secret, 0, len(cfg.Substrate.Secrets))
	for _, s := range cfg.Substrate.Secrets {
		scope := s.Scope
		if scope == "" {
			scope = egressspec.ScopeShared
		}
		out = append(out, render.Secret{Name: s.Name, Source: s.Source, Hosts: s.Inject.Hosts, Header: s.Inject.Header,
			Prefix: s.Inject.Prefix, Scope: scope, Profiles: s.Profiles})
	}
	return out
}

// LauncherSet is the set of launcher atespaces.
func LauncherSet(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for _, list := range cfg.Substrate.LauncherAtespaces {
		for _, ns := range list {
			out[ns] = true
		}
	}
	return out
}

// AtespaceRule assigns a profile to atespaces outside the launcher ones.
// An exact name always matches; a glob matches only atespaces DefenseClaw
// created or lists (E3), and a glob that would match a foreign atespace
// warns instead.
type AtespaceRule struct {
	Atespaces []string
	Profile   string
}

// ConfigResolver resolves profiles from config: a launcher atespace takes
// the profile it is listed under (or the registration's own profile), other
// atespaces take the first matching AtespaceRule. Every profile's sandbox
// section is tightened over substrate.admin (TightenOpenShellAdmin).
type ConfigResolver struct {
	Config *config.Config
	Rules  []AtespaceRule

	mu     sync.Mutex
	warned map[string]bool
}

var _ ProfileResolver = (*ConfigResolver)(nil)

// Resolve implements ProfileResolver.
func (r *ConfigResolver) Resolve(reg Registration, launcher bool) (Resolution, error) {
	sub := r.Config.Substrate
	name := ""
	var warnings []string
	if launcher {
		name = reg.Profile
		if name == "" {
			name, _ = sub.LauncherAtespace(reg.Atespace)
		}
	} else {
		owned := LauncherSet(r.Config)
		for _, rule := range r.Rules {
			if m, warn := MatchAtespace(rule.Atespaces, reg.Atespace, owned[reg.Atespace]); m {
				name = rule.Profile
				break
			} else if warn != "" && r.warnOnce(reg.Atespace+"|"+warn) {
				warnings = append(warnings, warn)
			}
		}
	}
	if name == "" {
		return Resolution{Warnings: warnings}, nil
	}
	floor := sub.Admin
	var overlay *config.OpenShellAdminConfig
	if p, ok := r.Config.Guardrail.Profiles[name]; ok {
		overlay = p.Sandbox
	} else if name != "default" {
		return Resolution{}, fmt.Errorf("profile %q is not defined in guardrail.profiles", name)
	}
	eff, err := config.TightenOpenShellAdmin(floor, overlay)
	if err != nil {
		return Resolution{}, fmt.Errorf("profile %q: %w", name, err)
	}
	res := Resolution{Managed: true, Warnings: warnings, Profile: render.Profile{
		Name: name, AllowOnly: eff.EgressAllowOnly, Block: eff.EgressBlock, AllowedCredentials: eff.AllowedCredentials,
	}}
	if eff.Allowed != nil && !*eff.Allowed {
		res.Refuse = "profile " + name + " does not allow sandboxes"
	}
	return res, nil
}

func (r *ConfigResolver) warnOnce(k string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.warned == nil {
		r.warned = map[string]bool{}
	}
	if r.warned[k] {
		return false
	}
	r.warned[k] = true
	return true
}

// MatchAtespace applies E3: an exact name matches; a glob matches only an
// owned atespace and otherwise returns a warning.
func MatchAtespace(patterns []string, atespace string, owned bool) (bool, string) {
	warn := ""
	for _, p := range patterns {
		if p == atespace {
			return true, ""
		}
		if !strings.ContainsAny(p, "*?[") {
			continue
		}
		if ok, err := path.Match(p, atespace); err == nil && ok {
			if owned {
				return true, ""
			}
			warn = fmt.Sprintf("atespace %s matches the glob %q but DefenseClaw neither created nor lists it; the profile does not apply (list it by name)", atespace, p)
		}
	}
	return false, warn
}

// MemoryRegistry is an in-process Registry.
type MemoryRegistry struct {
	mu sync.Mutex
	m  map[string]Registration
}

// NewMemoryRegistry returns an empty MemoryRegistry.
func NewMemoryRegistry() *MemoryRegistry { return &MemoryRegistry{m: map[string]Registration{}} }

func (m *MemoryRegistry) Get(_ context.Context, atespace, uid string) (Registration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.m[atespace+"/"+uid]
	r.Approved = slices.Clone(r.Approved)
	return r, ok, nil
}

func (m *MemoryRegistry) Put(_ context.Context, r Registration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Approved = slices.Clone(r.Approved)
	m.m[r.Atespace+"/"+r.UID] = r
	return nil
}

// All returns every registration sorted by key (tests, inventory).
func (m *MemoryRegistry) All() []Registration {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.m))
	for k := range m.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Registration, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.m[k])
	}
	return out
}
