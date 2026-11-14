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
	mcp := make([]string, 0, len(s.Extproc.MCPHosts))
	for _, h := range s.Extproc.MCPHosts {
		mcp = append(mcp, config.MCPHostName(h))
	}
	return render.Settings{
		ActorService:         s.EffectiveActorService(),
		AdminService:         s.EffectiveAdminService(),
		Audience:             s.EffectiveAudience(),
		TokenLifetimeSeconds: s.EffectiveTokenLifetime(),
		AllowHosts:           s.Egress.Allow,
		EcosystemPacks:       s.EffectiveEcosystemPacks(),
		MCPHosts:             mcp,
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

// ConfigResolver resolves profiles from config. A launcher atespace takes
// the registration's profile or the one it is listed under. Any other actor
// takes every guardrail.profile_assignments entry whose match.substrate
// selects it (atespaces with E3 matching, templates, workloads; entries with
// host selectors never apply to actors): the first match names the profile
// and every match's sandbox section tightens it, so the strictest
// combination applies, as on hosts. Each is tightened over substrate.admin.
type ConfigResolver struct {
	Config *config.Config

	mu     sync.Mutex
	warned map[string]bool
}

var _ ProfileResolver = (*ConfigResolver)(nil)

// Resolve implements ProfileResolver.
func (r *ConfigResolver) Resolve(reg Registration, launcher bool) (Resolution, error) {
	sub := r.Config.Substrate
	var names, warnings []string
	if launcher {
		name := reg.Profile
		if name == "" {
			name, _ = sub.LauncherAtespace(reg.Atespace)
		}
		if name != "" {
			names = []string{name}
		}
	} else {
		owned := LauncherSet(r.Config)
		for _, a := range r.Config.Guardrail.ProfileAssignments {
			m := a.Match.Substrate
			if m.Empty() || !a.Match.Empty() {
				continue
			}
			ok, warn := substrateMatches(m, reg, owned[reg.Atespace])
			if warn != "" && r.warnOnce(reg.Atespace+"|"+warn) {
				warnings = append(warnings, warn)
			}
			if ok && !slices.Contains(names, a.Profile) {
				names = append(names, a.Profile)
			}
		}
	}
	if len(names) == 0 {
		return Resolution{Warnings: warnings}, nil
	}
	eff := sub.Admin
	for _, name := range names {
		var overlay *config.OpenShellAdminConfig
		if p, ok := r.Config.Guardrail.Profiles[name]; ok {
			overlay = p.Sandbox
		} else if name != "default" {
			return Resolution{}, fmt.Errorf("profile %q is not defined in guardrail.profiles", name)
		}
		var err error
		if eff, err = config.TightenOpenShellAdmin(eff, overlay); err != nil {
			return Resolution{}, fmt.Errorf("profile %q: %w", name, err)
		}
	}
	res := Resolution{Managed: true, Warnings: warnings, Profile: render.Profile{
		Name: names[0], AllowOnly: eff.EgressAllowOnly, Block: eff.EgressBlock, AllowedCredentials: eff.AllowedCredentials,
	}}
	if eff.Allowed != nil && !*eff.Allowed {
		res.Refuse = "profile " + strings.Join(names, "+") + " does not allow sandboxes"
	} else if !eff.AllowsRuntime(config.SandboxRuntimeSubstrate) {
		res.Refuse = "profile " + strings.Join(names, "+") + " runs agents only on " + strings.Join(eff.Runtimes, ", ") +
			", not on Agent Substrate (runtimes)"
	}
	res.SandboxClass = eff.SandboxClass
	if eff.IdleSuspendAfter != "" {
		d := eff.EffectiveIdleSuspendAfter(0)
		res.IdleSuspendAfter = &d
	}
	return res, nil
}

// ManagedAtespaces are the atespaces this config manages by name: the
// launcher ones and those listed exactly in a match.substrate.
func (r *ConfigResolver) ManagedAtespaces() []string {
	set := LauncherSet(r.Config)
	for _, a := range r.Config.Guardrail.ProfileAssignments {
		if m := a.Match.Substrate; !m.Empty() {
			for _, ns := range m.Atespaces {
				if !strings.ContainsAny(ns, "*?[") {
					set[ns] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

func substrateMatches(m *config.ProfileMatchSubstrate, reg Registration, owned bool) (bool, string) {
	warn := ""
	if len(m.Atespaces) > 0 {
		ok, w := MatchAtespace(m.Atespaces, reg.Atespace, owned)
		if !ok {
			return false, w
		}
	}
	if len(m.Templates) > 0 && !slices.ContainsFunc(m.Templates, func(p string) bool {
		ok, err := path.Match(p, reg.Template)
		return err == nil && ok
	}) {
		return false, warn
	}
	if len(m.Workloads) > 0 && (reg.Workload == "" || !slices.Contains(m.Workloads, reg.Workload)) {
		return false, warn
	}
	return true, ""
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
