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

package extproc

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// Policy is a compiled profile: its egress Decider (feeds and host lists),
// URL and method rules, ask hosts and actor_secrets.
type Policy struct {
	Name           string
	UnattendedAsks string
	decider        *egress.Decider
	urlRules       []urlRule
	askHosts       *hostMatcher
	actorSecrets   []string
}

type urlRule struct {
	name       string
	hosts      *hostMatcher
	methods    map[string]bool
	pathPrefix string
	action     string
}

// appliesTo reports whether the rule covers the host and method; its path
// prefix is matched separately, on the canonical path.
func (r urlRule) appliesTo(host, method string) bool {
	if _, ok := r.hosts.match(host); !ok {
		return false
	}
	return len(r.methods) == 0 || r.methods[method]
}

// compilePolicy builds a Policy. The Decider runs in open mode: the
// EgressPolicy already limits the actor to its allowed hosts, so the
// callout adds the blocklist feeds and the profile's lists on top. The
// cluster domains are allow entries, so the guard's intranet rule (*.local)
// does not refuse in-cluster services the EgressPolicy opened; they are
// still subject to every block list.
func compilePolicy(cfg *Config, p ProfileConfig, blocklists []*egress.Feed) (*Policy, error) {
	allow := append([]string(nil), p.Egress.Allow...)
	for _, d := range cfg.ClusterDomains {
		allow = append(allow, "*."+strings.TrimPrefix(d, "*."))
	}
	dec, err := egress.NewDecider(egress.DeciderOptions{
		Mode:       egress.ModeOpen,
		Blocklists: blocklists,
		Allowlists: []*egress.Feed{},
		AdminBlock: p.Egress.AdminBlock,
		AllowOnly:  p.Egress.AllowOnly,
		Block:      p.Egress.Block,
		Allow:      allow,
	})
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", p.Name, err)
	}
	pol := &Policy{Name: p.Name, UnattendedAsks: p.UnattendedAsks, decider: dec, actorSecrets: p.ActorSecrets}
	if pol.askHosts, err = newHostMatcher(p.AskHosts); err != nil {
		return nil, err
	}
	for _, r := range p.URLRules {
		hm, err := newHostMatcher(r.Hosts)
		if err != nil {
			return nil, err
		}
		prefix := r.PathPrefix
		if prefix != "" {
			if prefix, err = canonicalPath(prefix); err != nil {
				return nil, fmt.Errorf("profile %s: url rule %q: path_prefix %q is ambiguous", p.Name, r.Name, r.PathPrefix)
			}
		}
		ur := urlRule{name: r.Name, hosts: hm, pathPrefix: prefix, action: r.Action}
		if len(r.Methods) > 0 {
			ur.methods = map[string]bool{}
			for _, m := range r.Methods {
				ur.methods[m] = true
			}
		}
		if ur.name == "" {
			ur.name = r.Action + ":" + strings.Join(r.Hosts, ",")
		}
		pol.urlRules = append(pol.urlRules, ur)
	}
	return pol, nil
}

// loadBlocklists reads the configured feed files; nil uses the built-in feed.
func loadBlocklists(files []string) ([]*egress.Feed, error) {
	if len(files) == 0 {
		return nil, nil
	}
	var out []*egress.Feed
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		feed, err := egress.ParseFeed(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if feed.Kind != egress.FeedKindBlocklist {
			return nil, fmt.Errorf("%s: feed kind %q, want %q", f, feed.Kind, egress.FeedKindBlocklist)
		}
		out = append(out, feed)
	}
	return out, nil
}

// StaticPolicies maps atespaces to the configured profiles: the first
// profile with a matching atespace glob, else the default profile, else the
// feeds alone. It stands in until registrations (A2/A3) name each actor's
// profile.
type StaticPolicies struct {
	profiles []*Policy
	globs    [][]string
	fallback *Policy
}

// NewStaticPolicies compiles cfg's profiles.
func NewStaticPolicies(cfg *Config) (*StaticPolicies, error) {
	feeds, err := loadBlocklists(cfg.BlocklistFiles)
	if err != nil {
		return nil, err
	}
	s := &StaticPolicies{}
	for _, p := range cfg.Profiles {
		pol, err := compilePolicy(cfg, p, feeds)
		if err != nil {
			return nil, err
		}
		s.profiles = append(s.profiles, pol)
		s.globs = append(s.globs, p.Atespaces)
		if p.Name == cfg.DefaultProfile {
			s.fallback = pol
		}
	}
	if s.fallback == nil {
		if s.fallback, err = compilePolicy(cfg, ProfileConfig{Name: "default", UnattendedAsks: "deny"}, feeds); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// PolicyFor implements PolicySource.
func (s *StaticPolicies) PolicyFor(_ context.Context, actor ActorRef) (*Policy, error) {
	for i, globs := range s.globs {
		for _, g := range globs {
			if ok, _ := path.Match(g, actor.Atespace); ok {
				return s.profiles[i], nil
			}
		}
	}
	return s.fallback, nil
}
