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
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// Policy is a compiled profile: its egress Decider (feeds and host lists),
// URL and method rules, ask hosts and actor_secrets.
type Policy struct {
	Name           string
	UnattendedAsks string
	// Unattended is set by a registration-backed PolicySource for an
	// unattended actor; StaticPolicies cannot know and leaves it false.
	Unattended   bool
	decider      *egress.Decider
	urlRules     []urlRule
	askHosts     *hostMatcher
	actorSecrets []string
}

type urlRule struct {
	name       string
	hosts      *hostMatcher
	methods    map[string]bool
	pathPrefix string
	// foldedPrefix is pathPrefix in lower case, for deny and ask rules.
	foldedPrefix string
	action       string
}

// appliesTo reports whether the rule covers the host and the request's
// methods (its method and every method an override names, GAP-0046); its
// path prefix is matched separately, on the canonical path. A rule applies
// when any of the methods is listed, so an override can't dodge it.
func (r urlRule) appliesTo(host string, methods []string) bool {
	if _, ok := r.hosts.match(host); !ok {
		return false
	}
	if len(r.methods) == 0 {
		return true
	}
	for _, m := range methods {
		if r.methods[m] {
			return true
		}
	}
	return false
}

// matchesPath matches the canonical path, ignoring case, since some
// origins do (/ADMIN is /admin there) (GAP-0046).
func (r urlRule) matchesPath(canonical string) bool {
	// A refusal or an ask of "/admin/" covers "/admin" too: most origins
	// serve the directory there (or redirect to it).
	p := strings.ToLower(canonical)
	return pathHasPrefix(p, r.foldedPrefix) || (strings.HasSuffix(r.foldedPrefix, "/") && p+"/" == r.foldedPrefix)
}

// ruleMethods is every method a method-scoped URL rule names: under all of
// them, a rule that would refuse or ask for some override applies.
func (p *Policy) ruleMethods() []string {
	var out []string
	for _, r := range p.urlRules {
		for m := range r.methods {
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	slices.Sort(out)
	return out
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
		ur := urlRule{name: r.Name, hosts: hm, pathPrefix: prefix, foldedPrefix: strings.ToLower(prefix), action: r.Action}
		if len(r.Methods) > 0 {
			ur.methods = map[string]bool{}
			for _, m := range r.Methods {
				ur.methods[strings.ToUpper(strings.TrimSpace(m))] = true
			}
		}
		if ur.name == "" {
			// Unique per rule: an approval of an ask rule is keyed by its
			// name (GAP-0177), so two unnamed rules on a host never share one.
			ur.name = r.Action + ":" + strings.Join(r.Hosts, ",") + ":" + strings.Join(r.Methods, ",") + ":" + prefix
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

// StaticPolicies maps actors to the configured profiles: the profile the
// actor's registration names, else the profile whose atespaces match (see
// PolicyFor), else the default profile, else the feeds alone. An
// unregistered actor is matched by its atespace.
type StaticPolicies struct {
	profiles []*Policy
	globs    [][]string
	fallback *Policy
	byName   map[string]*Policy
	// unattended holds each policy's copy for unattended actors (GAP-0090).
	unattended map[*Policy]*Policy
}

// NewStaticPolicies compiles cfg's profiles.
func NewStaticPolicies(cfg *Config) (*StaticPolicies, error) {
	feeds, err := loadBlocklists(cfg.BlocklistFiles)
	if err != nil {
		return nil, err
	}
	s := &StaticPolicies{byName: map[string]*Policy{}, unattended: map[*Policy]*Policy{}}
	for _, p := range cfg.Profiles {
		pol, err := compilePolicy(cfg, p, feeds)
		if err != nil {
			return nil, err
		}
		s.profiles = append(s.profiles, pol)
		s.globs = append(s.globs, p.Atespaces)
		s.byName[p.Name] = pol
		if p.Name == cfg.DefaultProfile {
			s.fallback = pol
		}
	}
	if s.fallback == nil {
		if s.fallback, err = compilePolicy(cfg, ProfileConfig{Name: "default", UnattendedAsks: "deny"}, feeds); err != nil {
			return nil, err
		}
	}
	for _, pol := range append(append([]*Policy(nil), s.profiles...), s.fallback) {
		cp := *pol
		cp.Unattended = true
		s.unattended[pol] = &cp
	}
	return s, nil
}

// ErrAmbiguousProfile is an atespace more than one profile's globs match
// with no single exact name among them: the callout and the gateway (which
// uses the registration's profile) could pick different profiles, so the
// callout does not guess (GAP-0069) and the failure mode applies.
var ErrAmbiguousProfile = errors.New("extproc: more than one profile matches the atespace")

// PolicyFor implements PolicySource. The profile the actor's registration
// names wins, so the callout and the gateway apply the same one; an
// unregistered actor (or a profile this callout does not have) is matched
// by atespace, where a profile naming the atespace exactly wins over globs
// and two exact names, or two globs and no exact name, are
// ErrAmbiguousProfile. Configuration order never decides. An unattended
// actor gets its policy's unattended copy.
func (s *StaticPolicies) PolicyFor(_ context.Context, actor ActorRef) (*Policy, error) {
	pol, err := s.match(actor)
	if err != nil || !actor.Unattended {
		return pol, err
	}
	if u := s.unattended[pol]; u != nil {
		return u, nil
	}
	cp := *pol
	cp.Unattended = true
	return &cp, nil
}

func (s *StaticPolicies) match(actor ActorRef) (*Policy, error) {
	if pol := s.byName[actor.Profile]; actor.Profile != "" && pol != nil {
		return pol, nil
	}
	var exact, glob []int
	for i, globs := range s.globs {
		for _, g := range globs {
			if ok, _ := path.Match(g, actor.Atespace); ok {
				if g == actor.Atespace {
					exact = append(exact, i)
				} else {
					glob = append(glob, i)
				}
				break
			}
		}
	}
	switch {
	case len(exact) == 1:
		return s.profiles[exact[0]], nil
	case len(exact) > 1:
		return nil, ErrAmbiguousProfile
	case len(glob) == 1:
		return s.profiles[glob[0]], nil
	case len(glob) > 1:
		return nil, ErrAmbiguousProfile
	}
	return s.fallback, nil
}
