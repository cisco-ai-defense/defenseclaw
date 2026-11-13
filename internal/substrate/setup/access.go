// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The roles of Agent Substrate's OpenFGA model (docs/guides/authorization.md
// at v1.0.0). Global policies take owner and viewer; atespace policies also
// editor.
const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// Binding is one role of an access policy and its members ("user:<id>").
type Binding struct {
	Role    string   `json:"role" yaml:"role"`
	Members []string `json:"members" yaml:"members"`
}

// AccessPolicy is the access policy of one atespace, or the global one when
// Atespace is empty. UID and Version are the update preconditions.
type AccessPolicy struct {
	Atespace string    `json:"atespace,omitempty"`
	UID      string    `json:"uid,omitempty"`
	Version  int64     `json:"version,omitempty"`
	Bindings []Binding `json:"bindings"`
}

// Member is the access-policy member of principal.
func Member(principal string) string { return "user:" + principal }

func (p *AccessPolicy) binding(role string) *Binding {
	for i := range p.Bindings {
		if p.Bindings[i].Role == role {
			return &p.Bindings[i]
		}
	}
	p.Bindings = append(p.Bindings, Binding{Role: role})
	return &p.Bindings[len(p.Bindings)-1]
}

// Members returns the members holding role, from every binding of it.
func (p AccessPolicy) Members(role string) []string {
	var out []string
	for _, b := range p.Bindings {
		if b.Role == role {
			out = append(out, b.Members...)
		}
	}
	return out
}

// mergeRoles folds bindings of the same role into one, in first-seen
// order. The policy writers edit the first binding of a role, so a second
// one (written outside DefenseClaw) would keep its members out of their
// reach: a foreign editor of a launcher atespace would survive the
// bootstrap.
func mergeRoles(bindings []Binding) []Binding {
	var out []Binding
	for _, b := range bindings {
		i := slices.IndexFunc(out, func(o Binding) bool { return o.Role == b.Role })
		if i < 0 {
			out = append(out, Binding{Role: b.Role, Members: append([]string{}, b.Members...)})
			continue
		}
		for _, m := range b.Members {
			if !slices.Contains(out[i].Members, m) {
				out[i].Members = append(out[i].Members, m)
			}
		}
	}
	return out
}

func (p *AccessPolicy) normalize() {
	out := p.Bindings[:0]
	for _, b := range p.Bindings {
		slices.Sort(b.Members)
		b.Members = slices.Compact(b.Members)
		if len(b.Members) > 0 {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Binding) int { return strings.Compare(a.Role, b.Role) })
	p.Bindings = out
}

// PolicyChange is one member added to or removed from a role.
type PolicyChange struct {
	Atespace string `json:"atespace"`
	Role     string `json:"role"`
	Member   string `json:"member"`
	Removed  bool   `json:"removed,omitempty"`
}

func (c PolicyChange) String() string {
	scope := "global"
	if c.Atespace != "" {
		scope = "atespace " + c.Atespace
	}
	verb := "grant"
	if c.Removed {
		verb = "revoke"
	}
	return fmt.Sprintf("%s %s %s on %s", verb, c.Role, c.Member, scope)
}

// LauncherPolicy returns the access policy of launcher atespace from its
// current one (nil when it has none): DefenseClaw's principals are the only
// editors and owners, so only DefenseClaw creates, forks (tag and create),
// suspends, resumes and reverts actors there (D3, E2, E17). Other viewers
// are removed too: people see only their own actors, through DefenseClaw
// (own data only, GAP-0084).
func LauncherPolicy(atespace string, current *AccessPolicy, editors []string) (AccessPolicy, []PolicyChange) {
	next := AccessPolicy{Atespace: atespace}
	if current != nil {
		next = *current
		next.Atespace = atespace
		next.Bindings = slices.Clone(current.Bindings)
	}
	want := make([]string, 0, len(editors))
	for _, e := range editors {
		want = append(want, Member(e))
	}
	var changes []PolicyChange
	for _, role := range []string{RoleOwner, RoleEditor, RoleViewer} {
		b := next.binding(role)
		var keep []string
		for _, m := range b.Members {
			if role != RoleOwner && slices.Contains(want, m) {
				keep = append(keep, m)
				continue
			}
			changes = append(changes, PolicyChange{Atespace: atespace, Role: role, Member: m, Removed: true})
		}
		b.Members = keep
	}
	editorsBinding := next.binding(RoleEditor)
	for _, m := range want {
		if !slices.Contains(editorsBinding.Members, m) {
			editorsBinding.Members = append(editorsBinding.Members, m)
			changes = append(changes, PolicyChange{Atespace: atespace, Role: RoleEditor, Member: m})
		}
	}
	next.normalize()
	return next, changes
}

// GrantPolicy returns current with every principal holding role, keeping all
// other bindings: DefenseClaw's editor grant in a managed atespace, and its
// viewer grant on the global policy.
func GrantPolicy(atespace string, current *AccessPolicy, role string, principals []string) (AccessPolicy, []PolicyChange) {
	next := AccessPolicy{Atespace: atespace}
	if current != nil {
		next = *current
		next.Atespace = atespace
		next.Bindings = slices.Clone(current.Bindings)
	}
	b := next.binding(role)
	var changes []PolicyChange
	for _, p := range principals {
		if m := Member(p); !slices.Contains(b.Members, m) {
			b.Members = append(b.Members, m)
			changes = append(changes, PolicyChange{Atespace: atespace, Role: role, Member: m})
		}
	}
	next.normalize()
	return next, changes
}

// RevokePolicy returns current without principals in role.
func RevokePolicy(current AccessPolicy, role string, principals []string) (AccessPolicy, []PolicyChange) {
	next := current
	next.Bindings = slices.Clone(current.Bindings)
	b := next.binding(role)
	var changes []PolicyChange
	b.Members = slices.DeleteFunc(slices.Clone(b.Members), func(m string) bool {
		for _, p := range principals {
			if m == Member(p) {
				changes = append(changes, PolicyChange{Atespace: current.Atespace, Role: role, Member: m, Removed: true})
				return true
			}
		}
		return false
	})
	next.normalize()
	return next, changes
}

// accessPolicyDoc is the kubectl-ate access-policy manifest.
type accessPolicyDoc struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Bindings []Binding `yaml:"bindings"`
}

// AccessPolicyManifest is the policy as `kubectl ate create|update
// access-policy -f` reads it, for an admin applying it by hand.
func AccessPolicyManifest(p AccessPolicy) ([]byte, error) {
	var doc accessPolicyDoc
	doc.Metadata.Name = "default"
	doc.Bindings = p.Bindings
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PrintAccessPolicies writes the policies the bootstrap Job would write, as
// commands and manifests an admin who is a global owner can apply. Current
// policies are not known here, so the launcher policies are DefenseClaw's
// alone and the grants show DefenseClaw's members only: merge them into the
// current policy with `get ... -o yaml` first.
func PrintAccessPolicies(plan ChartPlan) (string, error) {
	var sb strings.Builder
	sb.WriteString("# DefenseClaw access policies for Agent Substrate. Apply as a global owner.\n")
	sb.WriteString("# 1. Global: add DefenseClaw as viewer (inventory, live actor checks).\n")
	sb.WriteString("#    kubectl ate get access-policy --global -o yaml > global.yaml\n")
	sb.WriteString("#    add these members to its viewer binding, then: kubectl ate update access-policy --global -f global.yaml\n")
	for _, v := range plan.GlobalViewers {
		sb.WriteString("#      - " + Member(v) + "\n")
	}
	for _, a := range plan.LauncherAtespaces {
		p, _ := LauncherPolicy(a, nil, plan.Editors)
		m, err := AccessPolicyManifest(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "---\n# Launcher atespace %s: only DefenseClaw edits (create, fork, suspend, resume).\n", a)
		fmt.Fprintf(&sb, "#   kubectl ate create atespace %s   (if it does not exist)\n", a)
		fmt.Fprintf(&sb, "#   kubectl ate create access-policy -a %s -f this-document.yaml\n", a)
		sb.Write(m)
	}
	for _, a := range plan.WritableAtespaces {
		if slices.Contains(plan.LauncherAtespaces, a) {
			continue
		}
		fmt.Fprintf(&sb, "---\n# Managed atespace %s: add DefenseClaw to the editor binding of its current policy.\n", a)
		for _, e := range plan.Editors {
			sb.WriteString("#      - " + Member(e) + "\n")
		}
	}
	return sb.String(), nil
}
