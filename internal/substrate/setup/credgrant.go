// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

// NamespacePolicyKey is the key of the upstream Kubernetes credential
// provider's namespace policy ConfigMap (docs/guides/egress-credential-injection.md).
const NamespacePolicyKey = "namespace-policy.yaml"

type namespacePolicy struct {
	Policies []namespacePolicyEntry `yaml:"policies"`
	Rest     map[string]any         `yaml:",inline"`
}

type namespacePolicyEntry struct {
	Atespace          string         `yaml:"atespace"`
	AllowedNamespaces []string       `yaml:"allowedNamespaces"`
	Rest              map[string]any `yaml:",inline"`
}

// GrantChange is one atespace -> namespace grant added or removed.
type GrantChange struct {
	Atespace  string `json:"atespace"`
	Namespace string `json:"namespace"`
	Removed   bool   `json:"removed,omitempty"`
}

func parseNamespacePolicy(text string) (namespacePolicy, error) {
	var p namespacePolicy
	if err := yaml.Unmarshal([]byte(text), &p); err != nil {
		return p, fmt.Errorf("credential provider namespace policy: %w", err)
	}
	return p, nil
}

func (p namespacePolicy) encode() (string, error) {
	out, err := yaml.Marshal(p)
	return string(out), err
}

// GrantNamespace returns the namespace policy text with every atespace
// allowed to resolve Secrets in namespace, keeping every other entry.
func GrantNamespace(text string, atespaces []string, namespace string) (string, []GrantChange, error) {
	p, err := parseNamespacePolicy(text)
	if err != nil {
		return "", nil, err
	}
	var changes []GrantChange
	for _, a := range atespaces {
		i := slices.IndexFunc(p.Policies, func(e namespacePolicyEntry) bool { return e.Atespace == a })
		if i < 0 {
			p.Policies = append(p.Policies, namespacePolicyEntry{Atespace: a})
			i = len(p.Policies) - 1
		}
		if !slices.Contains(p.Policies[i].AllowedNamespaces, namespace) {
			p.Policies[i].AllowedNamespaces = append(p.Policies[i].AllowedNamespaces, namespace)
			changes = append(changes, GrantChange{Atespace: a, Namespace: namespace})
		}
	}
	if len(changes) == 0 {
		return text, nil, nil
	}
	out, err := p.encode()
	return out, changes, err
}

// RevokeNamespaceExcept removes namespace from the grants of every atespace
// not in keep (nil keep: every atespace), and an entry left with nothing.
func RevokeNamespaceExcept(text string, keep []string, namespace string) (string, []GrantChange, error) {
	p, err := parseNamespacePolicy(text)
	if err != nil {
		return "", nil, err
	}
	var changes []GrantChange
	kept := p.Policies[:0]
	for _, e := range p.Policies {
		if !slices.Contains(keep, e.Atespace) && slices.Contains(e.AllowedNamespaces, namespace) {
			e.AllowedNamespaces = slices.DeleteFunc(e.AllowedNamespaces, func(n string) bool { return n == namespace })
			changes = append(changes, GrantChange{Atespace: e.Atespace, Namespace: namespace, Removed: true})
			if len(e.AllowedNamespaces) == 0 && len(e.Rest) == 0 {
				continue
			}
		}
		kept = append(kept, e)
	}
	p.Policies = kept
	if len(changes) == 0 {
		return text, nil, nil
	}
	out, err := p.encode()
	return out, changes, err
}
