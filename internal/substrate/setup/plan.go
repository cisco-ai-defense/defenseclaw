// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// PlanSchema is the version of the hook plan the chart renders.
const PlanSchema = 1

// ChartPlan is plan.json of the chart's hook ConfigMap
// (templates/hooks/_hooks.tpl, dc.hookPlan): what every hook Job acts on.
type ChartPlan struct {
	Schema              int                `json:"schema"`
	Release             string             `json:"release"`
	Namespace           string             `json:"namespace"`
	ChartVersion        string             `json:"chart_version"`
	AppVersion          string             `json:"app_version"`
	StoreSchema         int                `json:"store_schema"`
	SubstrateNamespace  string             `json:"substrate_namespace"`
	SupportedVersions   string             `json:"supported_versions"`
	API                 PlanAPI            `json:"api"`
	ActorHost           string             `json:"actor_host"`
	LauncherAtespaces   []string           `json:"launcher_atespaces"`
	WritableAtespaces   []string           `json:"writable_atespaces"`
	Editors             []string           `json:"editors"`
	GlobalViewers       []string           `json:"global_viewers"`
	CredentialProvider  CredentialProvider `json:"credential_provider"`
	StoreStateConfigMap string             `json:"store_state_config_map"`
	// ControllerDeployment is stopped first by the uninstall (GAP-0056).
	ControllerDeployment string `json:"controller_deployment"`
	OwnerTokenSecret     string `json:"owner_token_secret"`
	DeleteOwnerToken     bool   `json:"delete_owner_token"`
	// AuthDelegatorBinding is the chart's ClusterRoleBinding of the gateway
	// ServiceAccount to system:auth-delegator, rendered only for the
	// Kubernetes sign-in (GAP-0153); "" when there is none. The uninstall
	// names it among what goes.
	AuthDelegatorBinding string `json:"auth_delegator_binding,omitempty"`
	// RelaySessionSecret is the relay session key Secret the relay-session
	// hook creates when absent (gateway.relaySessionSecret).
	RelaySessionSecret string `json:"relay_session_secret,omitempty"`
	// RelayCASecret is the relay CA Secret the relay-session hook creates
	// when absent (gateway.relayCASecret).
	RelayCASecret string `json:"relay_ca_secret,omitempty"`
}

// ChartEditors are the principals the chart's plan makes editors
// (dc.hookPlan "editors"): the gateway, controller and hooks
// ServiceAccounts of the release namespace.
func ChartEditors(namespace string) []string {
	return chartPrincipals(namespace, "gateway", "controller", "hooks")
}

// ChartGlobalViewers are the chart plan's global viewers (dc.hookPlan
// "global_viewers").
func ChartGlobalViewers(namespace string) []string {
	return chartPrincipals(namespace, "gateway", "controller", "callout", "hooks")
}

func chartPrincipals(namespace string, components ...string) []string {
	out := make([]string, len(components))
	for i, c := range components {
		out[i] = "system:serviceaccount:" + namespace + ":defenseclaw-" + c
	}
	return out
}

// PlanAPI is the ate-api-server address and token audience.
type PlanAPI struct {
	Address  string `json:"address"`
	Audience string `json:"audience"`
}

// CredentialProvider is the upstream Kubernetes credential provider the
// launcher atespaces are granted the secrets namespace in.
type CredentialProvider struct {
	Grant            bool   `json:"grant"`
	ConfigMap        string `json:"config_map"`
	Deployment       string `json:"deployment"`
	SecretsNamespace string `json:"secrets_namespace"`
	// UserSecretsNamespace is substrate.self_service_secrets.namespace (the
	// self-service values, dc-b-<person>); UserSecrets says whether
	// self-service secrets are on. On, the launcher atespaces are granted
	// it too; off, its grants are revoked. The chart always names it, so
	// turning self-service off revokes what turning it on granted.
	UserSecretsNamespace string `json:"user_secrets_namespace,omitempty"`
	UserSecrets          bool   `json:"user_secrets,omitempty"`
}

// grantedNamespaces are the namespaces the launcher atespaces are granted;
// revokedNamespaces the ones every grant of is removed (self-service off).
func (cp CredentialProvider) grantedNamespaces() (grant, revoke []string) {
	grant = []string{cp.SecretsNamespace}
	if u := cp.UserSecretsNamespace; u != "" && u != cp.SecretsNamespace {
		if cp.UserSecrets {
			grant = append(grant, u)
		} else {
			revoke = append(revoke, u)
		}
	}
	return grant, revoke
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ReadSource reads a file, or the environment variable NAME for "env:NAME"
// (the chart hook Jobs carry their plan and config in env).
func ReadSource(source string) ([]byte, error) {
	if name, ok := strings.CutPrefix(source, "env:"); ok {
		v, set := os.LookupEnv(name)
		if !set || v == "" {
			return nil, fmt.Errorf("%s is not set", name)
		}
		return []byte(v), nil
	}
	return os.ReadFile(source)
}

// LoadPlan reads and checks the plan from a file or "env:NAME".
func LoadPlan(source string) (ChartPlan, error) {
	raw, err := ReadSource(source)
	if err != nil {
		return ChartPlan{}, err
	}
	return ParsePlan(raw)
}

// ParsePlan decodes and checks a plan. Unknown members are refused: the
// plan and this binary come from the same chart release.
func ParsePlan(raw []byte) (ChartPlan, error) {
	var p ChartPlan
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("chart plan: %w", err)
	}
	return p, p.Validate()
}

// Validate checks the members every step relies on.
func (p ChartPlan) Validate() error {
	var errs []error
	if p.Schema != PlanSchema {
		errs = append(errs, fmt.Errorf("schema %d, this binary reads %d", p.Schema, PlanSchema))
	}
	if !dnsLabel.MatchString(p.Namespace) || !dnsLabel.MatchString(p.SubstrateNamespace) {
		errs = append(errs, errors.New("namespace and substrate_namespace must be DNS labels"))
	}
	if p.StoreSchema < 1 {
		errs = append(errs, errors.New("store_schema must be at least 1"))
	}
	if p.ActorHost == "" || p.API.Address == "" {
		errs = append(errs, errors.New("actor_host and api.address are required"))
	}
	for _, a := range append(append([]string{}, p.LauncherAtespaces...), p.WritableAtespaces...) {
		if !dnsLabel.MatchString(a) {
			errs = append(errs, fmt.Errorf("atespace %q is not a DNS label", a))
		}
	}
	if len(p.Editors) == 0 {
		errs = append(errs, errors.New("editors is empty"))
	}
	if p.CredentialProvider.Grant && (p.CredentialProvider.ConfigMap == "" || p.CredentialProvider.Deployment == "" ||
		!dnsLabel.MatchString(p.CredentialProvider.SecretsNamespace)) {
		errs = append(errs, errors.New("credential_provider needs config_map, deployment and a secrets_namespace"))
	}
	if p.CredentialProvider.SecretsNamespace == p.Namespace {
		errs = append(errs, errors.New("credential_provider.secrets_namespace must not be the DefenseClaw namespace (D14)"))
	}
	if u := p.CredentialProvider.UserSecretsNamespace; u != "" &&
		(!dnsLabel.MatchString(u) || u == p.Namespace || u == p.SubstrateNamespace || u == p.CredentialProvider.SecretsNamespace ||
			slices.Contains([]string{"default", "kube-system", "kube-public", "kube-node-lease"}, u) ||
			slices.Contains(p.LauncherAtespaces, u) || slices.Contains(p.WritableAtespaces, u)) {
		errs = append(errs, errors.New("credential_provider.user_secrets_namespace must be a namespace of its own: not the DefenseClaw, Substrate or admin secrets namespace, not a launcher or writable atespace, and not a Kubernetes system namespace"))
	}
	if p.StoreStateConfigMap == "" {
		errs = append(errs, errors.New("store_state_config_map is required"))
	}
	return errors.Join(errs...)
}
