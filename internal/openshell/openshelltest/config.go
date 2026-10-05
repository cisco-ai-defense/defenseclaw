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

package openshelltest

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

type configClient struct{ f *Fake }

var _ v1.ConfigInterface = (*configClient)(nil)

func (c *configClient) GetSandbox(ctx context.Context, workspace, sandboxName string) (*types.SandboxConfig, error) {
	if err := c.f.enter(MethodGetSandboxConfig); err != nil {
		return nil, err
	}
	if _, err := c.f.sdk.Sandboxes().Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	st := c.f.state(workspace, sandboxName)
	cfg := &types.SandboxConfig{
		Policy:         clonePolicy(st.policy),
		PolicyVersion:  st.policyVersion,
		ConfigRevision: st.configRev,
		PolicySource:   types.PolicySourceSandbox,
		Settings:       map[string]types.EffectiveSetting{},
	}
	if st.policy != nil {
		cfg.PolicyHash = policyHash(st.policy)
	}
	if g := c.f.activeGlobal(); g != nil {
		cfg.Policy = clonePolicy(g.Policy)
		cfg.PolicyHash = g.PolicyHash
		cfg.PolicySource = types.PolicySourceGlobal
		cfg.GlobalPolicyVersion = g.Version
	}
	for k, v := range c.f.globalSettings {
		cfg.Settings[k] = types.EffectiveSetting{Value: v, Scope: types.SettingScopeGlobal}
	}
	for k, v := range st.settings {
		if _, global := c.f.globalSettings[k]; !global {
			cfg.Settings[k] = types.EffectiveSetting{Value: v, Scope: types.SettingScopeSandbox}
		}
	}
	return cfg, nil
}

func (c *configClient) GetGateway(context.Context) (*types.GatewayConfig, error) {
	if err := c.f.enter(MethodGetGatewayConfig); err != nil {
		return nil, err
	}
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return &types.GatewayConfig{Settings: maps.Clone(c.f.globalSettings), SettingsRevision: c.f.globalSettingsRev}, nil
}

// Update mirrors the gateway's UpdateConfig rules: sandbox policy
// replacements may only change network_policies, merge operations are
// sandbox-scoped, sandbox-scoped setting deletes are rejected, and a
// non-zero ExpectedResourceVersion must match the sandbox.
func (c *configClient) Update(ctx context.Context, workspace string, u *types.ConfigUpdate) (*types.ConfigUpdateResult, error) {
	if err := c.f.enter(MethodUpdateConfig); err != nil {
		return nil, err
	}
	if u == nil {
		return nil, statusErr(types.ErrorInvalidArgument, "update must not be nil")
	}
	if u.Global {
		return c.updateGlobal(u)
	}
	if u.Name == "" {
		return nil, statusErr(types.ErrorInvalidArgument, "sandbox name is required for sandbox-scoped updates")
	}
	sb, err := c.f.sdk.Sandboxes().Get(ctx, workspace, u.Name)
	if err != nil {
		return nil, err
	}
	if u.ExpectedResourceVersion != 0 && u.ExpectedResourceVersion != sb.ResourceVersion {
		return nil, statusErr(types.ErrorConflict, "resource version %d does not match %d", u.ExpectedResourceVersion, sb.ResourceVersion)
	}
	ops := 0
	for _, set := range []bool{u.Policy != nil, len(u.MergeOperations) > 0, u.SettingKey != ""} {
		if set {
			ops++
		}
	}
	if ops != 1 {
		return nil, statusErr(types.ErrorInvalidArgument, "exactly one of policy, merge operations or a setting key is required")
	}

	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.activeGlobal() != nil && (u.Policy != nil || len(u.MergeOperations) > 0) {
		return nil, statusErr(types.ErrorConflict, "a gateway-global policy is active; sandbox policy changes are locked")
	}
	st := c.f.state(workspace, u.Name)
	res := &types.ConfigUpdateResult{Annotations: maps.Clone(u.Annotations)}
	switch {
	case u.SettingKey != "":
		if u.DeleteSetting {
			return nil, statusErr(types.ErrorInvalidArgument, "sandbox-scoped setting deletes are not supported")
		}
		if u.SettingValue == nil {
			return nil, statusErr(types.ErrorInvalidArgument, "setting value is required")
		}
		st.settings[u.SettingKey] = *u.SettingValue
		st.settingsRev++
		st.configRev++
		res.SettingsRevision = st.settingsRev
		res.Version = st.policyVersion
		return res, nil
	case u.Policy != nil:
		if st.createPolicy != nil && !sameStaticPolicy(st.createPolicy, u.Policy) {
			return nil, statusErr(types.ErrorInvalidArgument, "only network_policies may differ from the create-time policy")
		}
		next := clonePolicy(u.Policy)
		return c.commit(st, next, u.Annotations, res), nil
	default:
		next := clonePolicy(st.policy)
		if next == nil {
			next = &types.SandboxPolicy{Version: 1}
		}
		for _, op := range u.MergeOperations {
			if err := applyMerge(next, op); err != nil {
				return nil, err
			}
		}
		return c.commit(st, next, u.Annotations, res), nil
	}
}

// commit records a new sandbox policy revision; the caller holds mu.
func (c *configClient) commit(st *sandboxState, next *types.SandboxPolicy, annotations map[string]string, res *types.ConfigUpdateResult) *types.ConfigUpdateResult {
	for i := range st.revisions {
		if st.revisions[i].Status == types.PolicyLoadStatusLoaded {
			st.revisions[i].Status = types.PolicyLoadStatusSuperseded
		}
	}
	st.policyVersion++
	next.Version = st.policyVersion
	st.policy = next
	st.configRev++
	hash := policyHash(next)
	st.revisions = append(st.revisions, types.SandboxPolicyRevision{
		Version: st.policyVersion, PolicyHash: hash, Status: types.PolicyLoadStatusLoaded,
		CreatedAt: c.f.now(), LoadedAt: c.f.now(), Policy: clonePolicy(next), Provenance: maps.Clone(annotations),
	})
	res.Version = st.policyVersion
	res.PolicyHash = hash
	return res
}

func (c *configClient) updateGlobal(u *types.ConfigUpdate) (*types.ConfigUpdateResult, error) {
	if len(u.MergeOperations) > 0 {
		return nil, statusErr(types.ErrorInvalidArgument, "merge operations are sandbox-scoped")
	}
	if u.Policy != nil {
		c.f.SetGlobalPolicy(u.Policy)
		c.f.mu.Lock()
		defer c.f.mu.Unlock()
		g := c.f.activeGlobal()
		return &types.ConfigUpdateResult{Version: g.Version, PolicyHash: g.PolicyHash}, nil
	}
	if u.SettingKey == "" {
		return nil, statusErr(types.ErrorInvalidArgument, "a global update needs a policy or a setting key")
	}
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	res := &types.ConfigUpdateResult{}
	if u.DeleteSetting {
		_, existed := c.f.globalSettings[u.SettingKey]
		delete(c.f.globalSettings, u.SettingKey)
		res.Deleted = existed
	} else {
		if u.SettingValue == nil {
			return nil, statusErr(types.ErrorInvalidArgument, "setting value is required")
		}
		c.f.globalSettings[u.SettingKey] = *u.SettingValue
	}
	c.f.globalSettingsRev++
	res.SettingsRevision = c.f.globalSettingsRev
	return res, nil
}

// activeGlobal returns the loaded global revision; the caller holds mu.
func (f *Fake) activeGlobal() *types.SandboxPolicyRevision {
	for i := len(f.globalRevisions) - 1; i >= 0; i-- {
		if f.globalRevisions[i].Status == types.PolicyLoadStatusLoaded {
			return &f.globalRevisions[i]
		}
	}
	return nil
}

func sameStaticPolicy(a, b *types.SandboxPolicy) bool {
	return jsonEqual(a.Filesystem, b.Filesystem) && jsonEqual(a.Landlock, b.Landlock) && jsonEqual(a.Process, b.Process)
}

func jsonEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// applyMerge applies one merge operation the way the gateway documents
// them. AddRule merges endpoints and binaries into an existing rule of the
// same name.
func applyMerge(p *types.SandboxPolicy, op types.PolicyMergeOperation) error {
	if p.NetworkPolicies == nil {
		p.NetworkPolicies = map[string]types.NetworkPolicyRule{}
	}
	switch {
	case op.AddRule != nil:
		name := op.AddRule.RuleName
		if name == "" {
			return statusErr(types.ErrorInvalidArgument, "add_rule needs a rule name")
		}
		rule := *cloneRule(&op.AddRule.Rule)
		rule.Name = name
		if existing, ok := p.NetworkPolicies[name]; ok {
			for _, ep := range rule.Endpoints {
				if !slices.ContainsFunc(existing.Endpoints, func(e types.PolicyNetworkEndpoint) bool { return sameEndpoint(e, ep) }) {
					existing.Endpoints = append(existing.Endpoints, ep)
				}
			}
			for _, b := range rule.Binaries {
				if !slices.Contains(existing.Binaries, b) {
					existing.Binaries = append(existing.Binaries, b)
				}
			}
			rule = existing
		}
		p.NetworkPolicies[name] = rule
	case op.RemoveRule != nil:
		if _, ok := p.NetworkPolicies[op.RemoveRule.RuleName]; !ok {
			return statusErr(types.ErrorNotFound, "rule %q not found", op.RemoveRule.RuleName)
		}
		delete(p.NetworkPolicies, op.RemoveRule.RuleName)
	case op.RemoveEndpoint != nil:
		r := op.RemoveEndpoint
		rule, ok := p.NetworkPolicies[r.RuleName]
		if !ok {
			return statusErr(types.ErrorNotFound, "rule %q not found", r.RuleName)
		}
		before := len(rule.Endpoints)
		rule.Endpoints = slices.DeleteFunc(rule.Endpoints, func(e types.PolicyNetworkEndpoint) bool {
			return strings.EqualFold(e.Host, r.Host) && (r.Port == 0 || e.Port == r.Port || slices.Contains(e.Ports, r.Port))
		})
		if len(rule.Endpoints) == before {
			return statusErr(types.ErrorNotFound, "endpoint %s:%d not found in rule %q", r.Host, r.Port, r.RuleName)
		}
		if len(rule.Endpoints) == 0 {
			delete(p.NetworkPolicies, r.RuleName)
		} else {
			p.NetworkPolicies[r.RuleName] = rule
		}
	case op.RemoveBinary != nil:
		r := op.RemoveBinary
		rule, ok := p.NetworkPolicies[r.RuleName]
		if !ok {
			return statusErr(types.ErrorNotFound, "rule %q not found", r.RuleName)
		}
		rule.Binaries = slices.DeleteFunc(rule.Binaries, func(b types.PolicyNetworkBinary) bool { return b.Path == r.BinaryPath })
		p.NetworkPolicies[r.RuleName] = rule
	case op.AddDenyRules != nil:
		return withEndpoint(p, op.AddDenyRules.Target, func(ep *types.PolicyNetworkEndpoint) {
			ep.DenyRules = append(ep.DenyRules, op.AddDenyRules.DenyRules...)
		})
	case op.AddAllowRules != nil:
		return withEndpoint(p, op.AddAllowRules.Target, func(ep *types.PolicyNetworkEndpoint) {
			ep.Rules = append(ep.Rules, op.AddAllowRules.Rules...)
		})
	default:
		return statusErr(types.ErrorInvalidArgument, "empty merge operation")
	}
	return nil
}

func sameEndpoint(a, b types.PolicyNetworkEndpoint) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Port == b.Port && reflect.DeepEqual(a.Ports, b.Ports) && a.Path == b.Path
}

func withEndpoint(p *types.SandboxPolicy, target *types.L7RuleTarget, fn func(*types.PolicyNetworkEndpoint)) error {
	if target == nil {
		return statusErr(types.ErrorInvalidArgument, "an L7 append needs a target")
	}
	if len(target.Binaries) == 0 && !target.AnyBinary {
		return statusErr(types.ErrorInvalidArgument, "an L7 target needs binaries or any_binary")
	}
	rule, ok := p.NetworkPolicies[target.RuleName]
	if !ok {
		return statusErr(types.ErrorNotFound, "rule %q not found", target.RuleName)
	}
	for i := range rule.Endpoints {
		ep := &rule.Endpoints[i]
		if !strings.EqualFold(ep.Host, target.Host) {
			continue
		}
		if target.Path != nil && ep.Path != *target.Path {
			continue
		}
		fn(ep)
		p.NetworkPolicies[target.RuleName] = rule
		return nil
	}
	return statusErr(types.ErrorNotFound, "endpoint %s not found in rule %q", target.Host, target.RuleName)
}
