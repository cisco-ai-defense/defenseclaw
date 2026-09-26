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
	"regexp"
	"sort"
	"strconv"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// providerClient adds error injection to the SDK fake's provider store and
// replaces its unimplemented profile sub-client.
type providerClient struct {
	f        *Fake
	inner    v1.ProviderInterface
	profiles *profileClient
}

var _ v1.ProviderInterface = (*providerClient)(nil)

func (p *providerClient) Create(ctx context.Context, workspace string, provider *types.Provider) (*types.Provider, error) {
	if err := p.f.enter(MethodCreateProvider); err != nil {
		return nil, err
	}
	return p.inner.Create(ctx, workspace, provider)
}

func (p *providerClient) Get(ctx context.Context, workspace, name string) (*types.Provider, error) {
	if err := p.f.enter(MethodGetProvider); err != nil {
		return nil, err
	}
	return p.inner.Get(ctx, workspace, name)
}

func (p *providerClient) List(workspace string, opts ...types.ListOptions) (*v1.Pager[*types.Provider], error) {
	if err := p.f.enter(MethodListProviders); err != nil {
		return nil, err
	}
	return p.inner.List(workspace, opts...)
}

func (p *providerClient) ListAll(ctx context.Context, workspace string, opts ...types.ListOptions) ([]*types.Provider, error) {
	pager, err := p.List(workspace, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (p *providerClient) Update(ctx context.Context, workspace string, provider *types.Provider) (*types.Provider, error) {
	if err := p.f.enter(MethodUpdateProvider); err != nil {
		return nil, err
	}
	return p.inner.Update(ctx, workspace, provider)
}

func (p *providerClient) Delete(ctx context.Context, workspace, name string, opts ...types.DeleteOptions) (*types.DeletionResult, error) {
	if err := p.f.enter(MethodDeleteProvider); err != nil {
		return nil, err
	}
	return p.inner.Delete(ctx, workspace, name, opts...)
}

// Ensure goes through this wrapper's Get/Create/Update so each step is
// injectable.
func (p *providerClient) Ensure(ctx context.Context, workspace string, provider *types.Provider) (*types.Provider, error) {
	if provider == nil {
		return nil, statusErr(types.ErrorInvalidArgument, "provider must not be nil")
	}
	existing, err := p.Get(ctx, workspace, provider.Name)
	if err != nil {
		if !v1.IsNotFound(err) {
			return nil, err
		}
		return p.Create(ctx, workspace, provider)
	}
	updated := *provider
	updated.ID = existing.ID
	updated.ResourceVersion = existing.ResourceVersion
	return p.Update(ctx, workspace, &updated)
}

func (p *providerClient) Profiles() v1.ProfileInterface { return p.profiles }

func (p *providerClient) Refresh() v1.RefreshInterface { return p.inner.Refresh() }

// profileClient is an in-memory profile registry. Lint enforces the
// checks DefenseClaw's rendered profiles must already pass (an id in the
// gateway's syntax, credentials with env vars, endpoints with a host and
// port), so tests catch rendering mistakes.
type profileClient struct{ f *Fake }

var _ v1.ProfileInterface = (*profileClient)(nil)

var profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (p *profileClient) List(workspace string, _ ...types.ListOptions) (*v1.Pager[*types.ProviderProfile], error) {
	if err := p.f.enter(MethodListProfiles); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	items := make([]*types.ProviderProfile, 0, len(p.f.profiles))
	for _, pr := range p.f.profiles {
		items = append(items, cloneProfile(pr))
	}
	p.f.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return v1.NewPager("", func(context.Context, string) (*v1.Page[*types.ProviderProfile], error) {
		return &v1.Page[*types.ProviderProfile]{Items: items}, nil
	}), nil
}

func (p *profileClient) ListAll(ctx context.Context, workspace string, opts ...types.ListOptions) ([]*types.ProviderProfile, error) {
	pager, err := p.List(workspace, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (p *profileClient) Get(_ context.Context, _, id string) (*types.ProviderProfile, error) {
	if err := p.f.enter(MethodGetProfile); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	pr, ok := p.f.profiles[id]
	if !ok {
		return nil, statusErr(types.ErrorNotFound, "provider profile %q not found", id)
	}
	return cloneProfile(pr), nil
}

func lint(items []types.ProfileImportItem) []types.ProfileDiagnostic {
	var diags []types.ProfileDiagnostic
	add := func(item types.ProfileImportItem, field, msg string) {
		diags = append(diags, types.ProfileDiagnostic{Source: item.Source, ProfileID: item.Profile.ID, Field: field, Message: msg, Severity: "error"})
	}
	for _, item := range items {
		pr := item.Profile
		if !profileIDPattern.MatchString(pr.ID) {
			add(item, "id", "profile id must match "+profileIDPattern.String())
		}
		for i, cred := range pr.Credentials {
			if cred.Name == "" {
				add(item, "credentials["+strconv.Itoa(i)+"].name", "credential name is required")
			}
			if len(cred.EnvVars) == 0 {
				add(item, "credentials["+strconv.Itoa(i)+"].env_vars", "at least one env var is required")
			}
		}
		for i, ep := range pr.Endpoints {
			if ep.Host == "" || ep.Port == 0 {
				add(item, "endpoints["+strconv.Itoa(i)+"]", "endpoint needs a host and a port")
			}
		}
	}
	return diags
}

func (p *profileClient) Lint(_ context.Context, _ string, items []types.ProfileImportItem) (*types.LintResult, error) {
	if err := p.f.enter(MethodLintProfiles); err != nil {
		return nil, err
	}
	diags := lint(items)
	return &types.LintResult{Diagnostics: diags, Valid: len(diags) == 0}, nil
}

func (p *profileClient) Import(_ context.Context, _ string, items []types.ProfileImportItem) (*types.ImportResult, error) {
	if err := p.f.enter(MethodImportProfiles); err != nil {
		return nil, err
	}
	if diags := lint(items); len(diags) > 0 {
		return &types.ImportResult{Diagnostics: diags}, nil
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	for _, item := range items {
		if _, exists := p.f.profiles[item.Profile.ID]; exists {
			return nil, statusErr(types.ErrorAlreadyExists, "provider profile %q already exists", item.Profile.ID)
		}
	}
	res := &types.ImportResult{Imported: true}
	for _, item := range items {
		pr := cloneProfile(&item.Profile)
		pr.ResourceVersion = 1
		pr.Source = item.Source
		pr.Scope = "global"
		p.f.profiles[pr.ID] = pr
		res.Profiles = append(res.Profiles, *cloneProfile(pr))
	}
	return res, nil
}

func (p *profileClient) Update(_ context.Context, _, id string, expectedResourceVersion uint64, item types.ProfileImportItem) (*types.UpdateResult, error) {
	if err := p.f.enter(MethodUpdateProfile); err != nil {
		return nil, err
	}
	if item.Profile.ID != "" && item.Profile.ID != id {
		return nil, statusErr(types.ErrorInvalidArgument, "profile id %q does not match %q", item.Profile.ID, id)
	}
	item.Profile.ID = id
	if diags := lint([]types.ProfileImportItem{item}); len(diags) > 0 {
		return &types.UpdateResult{Diagnostics: diags}, nil
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	cur, ok := p.f.profiles[id]
	if !ok {
		return nil, statusErr(types.ErrorNotFound, "provider profile %q not found", id)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != cur.ResourceVersion {
		return nil, statusErr(types.ErrorConflict, "resource version %d does not match %d", expectedResourceVersion, cur.ResourceVersion)
	}
	next := cloneProfile(&item.Profile)
	next.ResourceVersion = cur.ResourceVersion + 1
	next.Source = item.Source
	next.Scope = cur.Scope
	p.f.profiles[id] = next
	return &types.UpdateResult{Profile: cloneProfile(next), Updated: true}, nil
}

func (p *profileClient) Delete(_ context.Context, _, id string, opts ...types.DeleteOptions) (*types.DeletionResult, error) {
	if err := p.f.enter(MethodDeleteProfile); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if _, ok := p.f.profiles[id]; !ok {
		if len(opts) > 0 && opts[0].AllowMissing {
			return &types.DeletionResult{Outcome: types.DeletionAlreadyAbsent}, nil
		}
		return nil, statusErr(types.ErrorNotFound, "provider profile %q not found", id)
	}
	delete(p.f.profiles, id)
	return &types.DeletionResult{Outcome: types.DeletionCompleted}, nil
}

func cloneProfile(p *types.ProviderProfile) *types.ProviderProfile {
	data, _ := json.Marshal(p)
	var out types.ProviderProfile
	_ = json.Unmarshal(data, &out)
	return &out
}

// healthClient answers from the fake's configurable health state.
type healthClient struct{ f *Fake }

func (h healthClient) Check(context.Context) (*types.HealthResult, error) {
	if err := h.f.enter(MethodHealth); err != nil {
		return nil, err
	}
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	res := h.f.health
	return &res, nil
}

func (h healthClient) GetGatewayInfo(context.Context) (*types.GatewayInfo, error) {
	if err := h.f.enter(MethodGatewayInfo); err != nil {
		return nil, err
	}
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	info := h.f.gatewayInfo
	info.ComputeDrivers = append([]types.ComputeDriverInfo(nil), info.ComputeDrivers...)
	info.Extensions = append([]types.ExtensionInfo(nil), info.Extensions...)
	return &info, nil
}

func (h healthClient) GetCurrentUser(ctx context.Context) (*types.CurrentUser, error) {
	return h.f.sdk.Health().GetCurrentUser(ctx)
}
