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

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// sandboxClient decorates the SDK fake's sandbox store with error
// injection, create-time policy capture and configuration admission.
type sandboxClient struct {
	f     *Fake
	inner v1.SandboxInterface
}

var _ v1.SandboxInterface = (*sandboxClient)(nil)

func (s *sandboxClient) Create(ctx context.Context, workspace, name string, spec *types.SandboxSpec, labels map[string]string, opts ...types.CreateOptions) (*types.Sandbox, error) {
	if err := s.f.enter(MethodCreateSandbox); err != nil {
		return nil, err
	}
	sb, err := s.inner.Create(ctx, workspace, name, spec, labels, opts...)
	if err != nil {
		return nil, err
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	st := s.f.state(workspace, name)
	if spec != nil && spec.Policy != nil {
		st.policy = clonePolicy(spec.Policy)
		st.createPolicy = clonePolicy(spec.Policy)
		st.policyVersion = 1
		st.revisions = []types.SandboxPolicyRevision{{
			Version: 1, PolicyHash: policyHash(spec.Policy), Status: types.PolicyLoadStatusLoaded,
			CreatedAt: s.f.now(), LoadedAt: s.f.now(), Policy: clonePolicy(spec.Policy),
		}}
	}
	return sb, nil
}

func (s *sandboxClient) Get(ctx context.Context, workspace, name string) (*types.Sandbox, error) {
	if err := s.f.enter(MethodGetSandbox); err != nil {
		return nil, err
	}
	return s.inner.Get(ctx, workspace, name)
}

func (s *sandboxClient) List(workspace string, opts ...types.ListOptions) (*v1.Pager[*types.Sandbox], error) {
	if err := s.f.enter(MethodListSandboxes); err != nil {
		return nil, err
	}
	return s.inner.List(workspace, opts...)
}

func (s *sandboxClient) ListAll(ctx context.Context, workspace string, opts ...types.ListOptions) ([]*types.Sandbox, error) {
	pager, err := s.List(workspace, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}

func (s *sandboxClient) Stop(ctx context.Context, workspace, name string) (*types.Sandbox, error) {
	if err := s.f.enter(MethodStopSandbox); err != nil {
		return nil, err
	}
	return s.inner.Stop(ctx, workspace, name)
}

func (s *sandboxClient) Start(ctx context.Context, workspace, name string) (*types.Sandbox, error) {
	if err := s.f.enter(MethodStartSandbox); err != nil {
		return nil, err
	}
	return s.inner.Start(ctx, workspace, name)
}

func (s *sandboxClient) Delete(ctx context.Context, workspace, name string, opts ...types.DeleteOptions) (*types.DeletionResult, error) {
	if err := s.f.enter(MethodDeleteSandbox); err != nil {
		return nil, err
	}
	res, err := s.inner.Delete(ctx, workspace, name, opts...)
	if err != nil {
		return nil, err
	}
	if res.Outcome != types.DeletionAlreadyAbsent {
		s.f.mu.Lock()
		delete(s.f.states, key(workspace, name))
		s.f.mu.Unlock()
	}
	return res, nil
}

func (s *sandboxClient) AttachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*types.AttachProviderResult, error) {
	if err := s.f.enter(MethodAttachProvider); err != nil {
		return nil, err
	}
	if _, err := s.f.sdk.Providers().Get(ctx, workspace, providerName); err != nil {
		return nil, err
	}
	return s.inner.AttachProvider(ctx, workspace, sandboxName, providerName, expectedResourceVersion)
}

func (s *sandboxClient) DetachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*types.DetachProviderResult, error) {
	if err := s.f.enter(MethodDetachProvider); err != nil {
		return nil, err
	}
	return s.inner.DetachProvider(ctx, workspace, sandboxName, providerName, expectedResourceVersion)
}

func (s *sandboxClient) ListProviders(workspace, sandboxName string, opts ...types.ListOptions) (*v1.Pager[*types.Provider], error) {
	return s.inner.ListProviders(workspace, sandboxName, opts...)
}

func (s *sandboxClient) ListAllProviders(ctx context.Context, workspace, sandboxName string, opts ...types.ListOptions) ([]*types.Provider, error) {
	return s.inner.ListAllProviders(ctx, workspace, sandboxName, opts...)
}

// WaitReady moves the sandbox to Ready (synchronously, like the SDK fake)
// and stamps the configuration admission a live 0.1.1 gateway reports:
// accepted by default, or whatever SetAdmission configured.
func (s *sandboxClient) WaitReady(ctx context.Context, workspace, name string, opts ...types.WaitOptions) (*types.Sandbox, error) {
	if err := s.f.enter(MethodWaitReady); err != nil {
		return nil, err
	}
	sb, err := s.inner.WaitReady(ctx, workspace, name, opts...)
	if err != nil {
		return nil, err
	}
	s.f.mu.Lock()
	st := s.f.state(workspace, name)
	state, msg, version := st.admission, st.admissionError, st.policyVersion
	s.f.mu.Unlock()

	reason, cond := "ConfigurationAccepted", "True"
	if state == types.ConfigurationAdmissionRejected {
		reason, cond = "ConfigurationRejected", "False"
	} else if state == types.ConfigurationAdmissionPending {
		reason, cond = "ConfigurationPending", "False"
	}
	sb.Status.Conditions = []types.SandboxCondition{
		{Type: "Ready", Status: "True", Reason: "DependenciesReady", Message: "Supervisor session connected"},
		{Type: "ConfigurationReady", Status: cond, Reason: reason, Message: msg},
	}
	sb.Status.ConfigurationAdmission = &types.SandboxConfigurationAdmission{
		State: state, PolicyVersion: version, Error: msg,
	}
	sb.Status.CurrentPolicyVersion = version
	s.f.sdk.AddSandbox(workspace, sb)
	return sb, nil
}

func (s *sandboxClient) WaitStopped(ctx context.Context, workspace, name string, opts ...types.WaitOptions) (*types.Sandbox, error) {
	if err := s.f.enter(MethodWaitStopped); err != nil {
		return nil, err
	}
	return s.inner.WaitStopped(ctx, workspace, name, opts...)
}

func (s *sandboxClient) Watch(ctx context.Context, workspace, name string, opts ...types.WatchOptions) (types.WatchInterface[*types.Sandbox], error) {
	return s.inner.Watch(ctx, workspace, name, opts...)
}

func (s *sandboxClient) GetLogs(ctx context.Context, workspace, sandboxName string, opts ...types.LogOption) (*types.LogResult, error) {
	return s.inner.GetLogs(ctx, workspace, sandboxName, opts...)
}
