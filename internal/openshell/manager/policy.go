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

package manager

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// resolve resolves the effective sandbox policy for flags against the
// current configuration.
func (m *Manager) resolve(cfg *config.Config, flags packs.Flags) (*packs.Effective, []packs.Violation, error) {
	eff, violations, err := packs.Resolve(cfg, flags)
	if err != nil {
		m.logf("%s: %v", gatewaylog.ErrCodeOpenShellPackInvalid, err)
		return nil, nil, &sandboxapi.Error{Code: sandboxapi.CodePackInvalid, Message: "the sandbox policy pack is invalid", Detail: err.Error()}
	}
	return eff, violations, nil
}

// resolveBox re-resolves a sandbox's policy against the current config, so
// an administrator change applies to running sandboxes.
func (m *Manager) resolveBox(b *box) (*packs.Effective, error) {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	eff, _, err := m.resolve(m.config(), rec.Flags.packs(rec.Harness, rec.Project, m.gatewayPort()))
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	b.eff = eff
	m.mu.Unlock()
	return eff, nil
}

func (m *Manager) gatewayPort() int {
	return int(m.gwPort.Load())
}

// violationError turns a policy refusal into the API error, logging admin
// refusals with their gateway error code.
func (m *Manager) violationError(ctx context.Context, err error, sandbox string) error {
	var v *packs.Violation
	if !errors.As(err, &v) {
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: err.Error()}
	}
	wire := wireViolation(*v)
	if v.Admin() {
		m.logf("%s: sandbox %s: %s", gatewaylog.ErrCodeOpenShellAdminViolation, sandbox, v.Error())
		_ = m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{
			State: audit.SandboxHealthDegraded, ErrorCode: string(gatewaylog.ErrCodeOpenShellAdminViolation),
			ErrorSummary: truncate(v.Key+": "+v.Constraint, 512), Timestamp: m.now(),
		})
		msg := v.Message
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg, Detail: v.Detail, Violation: &wire}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: v.Message, Detail: v.Detail, Violation: &wire}
}

func wireViolation(v packs.Violation) sandboxapi.Violation {
	return sandboxapi.Violation{
		Key: v.Key, Source: string(v.Source), Attempted: v.Attempted, Enforced: v.Enforced,
		Constraint: v.Constraint, Fatal: v.Fatal, Admin: v.Admin(), Message: v.Message, Detail: v.Detail,
	}
}

func wireViolations(list []packs.Violation) []sandboxapi.Violation {
	out := make([]sandboxapi.Violation, 0, len(list))
	for _, v := range list {
		out = append(out, wireViolation(v))
	}
	return out
}

func wireAdmin(a packs.AdminStatus) sandboxapi.AdminStatus {
	return sandboxapi.AdminStatus{Configured: a.Configured, Authority: string(a.Authority), Detail: a.Detail}
}

// Explain resolves a sandbox posture with provenance.
func (m *Manager) Explain(_ context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	cfg := m.config()
	var flags packs.Flags
	if req.Sandbox != "" {
		b, err := m.box(req.Sandbox)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		rec := b.rec
		m.mu.Unlock()
		flags = rec.Flags.packs(rec.Harness, rec.Project, m.gatewayPort())
	} else {
		project := req.Project
		if project != "" {
			if !filepath.IsAbs(project) {
				return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "project must be an absolute path")
			}
			if real, err := filepath.EvalSymlinks(project); err == nil {
				project = real
			}
		}
		flags = packs.Flags{
			Harness: config.NormalizeConnectorName(req.Harness), Pack: req.Pack, Profile: req.Profile, Project: project,
			Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo, Unmask: req.Unmask, OpenShellGatewayPort: m.gatewayPort(),
		}
	}
	eff, violations, err := m.resolve(cfg, flags)
	if err != nil {
		return nil, err
	}
	out := &sandboxapi.Explain{
		Profile: eff.Profile, NetworkMode: eff.NetworkMode, Approvals: eff.Approvals,
		Admin: wireAdmin(eff.Admin), Violations: wireViolations(violations),
	}
	if eff.Pack != nil {
		out.Pack, out.PackSource, out.PackDigest = eff.Pack.Name, eff.Pack.Source, eff.Pack.Digest
	}
	for _, s := range eff.Explain() {
		out.Settings = append(out.Settings, sandboxapi.Setting{
			Key: s.Key, Value: s.Value, Source: string(s.Source), Origin: s.Origin, Requested: s.Requested,
		})
	}
	return out, nil
}

// baseEffective is the configured posture without run flags; the egress
// proxy's global rules and the status come from it.
func (m *Manager) baseEffective(cfg *config.Config) (*packs.Effective, error) {
	eff, _, err := m.resolve(cfg, packs.Flags{OpenShellGatewayPort: m.gatewayPort()})
	return eff, err
}
