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
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// ConfirmingView rewrites v, the view of a sandbox whose policy is judged
// against a floor that is not its organization's yet (a managed daemon's
// closed start-up floor, before the managed gateway confirmed the sandbox's
// registration), to say so instead of what that floor makes of it: the
// policy the sandbox was created with in place of the current profile,
// network mode, approvals and clamps, without the drift warnings that
// compare it with the closed floor, and with note. Judged against the
// closed floor, every sandbox read "your organization does not let you run
// sandboxes (openshell.admin.allowed)" and a strict, deny-all policy after a
// daemon restart, for a sandbox the organization allows (GAP-0462). A view
// of a sandbox the manager does not hold is left as it is.
func (m *Manager) ConfirmingView(v *sandboxapi.Sandbox, note string) {
	if v == nil || v.Runtime == audit.SandboxRuntimeAxis {
		return
	}
	m.mu.Lock()
	b := m.boxes[v.Name]
	if b == nil || b.deleted || b.native != nil {
		m.mu.Unlock()
		return
	}
	r, eff := b.rec, b.eff
	running := b.phase == audit.SandboxPhaseReady && !b.started.IsZero()
	m.mu.Unlock()
	if eff != nil {
		// The warnings view added from the policy it judged (box.go view),
		// as displaySafe left them.
		drift := postureDrift(r, eff)
		if running {
			drift = append(drift, sessionDrift(r, eff, v.SessionYolo, v.Yolo)...)
		}
		drift = sandboxapi.DisplayTexts(drift)
		v.Warnings = slices.DeleteFunc(slices.Clone(v.Warnings), func(w string) bool { return slices.Contains(drift, w) })
	}
	v.Pack, v.PackDigest = r.Pack, r.PackDigest
	v.Profile, v.NetworkMode, v.Approvals, v.UserApprovals = r.Profile, r.NetworkMode, r.Approvals, ""
	v.HostPorts = slices.Clone(r.HostPorts)
	v.Violations = slices.Clone(r.Violations)
	if note != "" {
		v.Warnings = append(v.Warnings, sandboxapi.DisplayText(note))
	}
}
