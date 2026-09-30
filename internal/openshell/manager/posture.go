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
	"fmt"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// posture is what a sandbox's user sees of the policy it runs under: the
// settings a configuration change can move under a running sandbox.
type posture struct {
	pack, digest, profile, network, approvals, workdir string
	yolo                                               bool
	// blockUploads is the large-upload block (egress.block_large_uploads).
	blockUploads                 bool
	adminBlock, allowOnly, block []string
	// admin names the settings an openshell.admin constraint decided.
	admin map[string]bool
}

func postureOf(eff *packs.Effective) *posture {
	p := &posture{
		profile: eff.Profile, network: eff.NetworkMode, approvals: eff.Approvals, workdir: eff.Workspace.Mode, yolo: eff.Yolo,
		blockUploads: eff.Egress.BlockLargeUploads,
		adminBlock:   slices.Clone(eff.Egress.AdminBlock), allowOnly: slices.Clone(eff.Egress.AllowOnly), block: slices.Clone(eff.Egress.Block),
		admin: map[string]bool{},
	}
	if eff.Pack != nil {
		p.pack, p.digest = eff.Pack.Name, eff.Pack.Digest
	}
	for _, s := range eff.Explain() {
		if s.Source == packs.SourceAdmin {
			p.admin[s.Key] = true
		}
	}
	return p
}

// maxListedHosts bounds the hosts a policy-change line names per list.
const maxListedHosts = 5

// changes lists how q differs from p, and whether an organization's
// constraint took part in any of it.
func (p *posture) changes(q *posture) (out []string, org bool) {
	orgKey := func(key string) bool { return p.admin[key] || q.admin[key] }
	add := func(key, what string) {
		out = append(out, what)
		org = org || orgKey(key)
	}
	switch {
	case p.pack != q.pack:
		add("pack", "pack "+firstNonEmpty(p.pack, "-")+" → "+firstNonEmpty(q.pack, "-"))
	case p.digest != q.digest:
		add("pack", "pack "+firstNonEmpty(q.pack, "-")+" changed")
	}
	if p.profile != q.profile {
		add("profile", "profile "+p.profile+" → "+q.profile)
	}
	if p.network != q.network {
		what := "network " + p.network + " → " + q.network
		if q.network == packs.NetworkDeny {
			what += " (web egress off)"
		}
		add("network.mode", what)
	}
	if p.approvals != q.approvals {
		add("approvals.mode", "approvals "+p.approvals+" → "+q.approvals)
	}
	if p.yolo != q.yolo {
		add("yolo", "skip-permissions "+onOff(p.yolo, "allowed", "off")+" → "+onOff(q.yolo, "allowed", "off")+" (from the next start)")
	}
	if p.workdir != q.workdir {
		add("workdir.mode", "project "+p.workdir+" → "+q.workdir+" (from the next sandbox)")
	}
	if p.blockUploads != q.blockUploads {
		add("egress.block_large_uploads", "large uploads to first-seen hosts "+
			onOff(p.blockUploads, "blocked", "reported")+" → "+onOff(q.blockUploads, "blocked", "reported"))
	}
	for _, list := range []struct {
		name        string
		admin       bool
		before, now []string
	}{
		{"egress_block", true, p.adminBlock, q.adminBlock},
		{"egress_allow_only", true, p.allowOnly, q.allowOnly},
		{"the block list", false, p.block, q.block},
	} {
		added, removed := listDiff(list.before, list.now)
		if len(added) > 0 {
			out = append(out, list.name+" now includes "+hostList(added))
		}
		if len(removed) > 0 {
			out = append(out, list.name+" no longer includes "+hostList(removed))
		}
		if list.admin && (len(added) > 0 || len(removed) > 0) {
			org = true
		}
	}
	return out, org
}

func onOff(v bool, on, off string) string {
	if v {
		return on
	}
	return off
}

// listDiff is what now adds to before and what it drops.
func listDiff(before, now []string) (added, removed []string) {
	for _, h := range now {
		if !slices.Contains(before, h) {
			added = append(added, h)
		}
	}
	for _, h := range before {
		if !slices.Contains(now, h) {
			removed = append(removed, h)
		}
	}
	return added, removed
}

func hostList(hosts []string) string {
	if len(hosts) <= maxListedHosts {
		return strings.Join(hosts, ", ")
	}
	return strings.Join(hosts[:maxListedHosts], ", ") + fmt.Sprintf(" and %d more", len(hosts)-maxListedHosts)
}

// announcePosture tells the feed, once per change and per running sandbox,
// that a configuration change moved the policy the sandbox runs under
// (refreshEgress re-resolves it on every change): which settings moved,
// and whether the organization's policy did it. The first policy a box is
// seen with is its baseline.
func (m *Manager) announcePosture(b *box, eff *packs.Effective) {
	if eff == nil {
		return
	}
	now := postureOf(eff)
	m.mu.Lock()
	before := b.posture
	b.posture = now
	name, ready := b.rec.Name, b.phase == audit.SandboxPhaseReady && !b.creating && !b.deleted && !b.retained
	m.mu.Unlock()
	if before == nil || !ready {
		return
	}
	changes, org := before.changes(now)
	if len(changes) == 0 {
		return
	}
	who := "the sandbox policy changed"
	if org {
		who = "your organization's sandbox policy changed"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: sandboxapi.ReasonPolicyChanged,
		Message: truncate(who+": "+strings.Join(changes, "; ")+"; applied to "+name, 512)})
}
