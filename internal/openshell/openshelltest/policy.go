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
	"slices"
	"strconv"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// policyClient implements the draft inbox and revision history. Approving
// a chunk merges its proposed rule into the sandbox policy as an AddRule
// and records a new revision, as the gateway does.
type policyClient struct{ f *Fake }

var _ v1.PolicyInterface = (*policyClient)(nil)

func (p *policyClient) sandboxState(ctx context.Context, workspace, name string) (*sandboxState, error) {
	if _, err := p.f.sdk.Sandboxes().Get(ctx, workspace, name); err != nil {
		return nil, err
	}
	return p.f.state(workspace, name), nil
}

func (p *policyClient) GetDraft(ctx context.Context, workspace, sandboxName string, opts ...types.GetDraftOption) (*types.DraftPolicy, error) {
	if err := p.f.enter(MethodGetDraft); err != nil {
		return nil, err
	}
	cfg := types.ApplyGetDraftOptions(opts)
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	out := &types.DraftPolicy{DraftVersion: st.draftVersion}
	for _, c := range st.chunks {
		if f := cfg.StatusFilter(); f != "" && c.Status != f {
			continue
		}
		c.ProposedRule = cloneRule(c.ProposedRule)
		out.Chunks = append(out.Chunks, c)
	}
	return out, nil
}

func (p *policyClient) chunk(st *sandboxState, id string) (*types.PolicyChunk, error) {
	for i := range st.chunks {
		if st.chunks[i].ID == id {
			return &st.chunks[i], nil
		}
	}
	return nil, statusErr(types.ErrorNotFound, "draft chunk %q not found", id)
}

// approve merges pending chunks into one new revision; the caller holds mu.
func (p *policyClient) approve(st *sandboxState, chunks []*types.PolicyChunk) (uint32, string, error) {
	next := clonePolicy(st.policy)
	if next == nil {
		next = &types.SandboxPolicy{Version: 1}
	}
	for _, c := range chunks {
		if c.ProposedRule == nil {
			return 0, "", statusErr(types.ErrorConflict, "draft chunk %q has no proposed rule", c.ID)
		}
		name := c.RuleName
		if name == "" {
			name = c.ProposedRule.Name
		}
		if err := applyMerge(next, types.PolicyMergeOperation{AddRule: &types.AddNetworkRule{RuleName: name, Rule: *c.ProposedRule}}); err != nil {
			return 0, "", err
		}
	}
	res := (&configClient{f: p.f}).commit(st, next, map[string]string{"source": "draft"}, &types.ConfigUpdateResult{})
	for _, c := range chunks {
		c.Status = "approved"
		c.DecidedAt = p.f.now()
		st.history = append(st.history, types.DraftHistoryEntry{Timestamp: c.DecidedAt, EventType: "approved", ChunkID: c.ID,
			Description: "approved " + c.RuleName})
	}
	st.draftVersion++
	return res.Version, res.PolicyHash, nil
}

func (p *policyClient) ApproveDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reviewToken string) (*types.ApproveResult, error) {
	if err := p.f.enter(MethodApproveDraftChunk); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	c, err := p.chunk(st, chunkID)
	if err != nil {
		return nil, err
	}
	if c.Status != "pending" {
		return nil, statusErr(types.ErrorConflict, "draft chunk %q is %s", chunkID, c.Status)
	}
	if c.ReviewToken != "" && c.ReviewToken != reviewToken {
		return nil, statusErr(types.ErrorInvalidArgument, "review token does not match the evaluated candidate")
	}
	version, hash, err := p.approve(st, []*types.PolicyChunk{c})
	if err != nil {
		return nil, err
	}
	return &types.ApproveResult{PolicyVersion: version, PolicyHash: hash}, nil
}

func (p *policyClient) ApproveAllDraftChunks(ctx context.Context, workspace, sandboxName string, opts ...types.ApproveAllOption) (*types.ApproveAllResult, error) {
	if err := p.f.enter(MethodApproveAllChunks); err != nil {
		return nil, err
	}
	cfg := types.ApplyApproveAllOptions(opts)
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	var picked []*types.PolicyChunk
	skipped := uint32(0)
	if approvals := cfg.Approvals(); len(approvals) > 0 {
		for _, a := range approvals {
			c, err := p.chunk(st, a.ChunkID)
			if err != nil {
				return nil, err
			}
			if c.Status != "pending" {
				return nil, statusErr(types.ErrorConflict, "draft chunk %q is %s", a.ChunkID, c.Status)
			}
			if c.ReviewToken != "" && c.ReviewToken != a.ReviewToken {
				return nil, statusErr(types.ErrorInvalidArgument, "review token for %q does not match", a.ChunkID)
			}
			if c.SecurityNotes != "" && !cfg.IncludeSecurityFlagged() {
				skipped++
				continue
			}
			picked = append(picked, c)
		}
	} else {
		for i := range st.chunks {
			c := &st.chunks[i]
			if c.Status != "pending" {
				continue
			}
			if c.SecurityNotes != "" && !cfg.IncludeSecurityFlagged() {
				skipped++
				continue
			}
			picked = append(picked, c)
		}
	}
	res := &types.ApproveAllResult{ChunksSkipped: skipped}
	if len(picked) == 0 {
		return res, nil
	}
	version, hash, err := p.approve(st, picked)
	if err != nil {
		return nil, err
	}
	res.PolicyVersion, res.PolicyHash, res.ChunksApproved = version, hash, uint32(len(picked))
	return res, nil
}

func (p *policyClient) RejectDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reason string) error {
	if err := p.f.enter(MethodRejectDraftChunk); err != nil {
		return err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return err
	}
	c, err := p.chunk(st, chunkID)
	if err != nil {
		return err
	}
	if c.Status != "pending" {
		return statusErr(types.ErrorConflict, "draft chunk %q is %s", chunkID, c.Status)
	}
	c.Status, c.RejectionReason, c.DecidedAt = "rejected", reason, p.f.now()
	st.history = append(st.history, types.DraftHistoryEntry{Timestamp: c.DecidedAt, EventType: "rejected", ChunkID: c.ID, Description: reason})
	st.draftVersion++
	return nil
}

func (p *policyClient) ClearDraftChunks(ctx context.Context, workspace, sandboxName string) (*types.ClearResult, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	before := len(st.chunks)
	st.chunks = slices.DeleteFunc(st.chunks, func(c types.PolicyChunk) bool { return c.Status == "pending" })
	cleared := uint32(before - len(st.chunks))
	if cleared > 0 {
		st.history = append(st.history, types.DraftHistoryEntry{Timestamp: p.f.now(), EventType: "cleared",
			Description: strconv.Itoa(int(cleared)) + " pending chunks cleared"})
		st.draftVersion++
	}
	return &types.ClearResult{ChunksCleared: cleared}, nil
}

func (p *policyClient) GetDraftHistory(ctx context.Context, workspace, sandboxName string) ([]types.DraftHistoryEntry, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	return slices.Clone(st.history), nil
}

func (p *policyClient) EditDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string, proposedRule *types.NetworkPolicyRule) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return err
	}
	c, err := p.chunk(st, chunkID)
	if err != nil {
		return err
	}
	if c.Status != "pending" {
		return statusErr(types.ErrorConflict, "draft chunk %q is %s", chunkID, c.Status)
	}
	c.ProposedRule = cloneRule(proposedRule)
	st.draftVersion++
	return nil
}

func (p *policyClient) UndoDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string) (*types.UndoResult, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	c, err := p.chunk(st, chunkID)
	if err != nil {
		return nil, err
	}
	if c.Status != "approved" {
		return nil, statusErr(types.ErrorConflict, "draft chunk %q is %s", chunkID, c.Status)
	}
	next := clonePolicy(st.policy)
	name := c.RuleName
	if name == "" && c.ProposedRule != nil {
		name = c.ProposedRule.Name
	}
	if next != nil {
		delete(next.NetworkPolicies, name)
	}
	res := (&configClient{f: p.f}).commit(st, next, map[string]string{"source": "draft-undo"}, &types.ConfigUpdateResult{})
	c.Status, c.DecidedAt = "pending", p.f.now()
	st.history = append(st.history, types.DraftHistoryEntry{Timestamp: p.f.now(), EventType: "undone", ChunkID: c.ID})
	st.draftVersion++
	return &types.UndoResult{PolicyVersion: res.Version, PolicyHash: res.PolicyHash}, nil
}

func (p *policyClient) revisions(ctx context.Context, workspace, sandboxName string, global bool) ([]types.SandboxPolicyRevision, error) {
	if global {
		return slices.Clone(p.f.globalRevisions), nil
	}
	st, err := p.sandboxState(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}
	return slices.Clone(st.revisions), nil
}

func (p *policyClient) GetStatus(ctx context.Context, workspace, sandboxName string, opts ...types.GetStatusOption) (*types.PolicyStatusResult, error) {
	if err := p.f.enter(MethodPolicyStatus); err != nil {
		return nil, err
	}
	cfg := types.ApplyGetStatusOptions(opts)
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	revs, err := p.revisions(ctx, workspace, sandboxName, cfg.Global())
	if err != nil {
		return nil, err
	}
	if len(revs) == 0 {
		if cfg.Global() {
			return nil, statusErr(types.ErrorNotFound, "no global policy revision found")
		}
		return nil, statusErr(types.ErrorNotFound, "no policy revisions found")
	}
	var active uint32
	for _, r := range revs {
		if r.Status == types.PolicyLoadStatusLoaded && r.Version > active {
			active = r.Version
		}
	}
	want := cfg.Version()
	if want == 0 {
		want = revs[len(revs)-1].Version
	}
	for _, r := range revs {
		if r.Version == want {
			r.Policy = clonePolicy(r.Policy)
			return &types.PolicyStatusResult{Revision: r, ActiveVersion: active}, nil
		}
	}
	return nil, statusErr(types.ErrorNotFound, "policy version %d not found", want)
}

func (p *policyClient) List(workspace, sandboxName string, opts ...types.ListPolicyOption) (*v1.Pager[types.SandboxPolicyRevision], error) {
	if err := p.f.enter(MethodListPolicies); err != nil {
		return nil, err
	}
	cfg := types.ApplyListPolicyOptions(opts)
	if !cfg.Global() && sandboxName == "" {
		return nil, statusErr(types.ErrorInvalidArgument, "sandbox name must not be empty")
	}
	p.f.mu.Lock()
	revs, err := p.revisions(context.Background(), workspace, sandboxName, cfg.Global())
	p.f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for i := range revs {
		revs[i].Policy = clonePolicy(revs[i].Policy)
	}
	return v1.NewPager("", func(context.Context, string) (*v1.Page[types.SandboxPolicyRevision], error) {
		return &v1.Page[types.SandboxPolicyRevision]{Items: revs}, nil
	}), nil
}

func (p *policyClient) ListAll(ctx context.Context, workspace, sandboxName string, opts ...types.ListPolicyOption) ([]types.SandboxPolicyRevision, error) {
	pager, err := p.List(workspace, sandboxName, opts...)
	if err != nil {
		return nil, err
	}
	return pager.All(ctx)
}
