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

package workspace

import (
	"context"
	"fmt"
)

// UndoApplyOptions configures UndoApply.
type UndoApplyOptions struct {
	DataDir string
	Name    string
	// Preview computes the result without changing anything.
	Preview bool
}

// UndoApplyResult reports what UndoApply changed (or, with Preview, would
// change).
type UndoApplyResult struct {
	Name    string `json:"name"`
	Project string `json:"project"`
	Preview bool   `json:"preview"`
	// Changes turn the folder as it is now into the folder without the
	// apply's changes; the operator's own edits since the apply stay.
	Changes []TreeChange `json:"changes,omitempty"`
	// Conflicts are paths both the apply and the operator changed since;
	// nothing is changed then.
	Conflicts []string `json:"conflicts,omitempty"`
	// PreApplyRef keeps the folder as it was before the apply ("" for a
	// folder that is not a git repository, where DefenseClaw keeps it).
	PreApplyRef string `json:"pre_apply_ref,omitempty"`
	Undone      bool   `json:"undone,omitempty"`
}

// UndoApply reverts the last 3-way apply (Apply with ApplyMerge) of a
// copy-mode sandbox's work: a 3-way merge from the folder the apply left
// to the folder before it, applied to the folder as it is now, so edits
// the operator made since stay. When those edits overlap the apply's
// changes it reports the conflicts and changes nothing. A branch or patch
// file the work went to instead is the operator's to delete.
func UndoApply(ctx context.Context, opts UndoApplyOptions) (*UndoApplyResult, error) {
	rec, err := LoadCopy(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return nil, err
	}
	lay, err := newLayout(opts.DataDir)
	if err != nil {
		return nil, err
	}
	g := applyGit(rec)
	res := &UndoApplyResult{Name: rec.Name, Project: rec.Project, Preview: opts.Preview}
	preRef, postRef := applyRef(rec.Name, "pre-apply"), applyRef(rec.Name, "post-apply")
	if rec.Kind == CopyGit {
		res.PreApplyRef = preRef
	}
	post, err := g.line(ctx, "rev-parse", "-q", "--verify", postRef+"^{commit}")
	if err != nil || post == "" {
		return nil, fmt.Errorf("%w: no `pull --apply` of %s is recorded", ErrNothingApplied, rec.Name)
	}
	pre, err := g.line(ctx, "rev-parse", "-q", "--verify", preRef+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("workspace: the folder before the last apply of %s is no longer recorded (%s is gone), so the apply cannot be undone", rec.Name, preRef)
	}
	// post-apply sits on the pre-apply state it was made from; any other
	// pairing is an apply that was not recorded completely.
	if parent, err := g.line(ctx, "rev-parse", "-q", "--verify", post+"^1"); err != nil || parent != pre {
		return nil, fmt.Errorf("workspace: the last apply of %s was not recorded completely, so it cannot be undone; the folder before it is kept at %s", rec.Name, preRef)
	}
	v, err := hostGitVersion(ctx, rec.Project)
	if err != nil {
		return nil, err
	}
	if !v.atLeast(2, 38) {
		return nil, fmt.Errorf("workspace: git %s cannot revert the apply without touching the working tree (git 2.38+ can); the folder before it is kept at %s", v, preRef)
	}

	gi, curTree, cleanup, err := captureWorkTree(ctx, lay, rec, g)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	// Both sides sit on the apply's result, which makes it the merge base:
	// ours is the folder now, theirs the folder before the apply.
	ours, err := g.line(ctx, "commit-tree", curTree, "-p", post, "-m", "defenseclaw: working tree before undoing the apply of sandbox "+rec.Name)
	if err != nil {
		return nil, err
	}
	preTree, err := g.line(ctx, "rev-parse", pre+"^{tree}")
	if err != nil {
		return nil, err
	}
	theirs, err := g.line(ctx, "commit-tree", preTree, "-p", post, "-m", "defenseclaw: working tree before the apply of sandbox "+rec.Name)
	if err != nil {
		return nil, err
	}
	merged, conflicts, err := mergeTrees(ctx, g, nil, ours, theirs)
	if err != nil {
		return nil, fmt.Errorf("workspace: revert the apply: %w", err)
	}
	if len(conflicts) > 0 {
		res.Conflicts = conflicts
		return res, nil
	}
	if res.Changes, err = diffTrees(ctx, g, curTree, merged); err != nil {
		return nil, err
	}
	if opts.Preview {
		return res, nil
	}
	if len(res.Changes) > 0 {
		// The same two-way switch Apply uses: a file changed since the
		// capture fails the switch instead of being overwritten.
		if err := gi.run(ctx, "read-tree", "-m", "-u", curTree, merged); err != nil {
			return nil, fmt.Errorf("workspace: update the working tree: %w", err)
		}
	}
	// The apply is taken back; another undo has nothing to revert. The
	// pre-apply ref and its reflog stay.
	if err := g.run(ctx, "update-ref", "-d", postRef, post); err != nil {
		return nil, fmt.Errorf("workspace: the apply was reverted, but recording that failed: %w", err)
	}
	res.Undone = true
	return res, nil
}
