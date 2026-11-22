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
	"errors"
	"fmt"
	"strings"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// PushOptions configures Push.
type PushOptions struct {
	// Start carries the copy rules (DataDir, Home, MaxBytes, Masks,
	// Unmask); Project is taken from the copy record.
	Start StartOptions
	Name  string
	// Transport reaches the actor; a *Client also names the upload with Op.
	Transport osw.Transport
	// Op is relay.OpPush (default) or relay.OpSync.
	Op       string
	Paths    []string
	Mode     osw.PushMode
	PatchOut string
	DryRun   bool
	// Label names the restore point taken before the push.
	Label string
	// NoCheckpoint skips the restore point (sync takes its own); the push
	// log then names Checkpoint, the last one taken before it.
	NoCheckpoint bool
	Checkpoint   string
	Timeout      time.Duration
}

// PushOutcome is what Push found and did.
type PushOutcome struct {
	Plan       *osw.PushPlan
	Result     *osw.PushResult
	Checkpoint string
}

// ErrPushHostCopy: the Windows host copy has no push yet.
var ErrPushHostCopy = errors.New("push and sync are not available for a copy started on Windows yet (Preview); run the agent again from this folder to send a new copy")

// Push sends the folder's changes since the last send into the actor: the
// same staging as run (Preflight: masking, the secret scan, the cluster
// cap), a conflict check against the agent's files, a restore point, then
// the write. A conflict with PushRefuse returns *osw.PushConflictError and
// writes nothing (no restore point either).
func Push(ctx context.Context, opts PushOptions) (*PushOutcome, error) {
	if opts.Transport == nil {
		return nil, errors.New("workspace: push needs a transport to the actor")
	}
	dataDir := opts.Start.DataDir
	if usesHostCopy(dataDir, opts.Name) {
		return nil, ErrPushHostCopy
	}
	rec, err := osw.LoadCopy(dataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	start := opts.Start
	start.Project = rec.Project
	start.Transport = opts.Transport
	// The run's own rules carry over: what it excluded stays out and what
	// it shared stays shared, so a push does not see them as new changes.
	start.Masks = append(append([]string(nil), rec.Masks...), start.Masks...)
	// The run's shared files carry over by exact path: as patterns, a
	// shared root .env would share every .env added below it (RV1 P1-1).
	start.UnmaskExact = append(append([]string(nil), rec.Unmasked...), start.UnmaskExact...)
	start.UnmaskAsked = start.Unmask
	prepared, err := Preflight(ctx, start)
	if err != nil {
		return nil, err
	}
	defer prepared.Close()
	if prepared.copy == nil {
		return nil, ErrPushHostCopy
	}
	plan, err := osw.PlanPush(ctx, osw.PushPlanOptions{
		DataDir: dataDir, Name: opts.Name, Stage: prepared.copy, Exec: opts.Transport, Paths: opts.Paths, Timeout: opts.Timeout,
	})
	if err != nil {
		var moved *osw.BaselineMovedError
		if errors.As(err, &moved) {
			return nil, err
		}
		return nil, cleanErr("compare the folder with the agent's copy", err)
	}
	out := &PushOutcome{Plan: plan}
	if len(plan.Changes) == 0 || opts.DryRun {
		return out, nil
	}
	mode := opts.Mode
	if conf := plan.Conflicts(); len(conf) > 0 {
		if opts.PatchOut != "" {
			if err := plan.PatchOut(ctx, opts.PatchOut); err != nil {
				return out, cleanErr("write the patch", err)
			}
			mode = osw.PushTheirs
		}
		if mode == osw.PushRefuse {
			return out, &osw.PushConflictError{Paths: conf}
		}
		// Before the restore point: nothing is written when --mine would
		// remove an agent file or folder the person did not name (RV2 N2).
		if r := plan.Replacing(); len(r) > 0 && mode == osw.PushMine {
			return out, &osw.PushReplaceError{Changes: r}
		}
	}
	cpID := opts.Checkpoint
	if !opts.NoCheckpoint {
		cp, err := Checkpoint(ctx, CheckpointOptions{Exec: opts.Transport, Dir: rec.RemoteDir, DataDir: dataDir, Name: opts.Name, Label: opts.Label})
		if err != nil {
			return out, fmt.Errorf("save a restore point before the push: %w", err)
		}
		out.Checkpoint, cpID = cp.ID, cp.ID
	}
	if c, ok := opts.Transport.(interface{ SetOp(string) string }); ok {
		op := opts.Op
		if op == "" {
			op = relay.OpPush
		}
		prev := c.SetOp(op)
		defer c.SetOp(prev)
	}
	res, err := plan.Send(ctx, opts.Transport, mode, cpID)
	if err != nil {
		return out, cleanErr("send the changes", err)
	}
	out.Result = res
	return out, nil
}

// SetOp names the following uploads (relay.OpPush, relay.OpSync, or ""
// for a first copy) and returns the previous name.
func (c *Client) SetOp(op string) string {
	prev := c.Op
	c.Op = op
	return prev
}

// SendLine is the one-line summary of what a push sends (or would).
func (o *PushOutcome) SendLine(verb string) string {
	var parts []string
	var n int
	var size int64
	for _, c := range o.Plan.Changes {
		if c.Same || (c.Conflict && o.Result != nil && len(o.Result.Kept) > 0) {
			continue
		}
		n++
		size += c.Bytes
		if len(parts) < 8 {
			parts = append(parts, fmt.Sprintf("%s (%s)", c.Path, c.Status))
		}
	}
	if n == 0 {
		return ""
	}
	more := ""
	if n > len(parts) {
		more = fmt.Sprintf(" and %d more", n-len(parts))
	}
	noun := "changes"
	if n == 1 {
		noun = "change"
	}
	return fmt.Sprintf("%s %d %s (%s): %s%s.", verb, n, noun, uploadSize(size), strings.Join(parts, ", "), more)
}

// HeldBackLine names what the copy rules held back, or "".
func (o *PushOutcome) HeldBackLine() string {
	h := o.Plan.HeldBack
	if len(h) == 0 {
		return ""
	}
	noun := "files"
	if len(h) == 1 {
		noun = "file"
	}
	shown := h
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return fmt.Sprintf("Held back: %s (%d %s). Share one anyway with --unmask.", strings.Join(shown, ", "), len(h), noun)
}
