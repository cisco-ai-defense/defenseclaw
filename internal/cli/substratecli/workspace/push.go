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
	Label   string
	Timeout time.Duration
}

// PushOutcome is what Push found and did.
type PushOutcome struct {
	Plan       *osw.PushPlan
	Result     *osw.PushResult
	Checkpoint string
}

// ErrPushHostCopy: the Windows host copy has no push yet.
var ErrPushHostCopy = errors.New("push is not available for a copy started on Windows yet; run the agent again from this folder to send a new copy")

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
	start.Unmask = append(append([]string(nil), rec.Unmasked...), start.Unmask...)
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
	}
	cp, err := Checkpoint(ctx, CheckpointOptions{Exec: opts.Transport, Dir: rec.RemoteDir, DataDir: dataDir, Name: opts.Name, Label: opts.Label})
	if err != nil {
		return out, fmt.Errorf("save a restore point before the push: %w", err)
	}
	out.Checkpoint = cp.ID
	if c, ok := opts.Transport.(*Client); ok {
		prev := c.Op
		c.Op = opts.Op
		if c.Op == "" {
			c.Op = relay.OpPush
		}
		defer func() { c.Op = prev }()
	}
	res, err := plan.Send(ctx, opts.Transport, mode, cp.ID)
	if err != nil {
		return out, cleanErr("send the changes", err)
	}
	out.Result = res
	return out, nil
}

// SendLine is the one-line summary of what a push sends (or would).
func (o *PushOutcome) SendLine(verb string) string {
	var parts []string
	var n int
	var size int64
	for _, c := range o.Plan.Changes {
		if c.Same {
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
