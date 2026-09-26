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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SandboxInfo is the part of an OpenShell sandbox resume detection needs.
type SandboxInfo struct {
	Name      string
	Labels    map[string]string
	Phase     string
	CreatedAt time.Time
}

// SandboxLister finds sandboxes whose labels include every given pair.
// The OpenShell client implements it with a label-selector list call.
type SandboxLister interface {
	ListSandboxes(ctx context.Context, labels map[string]string) ([]SandboxInfo, error)
}

// ResumeCandidate is an existing sandbox for the same folder.
type ResumeCandidate struct {
	Sandbox SandboxInfo
	// Mode is "mount" or "copy" (from the sandbox label).
	Mode string
	// Copy or Snapshot is the local record for the sandbox, when present.
	Copy     *CopyRecord
	Snapshot *SnapshotRecord
}

// resumablePhases are OpenShell phases a sandbox can be connected to or
// started again from.
var resumablePhases = map[string]bool{
	"Provisioning": true, "Starting": true, "Ready": true,
	"Stopping": true, "Stopped": true, "Completed": true,
}

// FindResumable returns the sandboxes labelled with project's identity,
// newest first, skipping ones that are being deleted or failed.
func FindResumable(ctx context.Context, lister SandboxLister, dataDir, project string) ([]ResumeCandidate, error) {
	abs, err := filepath.Abs(project)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace: resolve %s: %w", project, err)
	}
	key, value := ProjectLabel(real)
	boxes, err := lister.ListSandboxes(ctx, map[string]string{key: value})
	if err != nil {
		return nil, err
	}
	var out []ResumeCandidate
	for _, b := range boxes {
		if b.Labels[key] != value || !resumablePhases[b.Phase] || ValidateName(b.Name) != nil {
			continue
		}
		c := ResumeCandidate{Sandbox: b, Mode: b.Labels[ModeLabelKey]}
		if rec, err := LoadCopy(dataDir, b.Name); err == nil && rec.Project == real {
			c.Copy = rec
		}
		if rec, err := LoadSnapshot(dataDir, b.Name); err == nil && rec.Project == real {
			c.Snapshot = rec
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sandbox.CreatedAt.After(out[j].Sandbox.CreatedAt) })
	return out, nil
}

// RefreshOptions configures Refresh.
type RefreshOptions struct {
	// Stage carries the staging settings; Stage.Name selects the sandbox.
	Stage StageOptions
	Exec  Execer
	// Upload sends the new copy.
	Upload Uploader
	// Force discards work in the sandbox that was never pulled.
	Force bool
}

// Refresh replaces a copy-mode sandbox's copy with the project as it is
// now: it refuses when the sandbox holds work that was not pulled (unless
// Force), stages again, removes the old copy inside the sandbox, uploads
// and re-establishes the baseline.
func Refresh(ctx context.Context, opts RefreshOptions) (*CopyRecord, error) {
	name := opts.Stage.Name
	old, err := LoadCopy(opts.Stage.DataDir, name)
	if err != nil {
		return nil, err
	}
	if old.UploadedAt != nil && !opts.Force {
		dirty, err := sandboxHasWork(ctx, opts.Exec, old)
		if err != nil {
			return nil, err
		}
		if dirty {
			return nil, fmt.Errorf("%w: pull or discard them first (sandbox %s)", ErrUnpulledChanges, name)
		}
	}
	stage := opts.Stage
	stage.Replace = true
	if stage.Project == "" {
		stage.Project = old.Project
	}
	if _, err := Stage(ctx, stage); err != nil {
		return nil, err
	}
	if err := removeRemoteCopy(ctx, opts.Exec, name, old); err != nil {
		return nil, err
	}
	if _, err := Upload(ctx, stage.DataDir, name, opts.Upload); err != nil {
		return nil, err
	}
	return EstablishBaseline(ctx, stage.DataDir, name, opts.Exec)
}

// sandboxHasWork reports whether the sandbox copy differs from what was
// uploaded (new commits, or a working tree other than the baseline's).
func sandboxHasWork(ctx context.Context, ex Execer, rec *CopyRecord) (bool, error) {
	res, err := ex.Exec(ctx, rec.Name, ExecRequest{Argv: []string{"sh", "-c", captureScript(rec, false) + "\nprintf 'basetree=%s\\n' \"$(g rev-parse \"$B^{tree}\")\""}, Timeout: 5 * time.Minute})
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, fmt.Errorf("workspace: inspect the sandbox copy (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
	}
	kv := parseKV(res.Stdout)
	head := rec.Head
	if rec.Kind == CopyPlain {
		head = rec.Baseline
	}
	return kv["head"] != head || kv["tree"] != kv["basetree"] || kv["tree"] == "", nil
}

// removeRemoteCopy deletes the previous copy (and hidden git dir) inside
// the sandbox before a fresh upload. Paths are checked to stay under the
// expected roots.
func removeRemoteCopy(ctx context.Context, ex Execer, name string, rec *CopyRecord) error {
	targets := []string{rec.RemoteDir}
	if rec.Kind == CopyPlain {
		targets = append(targets, rec.RemoteGitDir)
	}
	var quoted []string
	for _, t := range targets {
		clean := path.Clean(t)
		if clean != t || !strings.HasPrefix(clean, "/sandbox/") || strings.Count(clean, "/") < 3 {
			return fmt.Errorf("workspace: refusing to remove %q inside the sandbox", t)
		}
		quoted = append(quoted, shellQuote(clean))
	}
	res, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", "rm -rf -- " + strings.Join(quoted, " ")}, Timeout: 5 * time.Minute})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New("workspace: remove the previous copy in the sandbox: " + lastLines(res.Stderr, 5))
	}
	return nil
}
