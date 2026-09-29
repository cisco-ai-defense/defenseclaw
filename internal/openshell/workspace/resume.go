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
// GatewayClient implements it on an openshell.Client. The method is not
// named ListSandboxes because openshell.Client already has a method of
// that name returning []*openshell.Sandbox.
type SandboxLister interface {
	FindSandboxes(ctx context.Context, labels map[string]string) ([]SandboxInfo, error)
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
	boxes, err := lister.FindSandboxes(ctx, map[string]string{key: value})
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
// now. It refuses, unless Force, when the sandbox holds work that was not
// pulled (ErrUnpulledChanges; a sandbox still in the state its last pull
// took has none), or when that pull was never applied (ErrUnappliedPull):
// the refresh replaces the pull too. An applied pull, or one with nothing
// to apply, counts as handed back. Then it stages again, removes the old copy inside
// the sandbox, uploads and re-establishes the baseline. The local record,
// base.git and last pull stay as they were until all of that succeeded,
// so a failed refresh can be retried and a pull not yet applied still
// applies. A forced refresh that discards an unapplied pull says so in the
// new record's warnings.
func Refresh(ctx context.Context, opts RefreshOptions) (*CopyRecord, error) {
	name := opts.Stage.Name
	old, err := LoadCopy(opts.Stage.DataDir, name)
	if err != nil {
		return nil, err
	}
	live := old.inSandbox()
	last := lastPullOf(opts.Stage.DataDir, old)
	if !opts.Force {
		work, err := pendingWork(ctx, opts.Exec, live, last)
		if err != nil {
			return nil, err
		}
		switch {
		case work == CopyWorkUnpulled:
			return nil, fmt.Errorf("%w: pull or discard them first (sandbox %s)", ErrUnpulledChanges, name)
		case work != CopyWorkUnapplied:
		case last.Effective == "":
			return nil, fmt.Errorf("%w: it was refused (%s); refresh with --force to discard it (sandbox %s)", ErrUnappliedPull, strings.Join(last.Blocking, "; "), name)
		default:
			return nil, fmt.Errorf("%w: apply it, or refresh with --force to discard it (sandbox %s)", ErrUnappliedPull, name)
		}
	}
	stage := opts.Stage
	if stage.Project == "" {
		stage.Project = old.Project
	}
	lay, err := newLayout(stage.DataDir)
	if err != nil {
		return nil, err
	}
	rec, dir, err := stageCopy(ctx, lay, stage)
	if err != nil {
		return nil, err
	}
	installed := false
	defer func() {
		if !installed {
			_ = removeTree(dir)
		}
	}()
	// old's own paths too: a failed upload of it may have left files there.
	if err := removeRemoteCopy(ctx, opts.Exec, name, append([]*CopyRecord{old}, live...)...); err != nil {
		return nil, err
	}
	err = uploadStaged(ctx, dir, rec, opts.Upload)
	if err == nil {
		err = establishBaseline(ctx, rec, opts.Exec)
	}
	if err == nil && last != nil && !last.HandedOver() {
		rec.Warnings = append(rec.Warnings, fmt.Sprintf("the last pull of sandbox %s (%s) was never applied and is discarded", name, last.PulledAt.Format(time.RFC3339)))
	}
	if err == nil {
		err = installCopyDir(lay, rec, dir)
	}
	if err != nil {
		// The old copy is gone from the sandbox and the record still
		// describes it. Take out whatever of the new copy arrived as well:
		// a sandbox without a copy is one a retry refreshes without Force,
		// while a copy the record does not describe would pass for work.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_ = removeRemoteCopy(cleanup, opts.Exec, name, rec)
		return nil, err
	}
	installed = true
	return rec, nil
}

// CopyWork is what a copy-mode sandbox holds that was never handed back to
// the folder, which deleting or refreshing the sandbox discards.
type CopyWork int

const (
	// CopyWorkNone: nothing (no copy, a copy as uploaded, or one whose
	// last pull took exactly its state and was applied).
	CopyWorkNone CopyWork = iota
	// CopyWorkUnknown: the copy could not be looked at (the sandbox is not
	// running) and nothing recorded says it was handed back.
	CopyWorkUnknown
	// CopyWorkUnpulled: the copy changed since it was uploaded and since
	// its last pull.
	CopyWorkUnpulled
	// CopyWorkUnapplied: the last pull was never applied (or refused).
	CopyWorkUnapplied
)

// PendingWork reports the work the copy-mode sandbox name holds that was
// never handed back. ex looks at the copy inside the sandbox; a nil ex (the
// sandbox is not running) judges by the last pull alone. A sandbox without
// a copy record holds none.
func PendingWork(ctx context.Context, dataDir, name string, ex Execer) (CopyWork, error) {
	rec, err := LoadCopy(dataDir, name)
	if errors.Is(err, ErrCopyNotFound) {
		return CopyWorkNone, nil
	}
	if err != nil {
		return CopyWorkUnknown, err
	}
	live := rec.inSandbox()
	last := lastPullOf(dataDir, rec)
	if ex == nil {
		switch {
		case last != nil && !last.HandedOver():
			return CopyWorkUnapplied, nil
		case len(live) == 0:
			return CopyWorkNone, nil
		}
		return CopyWorkUnknown, nil
	}
	return pendingWork(ctx, ex, live, last)
}

// lastPullOf is the last pull of rec's copy, nil when there is none (or it
// was of a copy rec replaced).
func lastPullOf(dataDir string, rec *CopyRecord) *PullResult {
	last, _ := LoadPull(dataDir, rec.Name)
	if last != nil && last.Baseline != rec.Baseline {
		return nil
	}
	return last
}

// pendingWork looks at each copy the sandbox may hold (live) and then at
// the last pull of the record's copy.
func pendingWork(ctx context.Context, ex Execer, live []*CopyRecord, last *PullResult) (CopyWork, error) {
	for _, c := range live {
		state, err := inspectSandboxCopy(ctx, ex, c, last)
		if err != nil {
			return CopyWorkUnknown, err
		}
		if state == copyChanged {
			return CopyWorkUnpulled, nil
		}
	}
	if last != nil && !last.HandedOver() {
		return CopyWorkUnapplied, nil
	}
	return CopyWorkNone, nil
}

// copyState is what a refresh found in the sandbox copy.
type copyState int

const (
	// copyUnchanged: the copy is as uploaded, or not there at all
	// (removed by a refresh that failed later, or a new sandbox under the
	// same name), so it holds nothing to pull.
	copyUnchanged copyState = iota
	// copyPulled: the copy changed, and the last pull took exactly this
	// state (same HEAD, same working tree).
	copyPulled
	// copyChanged: the copy holds work that was never pulled.
	copyChanged
)

// inspectSandboxCopy compares the sandbox copy with what was uploaded (new
// commits, or a working tree other than the baseline's) and with last,
// the last pull of rec (nil if none).
func inspectSandboxCopy(ctx context.Context, ex Execer, rec *CopyRecord, last *PullResult) (copyState, error) {
	script := remoteGitPrelude(rec) + "\n" +
		`if [ ! -e "$W" ] && [ ! -L "$W" ] && [ ! -e "$G" ] && [ ! -L "$G" ]; then echo copy=missing; exit 0; fi` + "\n" +
		captureScript(rec, false) + "\nprintf 'basetree=%s\\n' \"$(g rev-parse \"$B^{tree}\")\""
	// Not Idempotent: a run the client gave up on may still be writing the
	// scratch index a second run would use.
	res, err := ex.Exec(ctx, rec.Name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: 5 * time.Minute})
	if err != nil {
		return copyChanged, err
	}
	if res.ExitCode != 0 {
		return copyChanged, fmt.Errorf("workspace: inspect the sandbox copy (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
	}
	kv := parseKV(res.Stdout)
	if kv["copy"] == "missing" {
		return copyUnchanged, nil
	}
	head := rec.Head
	if rec.Kind == CopyPlain {
		head = rec.Baseline
	}
	switch tree := kv["tree"]; {
	case tree == "":
		return copyChanged, nil
	case kv["head"] == head && tree == kv["basetree"]:
		return copyUnchanged, nil
	case last != nil && last.ResultTree != "" && kv["head"] == last.SandboxHead && tree == last.ResultTree:
		return copyPulled, nil
	}
	return copyChanged, nil
}

// removeRemoteCopy deletes previous copies (and hidden git dirs) inside
// the sandbox before a fresh upload. Paths are checked to stay under the
// expected roots.
func removeRemoteCopy(ctx context.Context, ex Execer, name string, recs ...*CopyRecord) error {
	var quoted []string
	seen := map[string]bool{}
	for _, rec := range recs {
		targets := []string{rec.RemoteDir}
		if rec.Kind == CopyPlain {
			targets = append(targets, rec.RemoteGitDir)
		}
		for _, t := range targets {
			clean := path.Clean(t)
			if clean != t || !strings.HasPrefix(clean, "/sandbox/") || strings.Count(clean, "/") < 3 {
				return fmt.Errorf("workspace: refusing to remove %q inside the sandbox", t)
			}
			if !seen[clean] {
				seen[clean] = true
				quoted = append(quoted, shellQuote(clean))
			}
		}
	}
	// Removing the same paths twice, even at once, is harmless.
	res, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", "rm -rf -- " + strings.Join(quoted, " ")}, Timeout: 5 * time.Minute, Idempotent: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New("workspace: remove the previous copy in the sandbox: " + lastLines(res.Stderr, 5))
	}
	return nil
}
