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

package cli

// GAP-0420: a --task run is resumed after a crash (at least once).
//
// A crashed actor comes back at its last durable snapshot, which for a
// headless task is usually the one from before the folder was copied in:
// the copy, the restore points and the relay's task record and log are gone
// with the worker. The launcher that started the task keeps what it needs
// to start it again on this computer: the task text (already in the person's
// shell history and the cluster's intent store), the folder and the copy
// flags. undo of such an agent copies the folder in again and starts the
// task from the beginning. The relay only runs the text the actor was
// registered for (GAP-0071), so the record cannot widen what the agent
// does; anything the task did outside its folder before the crash may
// happen again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const substrateTaskRecordVersion = 1

// substrateTaskRecord is the launcher's record of one --task run (mode
// 0600 under the data directory; no token, no secret value).
type substrateTaskRecord struct {
	Version  int    `json:"version"`
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	Prompt   string `json:"prompt"`
	// Project is the folder that was copied in ("" for --no-upload or
	// --clone); Clone and Ref the --clone source.
	Project     string    `json:"project,omitempty"`
	Clone       string    `json:"clone,omitempty"`
	Ref         string    `json:"ref,omitempty"`
	RemoteDir   string    `json:"remote_dir,omitempty"`
	Exclude     []string  `json:"exclude,omitempty"`
	Unmask      []string  `json:"unmask,omitempty"`
	MaxUploadMB int       `json:"max_upload_mb,omitempty"`
	Transport   string    `json:"transport,omitempty"`
	Started     time.Time `json:"started"`
}

func substrateTaskRecordPath(dataDir string, a api.Actor) string {
	return filepath.Join(dataDir, "substrate", "tasks", substrateCopyName(a)+".json")
}

// saveSubstrateTaskRecord writes rec for a; a failure is only a warning:
// the task runs, it just cannot be resumed from here.
func saveSubstrateTaskRecord(dataDir string, a api.Actor, rec substrateTaskRecord) error {
	rec.Version, rec.Atespace, rec.Name, rec.UID = substrateTaskRecordVersion, a.Atespace, a.Name, a.UID
	p := substrateTaskRecordPath(dataDir, a)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// loadSubstrateTaskRecord reads the record of a's task; false when this
// computer did not start it, or the record is of another actor that had the
// same name (the UID differs).
func loadSubstrateTaskRecord(dataDir string, a api.Actor) (substrateTaskRecord, bool) {
	var rec substrateTaskRecord
	b, err := os.ReadFile(substrateTaskRecordPath(dataDir, a))
	if err != nil || json.Unmarshal(b, &rec) != nil {
		return rec, false
	}
	ok := rec.Version == substrateTaskRecordVersion && rec.Atespace == a.Atespace && rec.Name == a.Name &&
		rec.Prompt != "" && (a.UID == "" || rec.UID == a.UID)
	return rec, ok
}

// substrateTaskLost reports whether a's relay has no task: its run was lost
// with a crash. It waits while a recovered agent's relay starts.
func substrateTaskLost(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, transport string) (bool, error) {
	o, err := substrateAttachOptions(cmd, s, a, transport, true, attach.KeyReplayOff)
	if err != nil {
		return false, err
	}
	o.NoBanner = true
	st, err := attach.Status(ctx, o)
	for try := 1; err != nil && try <= substrateUndoStartTries && substrateRelayStarting(err); try++ {
		if serr := substrateSleep(ctx, 2*time.Second); serr != nil {
			return false, serr
		}
		st, err = attach.Status(ctx, o)
	}
	if err != nil {
		return false, substrateFail(err)
	}
	return latestSubstrateTask(st) == "", nil
}

// substrateRerunTask copies the recorded folder into a again and starts its
// task from the beginning, detached.
func substrateRerunTask(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, rec substrateTaskRecord, yes bool) error {
	w := cmd.ErrOrStderr()
	what := "Start the task again from the beginning"
	switch {
	case rec.Project != "":
		if fi, err := os.Stat(rec.Project); err != nil || !fi.IsDir() {
			return fmt.Errorf("%s/%s lost its task in a crash, and the folder it ran on (%s) is not on this computer any more; start the task again in a new agent", a.Atespace, a.Name, safetext.Line(rec.Project))
		}
		what = "Copy " + safetext.Line(rec.Project) + " into it again and start the task from the beginning"
	case rec.Clone != "":
		what = "Clone " + safetext.Line(rec.Clone) + " into it again and start the task from the beginning"
	}
	if !yes {
		ok, err := substrateConfirm(cmd, fmt.Sprintf("%s/%s lost its task when it crashed. %s? What the task did outside its folder before the crash may happen again.", a.Atespace, a.Name, what))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing changed.")
			return nil
		}
	}
	f := &substrateRunFlags{clone: rec.Clone, ref: rec.Ref, remoteDir: rec.RemoteDir, exclude: rec.Exclude, unmask: rec.Unmask, maxUploadMB: rec.MaxUploadMB, transport: rec.Transport}
	if rec.Project != "" {
		// The copy is staged as run stages it: the cluster upload limit
		// and upload scan, the masks and --unmask of the recorded run.
		prepared, err := substratePreflight(ctx, cmd, s, f, rec.Project)
		if err != nil {
			return err
		}
		defer prepared.Close()
		if err := substrateUploadFolder(ctx, cmd, s, a, prepared); err != nil {
			return err
		}
	}
	if rec.Clone != "" {
		if err := substrateCloneInActor(ctx, cmd, s, a, f); err != nil {
			return err
		}
	}
	o, err := substrateAttachOptions(cmd, s, a, rec.Transport, true, attach.KeyReplayOff)
	if err != nil {
		return err
	}
	if err := substrateStartDetached(ctx, o, rec.Prompt, nil); err != nil {
		return substrateFail(err)
	}
	// What the agent was asking about went with the lost run.
	if n := substrateCloseAsks(ctx, s.Client, a, "the agent crashed and its task was started again"); n > 0 {
		fmt.Fprintf(w, "Closed %d pending question(s) of %s.\n", n, a.Name)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Started the task again in %s/%s, from the beginning. Follow it with: defenseclaw substrate logs -f %s\n", a.Atespace, a.Name, a.Name)
	return nil
}

// substrateStartDetached posts prompt to the relay and returns once the
// task's start is seen; the task then runs on its own.
func substrateStartDetached(ctx context.Context, o attach.Options, prompt string, args []string) error {
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	started := false
	_, err := attach.RunTask(dctx, attach.TaskOptions{Options: o, Prompt: prompt, Args: args, Emit: func(e relay.TaskEvent) {
		if e.Type == "start" {
			started = true
			cancel()
		}
	}})
	if !started {
		return substrateFirstErr(err, errors.New("the task did not start"))
	}
	return nil
}
