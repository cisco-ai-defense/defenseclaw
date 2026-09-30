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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Detached runs. `sandbox run --detach` starts the harness in the
// background inside the sandbox, with its output, pid, start and exit
// status in harness.RunDir (sandboxcli's runs.go). The run's log lives in
// the sandbox, so it cannot be read while the sandbox is stopped: every stop
// through the daemon, whoever asked for it (`sandbox stop`, the TUI, the
// macOS app, undo, a tamper stop), looks at the latest run as it ends the
// harness (endHarness), and when there is one keeps the end of its log and
// how the run stood under <data_dir>/sandboxes/<name>/runlog/. `sandbox
// logs` of a stopped sandbox reads it there (GET /sandboxes/{name}/logs).
// The next stop that finds a run replaces it, and a delete removes it.

// runLogDirName is the directory under <data_dir>/sandboxes/<name> where a
// stop keeps the log of the sandbox's latest detached run.
const runLogDirName = "runlog"

// Kept run log files: the end of the log, and keptRun.
const (
	runLogFile     = "latest.log"
	runLogMetaFile = "latest.json"
)

// runLogScript prints the end of the latest run's log in the run
// directory $1, at most $2 bytes (exit 3: there is no log; another status:
// latest.log names something other than a regular file, or it could not be
// opened). The run directory is the workload's: only what is a regular file
// as it is opened is read (harness.RunReadFunc), and no more than $2 bytes
// of it however it grows.
const runLogScript = harness.RunReadFunc + `d=$1; n=$2
[ -e "$d/latest.log" ] || exit 3
[ -f "$d/latest.log" ] && rs_open "$d/latest.log" || exit 4
/usr/bin/tail -c "$n" <&3 2>/dev/null | /usr/bin/head -c "$n"
`

// runLogWait bounds the read of a run's log at a stop: at most
// sandboxapi.MaxRunLogBytes of a regular file.
const runLogWait = 10 * time.Second

// keptRun describes a kept run log (runLogMetaFile).
type keptRun struct {
	// SandboxID ties the log to the OpenShell sandbox it came from: a later
	// sandbox of the name never shows it.
	SandboxID string              `json:"sandbox_id,omitempty"`
	State     sandboxapi.RunState `json:"state"`
	Exit      string              `json:"exit,omitempty"`
	StartedAt time.Time           `json:"started_at,omitzero"`
	KeptAt    time.Time           `json:"kept_at"`
}

func (m *Manager) runLogDir(name string) string {
	return filepath.Join(m.opts.DataDir, "sandboxes", name, runLogDirName)
}

// sandboxID is the OpenShell id of a box's sandbox. Callers hold
// Manager.mu.
func (b *box) sandboxID() string {
	if b.rec.ID != "" {
		return b.rec.ID
	}
	if b.sb != nil {
		return b.sb.ID
	}
	return ""
}

// keepRunLog keeps the end of the log of the detached run a stop found in
// a ready sandbox (endHarness), with how the run stood: a run still going
// is interrupted by the stop, and the feed says so. Best effort: the stop
// goes ahead whatever happens here. A stop of a sandbox whose hooks were
// tampered with (hooks.on_tamper: stop) keeps no log: the log is the
// workload's, and that stop waits on nothing the workload controls, so it
// does not look at the run either (endHarness), and the log kept of an
// earlier run goes, since it may not be the latest run's.
func (m *Manager) keepRunLog(ctx context.Context, gw *Gateway, b *box, run harness.DetachedRun) {
	m.mu.Lock()
	name, id := b.rec.Name, b.sandboxID()
	tamper := b.tamperStop
	m.mu.Unlock()
	if tamper {
		if err := m.dropRunLogMeta(name); err != nil {
			m.logf("sandbox %s: forget the log kept of an earlier detached run: %v", name, err)
		}
		m.logf("sandbox %s: the log of a detached run is not kept: the stop is for hook tampering", name)
		return
	}
	if run.State == sandboxapi.RunNone {
		return
	}
	meta := keptRun{SandboxID: id, State: sandboxapi.RunInterrupted, KeptAt: m.now().UTC()}
	if run.State == sandboxapi.RunExited {
		meta.State, meta.Exit = sandboxapi.RunExited, run.Exit
	}
	if run.Started > 0 {
		meta.StartedAt = time.Unix(run.Started, 0).UTC()
	}
	if run.State != sandboxapi.RunRunning && m.keptAlready(name, meta) {
		// A run that was over at an earlier stop (a session since, or a
		// pull that started the sandbox): its log is kept as it is.
		return
	}
	// The log kept of an earlier run goes first: a read that fails must not
	// leave it to be shown as this run's.
	if err := m.dropRunLogMeta(name); err != nil {
		m.logf("sandbox %s: keep the log of its detached run: %v", name, err)
	}
	kept := m.readRunLog(ctx, gw, name, meta)
	if run.State != sandboxapi.RunRunning {
		return
	}
	m.logf("sandbox %s: the stop ends its detached run, which was still going", name)
	msg := "sandbox " + name + "'s detached run was still going; the stop ended it unfinished"
	switch {
	case kept:
		msg += ", and its log is kept (`defenseclaw sandbox logs " + name + "`)"
	default:
		msg += "; its log could not be kept"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "run_interrupted", Message: msg})
}

// readRunLog reads the end of the latest run's log out of the sandbox and
// keeps it with meta; it reports whether it did.
func (m *Manager) readRunLog(ctx context.Context, gw *Gateway, name string, meta keptRun) bool {
	readCtx, cancel := context.WithTimeout(ctx, runLogWait+5*time.Second)
	defer cancel()
	res, err := gw.Client.Exec(readCtx, name, []string{"/bin/sh", "-c", runLogScript, "defenseclaw-run-log", harness.RunDir,
		strconv.Itoa(sandboxapi.MaxRunLogBytes)}, openshell.ExecOptions{Timeout: runLogWait, Attempts: 1, MaxOutputBytes: sandboxapi.MaxRunLogBytes})
	var log []byte
	switch {
	case err != nil:
		m.logf("sandbox %s: keep the log of its detached run: %v", name, err)
		return false
	case res.ExitCode == 0:
		log = res.Stdout
	case res.ExitCode != 3:
		// 3: the run left no log; the rest is kept all the same.
		m.logf("sandbox %s: keep the log of its detached run: the read exited with status %d", name, res.ExitCode)
		return false
	}
	if err := m.saveRunLog(name, meta, log); err != nil {
		m.logf("sandbox %s: keep the log of its detached run: %v", name, err)
		return false
	}
	return true
}

// keptAlready reports whether the kept run log is of the run meta
// describes, as it stands: the same sandbox, start and ending.
func (m *Manager) keptAlready(name string, meta keptRun) bool {
	if meta.StartedAt.IsZero() {
		return false
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(m.runLogDir(name), runLogMetaFile), 64<<10)
	if err != nil {
		return false
	}
	var kept keptRun
	if json.Unmarshal(data, &kept) != nil {
		return false
	}
	return kept.SandboxID == meta.SandboxID && kept.StartedAt.Equal(meta.StartedAt) && kept.State == meta.State && kept.Exit == meta.Exit
}

// saveRunLog writes a kept run log. The earlier metadata goes first and the
// new one last, so a reader never pairs one run's metadata with another
// run's log: a log without metadata is never shown.
func (m *Manager) saveRunLog(name string, meta keptRun, log []byte) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return fmt.Errorf("%w: sandbox %q", openshell.ErrInvalidName, name)
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := m.dropRunLogMeta(name); err != nil {
		return err
	}
	dir := m.runLogDir(name)
	if err := safefile.WritePrivate(filepath.Join(dir, runLogFile), log); err != nil {
		return err
	}
	return safefile.WritePrivate(filepath.Join(dir, runLogMetaFile), data)
}

// dropRunLogMeta removes the metadata of the kept run log, which hides the
// log: a log without metadata is never shown.
func (m *Manager) dropRunLogMeta(name string) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return fmt.Errorf("%w: sandbox %q", openshell.ErrInvalidName, name)
	}
	if err := os.Remove(filepath.Join(m.runLogDir(name), runLogMetaFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// removeRunLog removes a gone sandbox's kept run log.
func (m *Manager) removeRunLog(name string) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return nil
	}
	if err := os.RemoveAll(m.runLogDir(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the kept run log of %s: %w", name, err)
	}
	return nil
}

// RunLog returns the log of a detached run the daemon kept when it stopped
// the sandbox, with the run's start (StartedAt) to say which run it is of: a
// stop that finds a run replaces it (or drops it when it cannot keep the new
// one), and one that could not look at the run leaves it. lines > 0 keeps
// its last lines lines.
func (m *Manager) RunLog(_ context.Context, name string, lines int) (*sandboxapi.RunLog, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	id, retained := b.sandboxID(), b.retained
	m.mu.Unlock()
	notKept := sandboxapi.Errorf(sandboxapi.CodeNotFound, "no log of a detached run of sandbox %s was kept", name)
	if retained || !openshell.ValidSandboxName(name) || name == recordDirName {
		return nil, notKept
	}
	dir := m.runLogDir(name)
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, runLogMetaFile), 64<<10)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, notKept
	}
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "read the kept run log of %s: %v", name, err)
	}
	var meta keptRun
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "read the kept run log of %s: %v", name, err)
	}
	if meta.SandboxID != "" && id != "" && meta.SandboxID != id {
		return nil, notKept
	}
	log, err := safefile.ReadRegularFileBounded(filepath.Join(dir, runLogFile), sandboxapi.MaxRunLogBytes+1)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "read the kept run log of %s: %v", name, err)
	}
	// A stop may have kept another run's log between the two reads
	// (saveRunLog drops the metadata, writes the log, then the metadata):
	// the metadata read again must be the same, or the log is not this
	// run's.
	if again, err := safefile.ReadRegularFileBounded(filepath.Join(dir, runLogMetaFile), 64<<10); err != nil || !bytes.Equal(again, data) {
		return nil, notKept
	}
	if lines > 0 {
		log = harness.LastLines(log, lines)
	}
	return &sandboxapi.RunLog{Name: name, State: meta.State, Exit: meta.Exit, StartedAt: meta.StartedAt, KeptAt: meta.KeptAt,
		Log: strings.ToValidUTF8(string(log), "\uFFFD")}, nil
}
