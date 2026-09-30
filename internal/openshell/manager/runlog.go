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

// runState is the state of a sandbox's latest detached run.
type runState string

const (
	runNone        runState = "none"
	runRunning     runState = "running"
	runExited      runState = "exited"
	runInterrupted runState = "interrupted"
)

// detachedRun is what a sandbox's latest detached run left in harness.RunDir.
type detachedRun struct {
	State runState
	// Exit is the exit status of an exited run.
	Exit string
	// Started is the epoch second the run started (0: unknown).
	Started int64
}

// runLogDirName is the directory under <data_dir>/sandboxes/<name> where a
// stop keeps the log of the sandbox's latest detached run.
const runLogDirName = "runlog"

// Kept run log files: the end of the log, and keptRun.
const (
	runLogFile     = "latest.log"
	runLogMetaFile = "latest.json"
)

// runLogScript prints the end of the latest run's log in the run
// directory $1, at most $2 bytes (exit 3: there is no log). The run
// directory is the workload's: only a regular file is read.
const runLogScript = `d=$1
[ -f "$d/latest.log" ] || exit 3
exec tail -c "$2" "$d/latest.log" 2>/dev/null
`

// runLogWait bounds the read of a run's log at a stop.
const runLogWait = 30 * time.Second

// keptRun describes a kept run log (runLogMetaFile).
type keptRun struct {
	// SandboxID ties the log to the OpenShell sandbox it came from: a later
	// sandbox of the name never shows it.
	SandboxID string    `json:"sandbox_id,omitempty"`
	State     string    `json:"state"`
	Exit      string    `json:"exit,omitempty"`
	StartedAt time.Time `json:"started_at,omitzero"`
	KeptAt    time.Time `json:"kept_at"`
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
// goes ahead whatever happens here.
func (m *Manager) keepRunLog(ctx context.Context, gw *Gateway, b *box, run detachedRun) {
	if run.State == runNone {
		return
	}
	m.mu.Lock()
	name, id := b.rec.Name, b.sandboxID()
	m.mu.Unlock()
	meta := keptRun{SandboxID: id, State: sandboxapi.RunInterrupted, KeptAt: m.now().UTC()}
	if run.State == runExited {
		meta.State, meta.Exit = sandboxapi.RunExited, run.Exit
	}
	if run.Started > 0 {
		meta.StartedAt = time.Unix(run.Started, 0).UTC()
	}
	if run.State == runRunning {
		m.logf("sandbox %s: the stop ends its detached run, which was still going", name)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "run_interrupted",
			Message: "sandbox " + name + "'s detached run was still going; the stop ended it unfinished, and its log is kept " +
				"(`defenseclaw sandbox logs " + name + "`)"})
	}
	readCtx, cancel := context.WithTimeout(ctx, runLogWait+5*time.Second)
	defer cancel()
	res, err := gw.Client.Exec(readCtx, name, []string{"/bin/sh", "-c", runLogScript, "defenseclaw-run-log", harness.RunDir,
		strconv.Itoa(sandboxapi.MaxRunLogBytes)}, openshell.ExecOptions{Timeout: runLogWait, Attempts: 1, MaxOutputBytes: sandboxapi.MaxRunLogBytes})
	var log []byte
	switch {
	case err != nil:
		m.logf("sandbox %s: keep the log of its detached run: %v", name, err)
		return
	case res.ExitCode == 0:
		log = res.Stdout
	case res.ExitCode != 3:
		// 3: the run left no log; the rest is kept all the same.
		m.logf("sandbox %s: keep the log of its detached run: the read exited with status %d", name, res.ExitCode)
		return
	}
	if err := m.saveRunLog(name, meta, log); err != nil {
		m.logf("sandbox %s: keep the log of its detached run: %v", name, err)
	}
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
	dir := m.runLogDir(name)
	if err := os.Remove(filepath.Join(dir, runLogMetaFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := safefile.WritePrivate(filepath.Join(dir, runLogFile), log); err != nil {
		return err
	}
	return safefile.WritePrivate(filepath.Join(dir, runLogMetaFile), data)
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

// RunLog returns the log of the latest detached run the daemon kept when
// it last stopped the sandbox; lines > 0 keeps its last lines lines.
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
	if lines > 0 {
		log = lastLines(log, lines)
	}
	return &sandboxapi.RunLog{Name: name, State: meta.State, Exit: meta.Exit, StartedAt: meta.StartedAt, KeptAt: meta.KeptAt,
		Log: strings.ToValidUTF8(string(log), "\uFFFD")}, nil
}

// lastLines returns the last n lines of data.
func lastLines(data []byte, n int) []byte {
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return nil
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			n--
			if n == 0 {
				return append(data[i+1:len(data):len(data)], '\n')
			}
		}
	}
	return append(data[:len(data):len(data)], '\n')
}
