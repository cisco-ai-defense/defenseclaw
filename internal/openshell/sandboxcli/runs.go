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

package sandboxcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Detached runs. `sandbox run --detach` starts the harness in the background
// inside the sandbox (session.detach): its output goes to RunDir/<start>.log,
// which latest.log links to, its runner's pid to latest.pid, its start (epoch
// seconds) to latest.started and its exit status to latest.exit once it
// ends. Every stop through the daemon, whoever asks for it (this CLI, the
// TUI, the macOS app, undo, a tamper stop), writes "interrupted" there
// before it lets the harness exit, and the runner keeps that mark rather
// than the status the stop's SIGTERM gave the harness; a run the sandbox
// stopped under without one never writes latest.exit, its process being
// gone. The daemon's stop also keeps the end of the run's log on this
// machine, and `sandbox logs` of a stopped sandbox reads it from there
// (sandboxapi.RunLog). The CLI only asks first on a terminal when `sandbox
// stop` would end a run that is still going.

// runStateScript prints how the latest run stands, as the daemon's stop
// reads it (harness.RunStateFunc, harness.ParseRun).
const runStateScript = harness.RunStateFunc + `run_state "$1"
`

// runNoLog is the exit status of runTailScript and runFollowScript when the
// sandbox has no run log.
const runNoLog = 3

// runTailScript prints the last lines of the latest run's log (exit 3: there
// is no log). tail's own complaints stay in the sandbox: `sandbox logs` says
// what went wrong.
const runTailScript = `d=$1
n=$2
[ -e "$d/latest.log" ] || exit 3
exec tail -n "$n" "$d/latest.log" 2>/dev/null
`

// runFollowScript follows the latest run's log until the run ends (exit 3:
// there is no log).
const runFollowScript = `d=$1
n=$2
` + harness.RunAliveFunc + `[ -e "$d/latest.log" ] || exit 3
tail -n "$n" -F "$d/latest.log" 2>/dev/null &
t=$!
while run_alive "$d" && [ ! -s "$d/latest.exit" ]; do sleep 1; done
sleep 1
kill "$t" 2>/dev/null
wait "$t" 2>/dev/null
exit 0
`

// detachedRun reads the state of a running sandbox's latest detached run.
func (a *App) detachedRun(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox) (harness.DetachedRun, error) {
	inv, err := cli.Exec(sb.Name, []string{"sh", "-c", runStateScript, "sh", RunDir}, openshell.CLIExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		return harness.DetachedRun{}, err
	}
	var out bytes.Buffer
	code, err := a.Streamer.Stream(ctx, inv, &out, io.Discard)
	if err != nil {
		return harness.DetachedRun{}, err
	}
	if code != 0 {
		return harness.DetachedRun{}, fmt.Errorf("read the detached run of %s: exit status %d", sb.Name, code)
	}
	return harness.ParseRun(out.Bytes()), nil
}

// beforeStop runs before `sandbox stop` asks the daemon to stop a running
// sandbox: a detached run still going is confirmed on a terminal (unless
// yes) and said otherwise. The daemon's stop marks it interrupted and keeps
// its log. It returns false when the user keeps the run going, and whether
// no detached run is known to be going (idle).
func (a *App) beforeStop(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox, yes bool) (ok, idle bool, err error) {
	if sb.Phase != "ready" {
		return true, true, nil
	}
	run, err := a.detachedRun(ctx, cli, sb)
	if err != nil {
		// Without an answer the stop goes ahead, as it did before runs
		// were checked.
		return true, false, nil
	}
	if run.State == sandboxapi.RunNone {
		return true, true, nil
	}
	if run.State == sandboxapi.RunRunning {
		what := sb.Name + "'s detached run" + a.startedText(run.Started) + " is still going; stopping the sandbox ends it"
		if a.IO.TTY && !yes {
			ok, err := a.ask(what+". Stop anyway?", false, false)
			if err != nil || !ok {
				return false, false, err
			}
		} else {
			a.warn(what)
		}
	}
	return true, run.State != sandboxapi.RunRunning, nil
}

func (a *App) startedText(started int64) string {
	if started <= 0 {
		return ""
	}
	return " (started " + a.clock(time.Unix(started, 0)) + ")"
}

// legacyRun is a detached run's log an earlier CLI kept on this machine as
// it stopped the sandbox (cli/run.json and cli/run.log), before the daemon
// kept them: `sandbox logs` of a stopped sandbox the daemon kept none for
// still shows it.
type legacyRun struct {
	harness.DetachedRun
	// SandboxID ties the log to the sandbox: a later sandbox of the same
	// name does not show it.
	SandboxID string    `json:"sandbox_id,omitempty"`
	Name      string    `json:"name"`
	SavedAt   time.Time `json:"saved_at"`
}

// cliStateDir is where the CLI keeps what it remembers of a sandbox: the
// run's options and where a copy's work went (runstate.go), and what an
// earlier CLI kept there before the daemon did (a run log, the undo point
// the user accepted). The daemon never reads it; `sandbox delete` removes
// it.
func (a *App) cliStateDir(name string) (string, error) {
	if !openshell.ValidSandboxName(name) {
		return "", fmt.Errorf("%w: sandbox %q", openshell.ErrInvalidName, name)
	}
	return filepath.Join(a.dataDir(), "sandboxes", name, "cli"), nil
}

// legacyRunLog returns the log an earlier CLI kept for this sandbox, if
// any.
func (a *App) legacyRunLog(sb *sandboxapi.Sandbox) (*legacyRun, []byte, error) {
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return nil, nil, err
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, "run.json"), 64<<10)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var meta legacyRun
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, nil, fmt.Errorf("read the kept run log of %s: %w", sb.Name, err)
	}
	if meta.SandboxID != sb.ID {
		return nil, nil, nil
	}
	log, err := safefile.ReadRegularFileBounded(filepath.Join(dir, "run.log"), sandboxapi.MaxRunLogBytes+1)
	if err != nil {
		return nil, nil, err
	}
	return &meta, log, nil
}

// forgetCLIState removes what the CLI kept for a deleted sandbox, and the
// sandbox's data directory once nothing else is in it (the daemon removes
// it as it deletes the sandbox, but not while the CLI's state is there).
func (a *App) forgetCLIState(name string) {
	if dir, err := a.cliStateDir(name); err == nil {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Dir(dir))
	}
}

// Claude Code prints nothing in -p mode until it finishes, so a detached run
// of it streams JSON events (--output-format stream-json), which `sandbox
// logs` renders as lines.

// streamingArgs adds Claude Code's streaming output to a detached run's
// arguments, unless they choose an output format.
func streamingArgs(spec *harness.Spec, args []string) []string {
	if spec.Name != "claudecode" || slices.ContainsFunc(args, func(a string) bool {
		return a == "--output-format" || strings.HasPrefix(a, "--output-format=")
	}) {
		return args
	}
	out := append([]string(nil), args...)
	out = append(out, "--output-format", "stream-json")
	if !slices.Contains(out, "--verbose") {
		out = append(out, "--verbose")
	}
	return out
}

// streamRenderer turns Claude Code's stream-json events into readable lines
// as they arrive; other lines pass through.
type streamRenderer struct {
	w       io.Writer
	partial []byte
}

func (r *streamRenderer) Write(p []byte) (int, error) {
	r.partial = append(r.partial, p...)
	for {
		i := bytes.IndexByte(r.partial, '\n')
		if i < 0 {
			break
		}
		line := r.partial[:i]
		r.partial = r.partial[i+1:]
		if err := r.line(line); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Flush writes a last line without a newline.
func (r *streamRenderer) Flush() error {
	if len(r.partial) == 0 {
		return nil
	}
	line := r.partial
	r.partial = nil
	return r.line(line)
}

func (r *streamRenderer) line(line []byte) error {
	text, ok := renderStreamEvent(line)
	if !ok {
		_, err := r.w.Write(append(append([]byte(nil), line...), '\n'))
		return err
	}
	if text == "" {
		return nil
	}
	_, err := io.WriteString(r.w, text+"\n")
	return err
}

// streamEvent is the part of a Claude Code stream-json event the renderer
// reads.
type streamEvent struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	Model   string `json:"model"`
	Message *struct {
		Content []struct {
			Type    string          `json:"type"`
			Text    string          `json:"text"`
			Name    string          `json:"name"`
			Input   json.RawMessage `json:"input"`
			IsError bool            `json:"is_error"`
			Content json.RawMessage `json:"content"`
		} `json:"content"`
	} `json:"message"`
	Result   string  `json:"result"`
	IsError  bool    `json:"is_error"`
	NumTurns int     `json:"num_turns"`
	Duration int64   `json:"duration_ms"`
	Cost     float64 `json:"total_cost_usd"`
}

// renderStreamEvent renders one stream-json line; ok is false for a line
// that is not one (it is printed as it is).
func renderStreamEvent(line []byte) (string, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return "", false
	}
	var ev streamEvent
	if json.Unmarshal(line, &ev) != nil {
		return "", false
	}
	switch ev.Type {
	case "system":
		if ev.Subtype == "init" {
			if ev.Model != "" {
				return "● session started (" + ev.Model + ")", true
			}
			return "● session started", true
		}
		return "", true
	case "assistant":
		if ev.Message == nil {
			return "", true
		}
		var out []string
		for _, c := range ev.Message.Content {
			switch c.Type {
			case "text":
				if t := strings.TrimSpace(c.Text); t != "" {
					out = append(out, t)
				}
			case "tool_use":
				out = append(out, "→ "+c.Name+toolSummary(c.Input))
			}
		}
		return strings.Join(out, "\n"), true
	case "user":
		if ev.Message == nil {
			return "", true
		}
		var out []string
		for _, c := range ev.Message.Content {
			if c.Type == "tool_result" && c.IsError {
				out = append(out, "  ✗ "+truncate(toolResultText(c.Content), 200))
			}
		}
		return strings.Join(out, "\n"), true
	case "result":
		status := "finished"
		if ev.IsError || (ev.Subtype != "" && ev.Subtype != "success") {
			status = "failed (" + firstNonEmpty(ev.Subtype, "error") + ")"
		}
		text := "● " + status
		var facts []string
		if ev.NumTurns > 0 {
			facts = append(facts, plural(int64(ev.NumTurns), "turn", "turns"))
		}
		if ev.Duration > 0 {
			facts = append(facts, humanDuration(time.Duration(ev.Duration)*time.Millisecond))
		}
		if len(facts) > 0 {
			text += " after " + strings.Join(facts, ", ")
		}
		if ev.IsError && strings.TrimSpace(ev.Result) != "" {
			text += ": " + truncate(ev.Result, 300)
		}
		return text, true
	case "stream_event", "rate_limit_event":
		return "", true
	}
	return "", false
}

// toolSummary is ": <command or path>" for a tool call's input.
func toolSummary(input json.RawMessage) string {
	var in map[string]any
	if json.Unmarshal(input, &in) != nil {
		return ""
	}
	for _, k := range []string{"command", "file_path", "path", "pattern", "url", "description"} {
		if s, ok := in[k].(string); ok && strings.TrimSpace(s) != "" {
			return ": " + truncate(s, 120)
		}
	}
	return ""
}

// toolResultText is a tool result's text (a string or a list of text
// blocks).
func toolResultText(content json.RawMessage) string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			parts = append(parts, b.Text)
		}
		return strings.Join(parts, " ")
	}
	return ""
}
