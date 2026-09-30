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
	"strconv"
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
// ends. A stop through DefenseClaw writes "interrupted" there first (this
// CLI before it asks for the stop, the daemon before it lets the harness
// exit), and the runner keeps that mark rather than the status the stop's
// SIGTERM gave the harness; a run the sandbox stopped under without one
// never writes latest.exit, its process being gone. When DefenseClaw stops
// a sandbox it keeps the run's log on this machine (cliStateDir), and
// `sandbox logs` reads it there.

// runState is the state of a sandbox's latest detached run.
type runState string

const (
	runNone        runState = "none"
	runRunning     runState = "running"
	runExited      runState = "exited"
	runInterrupted runState = "interrupted"
)

// detachedRun is what a sandbox's latest detached run left in RunDir.
type detachedRun struct {
	State runState `json:"state"`
	// Exit is the exit status of an exited run.
	Exit string `json:"exit,omitempty"`
	// Started is the epoch second the run started (0: unknown).
	Started int64 `json:"started,omitempty"`
}

// runAlive is a POSIX sh function: the latest run's runner is alive. A pid
// counts only while its command line is the runner's (it names
// latest.exit), so a pid reused after the sandbox restarted is not taken for
// the run; a process table that hides command lines trusts the pid. A zombie
// is not alive. An empty command line is a runner caught mid-exec (setsid,
// nohup and sh exec one another as it starts), so it counts as alive rather
// than as a run that ended without recording its status.
const runAlive = `alive() {
  pid=$(cat "$d/latest.pid" 2>/dev/null)
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  [ -r "/proc/$pid/cmdline" ] || return 0
  [ "$(sed 's/^.*) //' "/proc/$pid/stat" 2>/dev/null | cut -c1)" != Z ] || return 1
  cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)
  [ -n "$cmd" ] || return 0
  printf '%s\n' "$cmd" | grep -q latest.exit
}
`

// runStateScript prints the latest run's state as key=value lines.
const runStateScript = `d=$1
` + runAlive + `if [ ! -e "$d/latest.log" ] && [ ! -e "$d/latest.pid" ]; then echo state=none; exit 0; fi
echo "started=$(cat "$d/latest.started" 2>/dev/null)"
if alive; then echo state=running; exit 0; fi
if [ -s "$d/latest.exit" ]; then
  s=$(head -c 32 "$d/latest.exit" | tr -d '\n')
  case "$s" in
    interrupted) echo state=interrupted ;;
    *) echo state=exited; echo "exit=$s" ;;
  esac
  exit 0
fi
echo state=interrupted
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
` + runAlive + `[ -e "$d/latest.log" ] || exit 3
tail -n "$n" -F "$d/latest.log" 2>/dev/null &
t=$!
while alive && [ ! -s "$d/latest.exit" ]; do sleep 1; done
sleep 1
kill "$t" 2>/dev/null
wait "$t" 2>/dev/null
exit 0
`

// runMarkScript records that the latest run is interrupted (the sandbox is
// about to stop) unless it ended meanwhile, and prints the tail of its log
// for the copy this machine keeps.
const runMarkScript = `d=$1
` + runAlive + `if alive && [ ! -s "$d/latest.exit" ]; then printf 'interrupted\n' > "$d/latest.exit"; fi
tail -c 1048576 "$d/latest.log" 2>/dev/null
exit 0
`

// maxSavedRunLog bounds the run log DefenseClaw keeps on this machine.
const maxSavedRunLog = 1 << 20

func parseDetachedRun(out string) detachedRun {
	run := detachedRun{State: runNone}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "state":
			switch s := runState(v); s {
			case runRunning, runExited, runInterrupted, runNone:
				run.State = s
			}
		case "exit":
			run.Exit = v
		case "started":
			run.Started, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return run
}

// detachedRun reads the state of a running sandbox's latest detached run.
func (a *App) detachedRun(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox) (detachedRun, error) {
	inv, err := cli.Exec(sb.Name, []string{"sh", "-c", runStateScript, "sh", RunDir}, openshell.CLIExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		return detachedRun{}, err
	}
	var out bytes.Buffer
	code, err := a.Streamer.Stream(ctx, inv, &out, io.Discard)
	if err != nil {
		return detachedRun{}, err
	}
	if code != 0 {
		return detachedRun{}, fmt.Errorf("read the detached run of %s: exit status %d", sb.Name, code)
	}
	return parseDetachedRun(out.String()), nil
}

// beforeStop runs before DefenseClaw stops a running sandbox (`sandbox
// stop`, undo): a detached run still going is confirmed on a terminal
// (unless yes) and said otherwise, marked interrupted, and its log kept on
// this machine; a finished run's log is kept too. It returns false when the
// user keeps the run going.
func (a *App) beforeStop(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox, yes bool) (bool, error) {
	if sb.Phase != "ready" {
		return true, nil
	}
	run, err := a.detachedRun(ctx, cli, sb)
	if err != nil || run.State == runNone {
		// Without an answer the stop goes ahead, as it did before runs
		// were checked.
		return true, nil
	}
	if run.State == runRunning {
		what := sb.Name + "'s detached run" + a.startedText(run.Started) + " is still going; stopping the sandbox ends it"
		if a.IO.TTY && !yes {
			ok, err := a.ask(what+". Stop anyway?", false, false)
			if err != nil || !ok {
				return false, err
			}
		} else {
			a.warn(what)
		}
	}
	a.keepRunLog(ctx, cli, sb, run)
	return true, nil
}

// keepRunLog marks a detached run the coming stop ends as interrupted and
// keeps the run's log on this machine (best effort: the stop goes ahead).
func (a *App) keepRunLog(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox, run detachedRun) {
	if run.State == runNone {
		return
	}
	inv, err := cli.Exec(sb.Name, []string{"sh", "-c", runMarkScript, "sh", RunDir}, openshell.CLIExecOptions{Timeout: time.Minute})
	if err != nil {
		return
	}
	var log limitedBuffer
	log.max = maxSavedRunLog
	if code, err := a.Streamer.Stream(ctx, inv, &log, io.Discard); err != nil || code != 0 {
		return
	}
	if run.State == runRunning {
		run = detachedRun{State: runInterrupted, Started: run.Started}
	}
	if err := a.saveRunLog(sb, run, log.Bytes()); err != nil {
		a.warn("could not keep " + sb.Name + "'s run log on this machine: " + err.Error())
	}
}

func (a *App) startedText(started int64) string {
	if started <= 0 {
		return ""
	}
	return " (started " + a.clock(time.Unix(started, 0)) + ")"
}

// savedRun is a detached run's log DefenseClaw kept on this machine when it
// stopped the sandbox.
type savedRun struct {
	detachedRun
	// SandboxID ties the log to the sandbox: a later sandbox of the same
	// name does not show it.
	SandboxID string    `json:"sandbox_id,omitempty"`
	Name      string    `json:"name"`
	SavedAt   time.Time `json:"saved_at"`
}

// cliStateDir is where the CLI keeps what it remembers of a sandbox: the
// run log it kept at a stop and the undo point the user accepted (M2). The
// daemon never reads it; `sandbox delete` removes it.
func (a *App) cliStateDir(name string) (string, error) {
	if !openshell.ValidSandboxName(name) {
		return "", fmt.Errorf("%w: sandbox %q", openshell.ErrInvalidName, name)
	}
	return filepath.Join(a.dataDir(), "sandboxes", name, "cli"), nil
}

func (a *App) saveRunLog(sb *sandboxapi.Sandbox, run detachedRun, log []byte) error {
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return err
	}
	meta, err := json.Marshal(savedRun{detachedRun: run, SandboxID: sb.ID, Name: sb.Name, SavedAt: a.Now().UTC()})
	if err != nil {
		return err
	}
	if err := safefile.WritePrivate(filepath.Join(dir, "run.log"), log); err != nil {
		return err
	}
	return safefile.WritePrivate(filepath.Join(dir, "run.json"), meta)
}

// savedRunLog returns the log kept for this sandbox, if any.
func (a *App) savedRunLog(sb *sandboxapi.Sandbox) (*savedRun, []byte, error) {
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
	var meta savedRun
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, nil, fmt.Errorf("read the kept run log of %s: %w", sb.Name, err)
	}
	if meta.SandboxID != sb.ID {
		return nil, nil, nil
	}
	log, err := safefile.ReadRegularFileBounded(filepath.Join(dir, "run.log"), maxSavedRunLog+1)
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

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		_, _ = b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
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
