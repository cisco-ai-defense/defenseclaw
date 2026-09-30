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

package harness

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Detached runs. `sandbox run --detach` starts the harness in the
// background inside the sandbox, as the latest run in RunDir: its output
// goes to a dated log that latest.log links to, its runner's pid to
// latest.pid, its start (epoch seconds) to latest.started and its exit
// status to latest.exit once it ends. A stop marks a run it ends with
// "interrupted" there, which the runner keeps. The CLI (`sandbox logs`,
// `sandbox stop`, the end of a session) and the daemon (every stop) read
// how the latest run stands with the same script (RunStateFunc) and parser
// (ParseRun), so they always agree.

// DetachedRun is how a sandbox's latest detached run stands.
type DetachedRun struct {
	// State is sandboxapi.RunNone without a run.
	State sandboxapi.RunState `json:"state"`
	// Exit is the exit status of an exited run.
	Exit string `json:"exit,omitempty"`
	// Started is the epoch second the run started (0: unknown).
	Started int64 `json:"started,omitempty"`
}

// RunReadFunc defines the POSIX sh functions rs_open FILE, which opens
// FILE on fd 3 when what it names is a regular file as it is opened, and
// rs_read FILE BYTES, which prints at most the first BYTES of a regular
// FILE (callers read it in a command substitution). The run directory is
// the workload's: a FIFO, a device or a link to one must neither hold a
// read nor feed it without end, nor be opened at all when it is there to
// be seen, so callers look first ([ -f ]), and rs_open covers one swapped
// in after that look. Its open is read-write, which never waits for a
// FIFO's other end as a read-only one does, and its check is of what was
// opened (/dev/fd/3), so nothing can change in between. An open that fails
// ends the shell, as a redirection error of exec does (in rs_read's command
// substitution, a subshell that then prints nothing). head and tail are
// the image's, from the root-owned /usr/bin. The functions keep their
// arguments in variables of their own first: an old bash as sh loses the
// caller's positional parameters across a function that runs exec.
const RunReadFunc = `rs_open() {
  rs_of=$1
  { exec 3<>"$rs_of"; } 2>/dev/null || return 1
  [ -f /dev/fd/3 ] || [ -f /proc/self/fd/3 ] || { exec 3<&-; return 1; }
}
rs_read() {
  rs_rf=$1; rs_rn=$2
  [ -f "$rs_rf" ] && rs_open "$rs_rf" || return 1
  /usr/bin/head -c "$rs_rn" <&3 2>/dev/null
  exec 3<&-
}
`

// RunAliveFunc defines the POSIX sh function run_alive DIR (and
// RunReadFunc's): the latest run in the run directory DIR is going while
// the pid in latest.pid is a live process whose command line names
// latest.exit, its runner's (a pid reused after the sandbox restarted is
// not the run's; a process table that hides command lines trusts the pid).
const RunAliveFunc = RunReadFunc + `run_alive() {
  rs_pid=$(rs_read "$1/latest.pid" 32 | tr -d '\n')
  case "$rs_pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$rs_pid" 2>/dev/null || return 1
  [ ! -r "/proc/$rs_pid/cmdline" ] || tr '\0' ' ' <"/proc/$rs_pid/cmdline" 2>/dev/null | grep -q latest.exit
}
`

// RunStateFunc defines the POSIX sh function run_state DIR [mark] (and
// RunAliveFunc's), which prints how the latest run in the run directory DIR
// stands, nothing without a run: run=running while its runner is alive and
// latest.exit holds no status of the run's own, run=exited with
// run_exit=<status> once it holds one, run=interrupted when the run ended
// without one (a stop ended it, or the sandbox stopped under it); then
// run_started=<epoch seconds>. With mark, a run that has no status yet is
// then marked interrupted in latest.exit (a stop is about to end it), after
// the lines are printed, so a mark held up still leaves them said: the mark
// goes through rs_open's descriptor, checked to be a regular file, so a
// FIFO swapped in (whose full buffer would hold a write) gets none.
const RunStateFunc = RunAliveFunc + `run_state() {
  rs_d=$1; rs_mark=$2
  [ -e "$rs_d/latest.pid" ] || [ -e "$rs_d/latest.log" ] || return 0
  rs_run=interrupted
  run_alive "$rs_d" && rs_run=running
  rs_exit=$(rs_read "$rs_d/latest.exit" 32)
  if [ -n "$rs_exit" ]; then
    rs_exit=$(printf '%s' "$rs_exit" | tr -dc 'A-Za-z0-9_.-')
    [ "$rs_exit" = interrupted ] || { rs_run=exited; echo "run_exit=$rs_exit"; }
  fi
  rs_started=$(rs_read "$rs_d/latest.started" 32 | tr -dc 0-9)
  echo "run=$rs_run"
  echo "run_started=$rs_started"
  if [ -z "$rs_exit" ] && [ "$rs_mark" = mark ] && [ -e "$rs_d/latest.pid" ] &&
    { [ ! -e "$rs_d/latest.exit" ] || { [ -f "$rs_d/latest.exit" ] && [ ! -s "$rs_d/latest.exit" ]; }; }; then
    ( rs_open "$rs_d/latest.exit" && printf 'interrupted\n' >&3 ) 2>/dev/null
  fi
  return 0
}
`

// ParseRun reads what run_state printed (RunStateFunc), among other
// whitespace-separated output: a State of sandboxapi.RunNone without a
// run.
func ParseRun(out []byte) DetachedRun {
	run := DetachedRun{State: sandboxapi.RunNone}
	for _, tok := range strings.Fields(string(out)) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		switch k {
		case "run":
			switch s := sandboxapi.RunState(v); s {
			case sandboxapi.RunRunning, sandboxapi.RunExited, sandboxapi.RunInterrupted:
				run.State = s
			}
		case "run_exit":
			run.Exit = v
		case "run_started":
			run.Started, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return run
}

// LastLines returns the last n lines of a run's log.
func LastLines(data []byte, n int) []byte {
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
