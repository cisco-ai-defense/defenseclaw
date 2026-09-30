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

// RunAliveFunc defines the POSIX sh function run_alive DIR: the latest run
// in the run directory DIR is going while the pid in latest.pid is a live
// process whose command line names latest.exit, its runner's (a pid reused
// after the sandbox restarted is not the run's; a process table that hides
// command lines trusts the pid). The run directory is the workload's: only
// a regular file is read, and only its first bytes.
const RunAliveFunc = `run_alive() {
  rs_pid=
  [ -f "$1/latest.pid" ] && rs_pid=$(head -c 32 "$1/latest.pid" 2>/dev/null | tr -d '\n')
  case "$rs_pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$rs_pid" 2>/dev/null || return 1
  [ ! -r "/proc/$rs_pid/cmdline" ] || tr '\0' ' ' <"/proc/$rs_pid/cmdline" 2>/dev/null | grep -q latest.exit
}
`

// RunStateFunc defines the POSIX sh function run_state DIR [mark] (and
// run_alive), which prints how the latest run in the run directory DIR
// stands, nothing without a run: run=running while its runner is alive and
// latest.exit holds no status of the run's own, run=exited with
// run_exit=<status> once it holds one, run=interrupted when the run ended
// without one (a stop ended it, or the sandbox stopped under it); then
// run_started=<epoch seconds>. With mark, a run that has no status yet is
// marked interrupted in latest.exit first (a stop is about to end it).
const RunStateFunc = RunAliveFunc + `run_state() {
  [ -e "$1/latest.pid" ] || [ -e "$1/latest.log" ] || return 0
  rs_run=interrupted; rs_started=
  run_alive "$1" && rs_run=running
  if [ -f "$1/latest.exit" ] && [ -s "$1/latest.exit" ]; then
    rs_exit=$(head -c 32 "$1/latest.exit" 2>/dev/null | tr -dc 'A-Za-z0-9_.-')
    [ "$rs_exit" = interrupted ] || { rs_run=exited; echo "run_exit=$rs_exit"; }
  elif [ "$2" = mark ] && [ -e "$1/latest.pid" ]; then
    { printf 'interrupted\n' > "$1/latest.exit"; } 2>/dev/null
  fi
  [ -f "$1/latest.started" ] && rs_started=$(head -c 32 "$1/latest.started" 2>/dev/null | tr -dc 0-9)
  echo "run=$rs_run"
  echo "run_started=$rs_started"
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
