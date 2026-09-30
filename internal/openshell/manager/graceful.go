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
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A stop (or an undo that stops the sandbox) used to tear the sandbox down
// under a running harness: the harness died with the container, its
// SessionEnd hook never ran, and its terminal showed OpenShell's "exec
// relay closed before the command reported an exit status". The manager now
// asks the harness to exit first (SIGTERM to its processes, found by the
// install root their executable or script lies under) and waits a moment
// for them to go: a harness that exits runs its end-of-session hook, and its
// terminal ends like a /exit. A detached run the stop ends this way is
// marked interrupted first, so `sandbox logs` does not take the status the
// SIGTERM gave it for the run's own ending. The stop goes ahead whatever
// the sandbox answers.
//
// On a driver whose stop does not flush the workload's writes (the MicroVM
// driver, openshell.Driver.StopFlushes), a file written and not synced
// before the stop comes back empty: a copy sandbox's unpulled work would
// be lost at every stop. The same exec therefore ends with sync(1), after
// the harness has exited and written its last files, and every stop goes
// through it.

// Harness shutdown bounds: how long the in-sandbox script waits for the
// harness to exit, how long the exec of it may take in all, and how much
// longer the flush of the sandbox's disk may add.
const (
	harnessExitWait   = 8 * time.Second
	harnessExitBudget = harnessExitWait + 7*time.Second
	flushWait         = 20 * time.Second
)

// flushTrap makes endHarnessScript flush the sandbox's disk as it ends,
// whichever way it ends, and say so: "synced" follows how the harness
// ended.
const flushTrap = "trap '/bin/sync && echo synced' EXIT\n"

// endHarnessScript sends SIGTERM to the harness processes of the sandbox
// user and waits up to $2 tenths of a second for them to exit. A harness
// process is one whose executable, or one of whose first three arguments
// resolved (the launcher runs /usr/local/bin/<command>, a link into the
// install root; a script harness's interpreter runs a script there), lies
// under the install root $1. The harness's executable link is often not
// readable to the exec (a process that is not dumpable), its command line
// always is. Before any of that, a detached run in the run directory $3
// (harness.RunDir) that has not ended is marked interrupted, as `sandbox
// stop` marks it: its runner keeps the mark. It prints how it ended:
// "none", "exited" or "running".
const endHarnessScript = `root=$1; ticks=$2; runs=$3; self=$$; pids=
if [ -n "$runs" ] && [ -e "$runs/latest.pid" ] && [ ! -s "$runs/latest.exit" ]; then
  { printf 'interrupted\n' > "$runs/latest.exit"; } 2>/dev/null
fi
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  [ "$p" = "$self" ] && continue
  exe=$(readlink "$d/exe" 2>/dev/null) || exe=
  case "$exe" in "$root"/*) pids="$pids $p"; continue ;; esac
  for a in $(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -n 3); do
    case "$a" in /*) ;; *) continue ;; esac
    r=$(readlink -f "$a" 2>/dev/null) || r=$a
    case "$r" in "$root"/*) pids="$pids $p"; break ;; esac
  done
done
[ -n "$pids" ] || { echo none; exit 0; }
kill -TERM $pids 2>/dev/null
i=0
while [ "$i" -lt "$ticks" ]; do
  alive=
  for p in $pids; do [ -e "/proc/$p" ] && alive=1; done
  [ -z "$alive" ] && { echo exited; exit 0; }
  sleep 0.1
  i=$((i+1))
done
echo running`

// endHarness asks a ready sandbox's harness to exit before the sandbox is
// stopped, so its end-of-session hook reaches DefenseClaw, and flushes the
// sandbox's disk when the driver's stop would not. Failures are logged:
// the stop goes ahead either way.
func (m *Manager) endHarness(ctx context.Context, gw *Gateway, b *box) {
	m.mu.Lock()
	name, harnessName := b.rec.Name, b.rec.Harness
	ready := b.phase == audit.SandboxPhaseReady && !b.creating && !b.deleted && !b.retained
	m.mu.Unlock()
	if !ready {
		return
	}
	flush := !gw.Driver.StopFlushes
	spec, ok := harness.Get(harnessName)
	if !ok {
		if flush {
			m.flushSandbox(ctx, gw, name)
		}
		return
	}
	script, budget, timeout := endHarnessScript, harnessExitBudget, harnessExitWait+3*time.Second
	if flush {
		script, budget, timeout = flushTrap+script, budget+flushWait, timeout+flushWait
	}
	execCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ticks := int(harnessExitWait / (100 * time.Millisecond))
	res, err := gw.Client.Exec(execCtx, name, []string{"/bin/sh", "-c", script, "defenseclaw-end-harness", spec.InstallRoot(),
		strconv.Itoa(ticks), harness.RunDir}, openshell.ExecOptions{Timeout: timeout, Attempts: 1, MaxOutputBytes: 256})
	if err != nil {
		m.logf("sandbox %s: ask the harness to exit before the stop: %v", name, err)
		if flush {
			// The flush matters more than the harness's goodbye: once more,
			// on its own.
			m.flushSandbox(ctx, gw, name)
		}
		return
	}
	out := strings.Fields(string(res.Stdout))
	if len(out) > 0 && out[0] == "running" {
		m.logf("sandbox %s: the harness did not exit within %s; stopping the sandbox under it", name, harnessExitWait)
	}
	if flush && !slices.Contains(out, "synced") {
		m.flushFailed(name, fmt.Errorf("sync(1) did not finish (the sandbox answered %q)", strings.Join(out, " ")))
	}
}

// flushSandbox runs sync(1) in a ready sandbox before a stop its driver
// does not flush, and reports a failure.
func (m *Manager) flushSandbox(ctx context.Context, gw *Gateway, name string) {
	ctx, cancel := context.WithTimeout(ctx, flushWait+5*time.Second)
	defer cancel()
	res, err := gw.Client.Exec(ctx, name, []string{"/bin/sync"}, openshell.ExecOptions{Timeout: flushWait, Attempts: 1, MaxOutputBytes: 256})
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("sync(1) exited with status %d", res.ExitCode)
	}
	if err != nil {
		m.flushFailed(name, err)
	}
}

// flushFailed says a stop went ahead without the flush: what the workload
// wrote since the last one may come back empty.
func (m *Manager) flushFailed(name string, err error) {
	msg := "sandbox " + name + ": its disk could not be flushed before the stop; files written since the last flush may come back empty"
	m.logf("%s: %v", msg, err)
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "stop_unflushed", Message: msg})
}
