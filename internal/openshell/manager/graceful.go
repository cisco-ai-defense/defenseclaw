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
// terminal ends like a /exit. The stop goes ahead whatever the sandbox
// answers.
//
// The same exec looks at the sandbox's latest detached run (`sandbox run
// --detach`, harness.RunDir) first, whoever asked for the stop (the CLI,
// the TUI, the macOS app, undo, a tamper stop): one that has not ended is
// marked interrupted, so `sandbox logs` does not take the status the
// SIGTERM gave it for the run's own ending, and once the harness has
// exited the stop keeps the end of the run's log on this machine
// (runlog.go), where `sandbox logs` reads it while the sandbox is stopped.
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

// An automatic stop of a legacy MicroVM (stopWithFlush with requireFlush)
// must not lose what the workload writes after the flush: sync(1) on its
// own proves nothing about a background process that goes on writing until
// OpenShell kills the VM, which 0.1.3 does without a flush. That stop's
// exec therefore pauses the guest's processes (quiesceFunc) before it
// flushes, and they stay paused through the stop: a paused process writes
// nothing more. A VM that keeps running gets them back (thawGuest).

// quiesceWait bounds how long quiesceFunc waits for the guest's processes
// to stop, thawWait how long letting them run again may take.
const (
	quiesceWait  = 5 * time.Second
	quiesceTicks = int(quiesceWait / (100 * time.Millisecond))
	thawWait     = 10 * time.Second
)

// quiesceFunc defines quiesce PROC TICKS. It sends SIGSTOP to every process
// of the exec's own user in the guest whose proc file system is PROC, except
// PID 1, the exec's shell, its ancestors (the supervisor's exec relay) and
// its children, and waits up to TICKS tenths of a second until every one of
// them is stopped. It prints frozen=PID for each process it stopped, then
// "quiesced"; or, when one cannot be stopped or does not stop in time, it
// lets them all run again and prints "unquiesced". The workload runs as the
// sandbox user, the exec's, with no new privileges, so the exec can stop
// every process the workload started; another user's process is
// OpenShell's own. Kernel threads (no memory of their own) and zombies write
// nothing. Between its looks at PROC it runs only shell builtins, so it
// never finds a command of its own to stop.
const quiesceFunc = `quiesce() {
  proc=$1 qticks=$2 me=$$ uid= anc=" " frozen= n=0 p=$$
  while [ -n "$p" ] && [ "$p" != 0 ]; do
    anc="$anc$p " pp=
    [ -r "$proc/$p/status" ] || break
    while read -r k v _; do
      case $k in PPid:) pp=$v ;; Uid:) [ "$p" = "$me" ] && uid=$v ;; esac
    done 2>/dev/null < "$proc/$p/status"
    p=$pp
  done
  [ -n "$uid" ] || { echo unquiesced; return 1; }
  while :; do
    left= stuck=
    for d in "$proc"/[0-9]*; do
      p=${d##*/}
      [ "$p" = 1 ] && continue
      case $anc in *" $p "*) continue ;; esac
      [ -r "$d/status" ] || continue
      st= pp= u= vm=
      while read -r k v _; do
        case $k in State:) st=$v ;; PPid:) pp=$v ;; Uid:) u=$v ;; VmSize:) vm=$v ;; esac
      done 2>/dev/null < "$d/status"
      [ "$pp" = "$me" ] && continue
      [ "$u" = "$uid" ] && [ -n "$vm" ] || continue
      case $st in T|t|Z|X|'') continue ;; esac
      left=1
      if kill -STOP "$p" 2>/dev/null; then
        case "$frozen " in *" $p "*) ;; *) frozen="$frozen $p"; echo "frozen=$p" ;; esac
      elif [ -d "$d" ]; then
        stuck=1
      fi
    done
    [ -z "$left" ] && { echo quiesced; return 0; }
    [ -z "$stuck" ] && [ "$n" -lt "$qticks" ] || break
    n=$((n+1))
    sleep 0.1
  done
  [ -z "$frozen" ] || kill -CONT $frozen 2>/dev/null
  echo unquiesced
  return 1
}
`

// quiesceTrap is flushTrap for a stop that must pause the guest first
// (quiesceFunc): endHarnessScript's $4 and $5 are quiesce's PROC and TICKS.
const quiesceTrap = "quiesce_proc=$4 quiesce_ticks=$5\n" +
	"trap 'quiesce \"$quiesce_proc\" \"$quiesce_ticks\"; /bin/sync && echo synced' EXIT\n"

// quiesceFlushScript pauses the guest ($1 PROC, $2 TICKS) and flushes its
// disk, for a stop whose harness exec failed or that has no harness.
const quiesceFlushScript = quiesceFunc + `quiesce "$1" "$2"
/bin/sync && echo synced
`

// thawScript lets the processes quiesceFunc stopped ($@) run again.
const thawScript = `kill -CONT "$@" 2>/dev/null; exit 0`

// endHarnessScript sends SIGTERM to the harness processes of the sandbox
// user and waits up to $2 tenths of a second for them to exit. A harness
// process is one whose executable, or one of whose first three arguments
// resolved (the launcher runs /usr/local/bin/<command>, a link into the
// install root; a script harness's interpreter runs a script there), lies
// under the install root $1. The harness's executable link is often not
// readable to the exec (a process that is not dumpable), its command line
// always is. It prints how it ended: "none", "exited" or "running".
//
// Before any of that it looks at the latest detached run in the run
// directory $3 (harness.RunDir) as `sandbox logs` does (harness.RunStateFunc,
// with mark: a run that has not ended is marked interrupted in latest.exit,
// a mark its runner keeps), and prints what it found: run=running (a live
// run the stop ends), run=exited with run_exit=<status>, or run=interrupted
// (the sandbox stopped under it before), and run_started=<epoch seconds>;
// nothing without a run.
const endHarnessScript = `root=$1; ticks=$2; runs=$3; self=$$; pids=
` + harness.RunStateFunc + `[ -z "$runs" ] || run_state "$runs" mark
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

// runProbeScript is endHarnessScript's look at the run on its own, run
// directory $1: a stop whose endHarnessScript exec failed before it said how
// the run stood asks again, so the run is still marked and its log kept.
const runProbeScript = harness.RunStateFunc + `run_state "$1" mark
`

// runProbeWait bounds runProbeScript.
const runProbeWait = 10 * time.Second

// harnessEnd is what endHarnessScript printed: how the harness ended
// (none, exited or running), whether the flush trap ran, whether quiesce
// paused the guest first and which processes it paused, and the latest
// detached run as the stop found it (State sandboxapi.RunNone without one).
type harnessEnd struct {
	Harness  string
	Synced   bool
	Quiesced bool
	Frozen   []string
	Run      harness.DetachedRun
}

// parseHarnessEnd reads endHarnessScript's (and quiesceFlushScript's)
// output.
func parseHarnessEnd(out []byte) harnessEnd {
	end := harnessEnd{Run: harness.ParseRun(out)}
	for _, tok := range strings.Fields(string(out)) {
		if pid, ok := strings.CutPrefix(tok, "frozen="); ok {
			end.Frozen = addGuestPID(end.Frozen, pid)
			continue
		}
		switch {
		case strings.Contains(tok, "="):
		case tok == "synced":
			end.Synced = true
		case tok == "quiesced":
			end.Quiesced = true
		case tok == "unquiesced":
		case end.Harness == "":
			end.Harness = tok
		}
	}
	return end
}

// addGuestPID adds pid, a guest process ID quiesce printed, to pids once.
func addGuestPID(pids []string, pid string) []string {
	if pid == "" || len(pid) > 10 || strings.Trim(pid, "0123456789") != "" || slices.Contains(pids, pid) {
		return pids
	}
	return append(pids, pid)
}

// answered is what the guest's exec said, for an error: its words without
// the process IDs quiesce paused.
func answered(out []byte) string {
	var said []string
	for _, tok := range strings.Fields(string(out)) {
		if !strings.HasPrefix(tok, "frozen=") {
			said = append(said, tok)
		}
	}
	return truncate(strings.Join(said, " "), 200)
}

// guestFlush is how a stop's flush of the sandbox's disk went: confirmed
// when it was confirmed or none was needed (a driver whose stop flushes);
// err why one that was tried was not; frozen the guest processes quiesce
// paused for it, which run again unless the VM stops (thawGuest).
type guestFlush struct {
	confirmed bool
	err       error
	frozen    []string
}

// endHarness asks a ready sandbox's harness to exit before the sandbox is
// stopped, so its end-of-session hook reaches DefenseClaw, and flushes the
// sandbox's disk when the driver's stop would not; with quiesce, it pauses
// the guest's processes before that flush (quiesceFunc), and the flush
// counts only once they are paused. It returns the latest detached run as
// it found it (State sandboxapi.RunNone: there is none, or the sandbox did
// not answer), whose log the stop keeps next: from what the script printed
// before an exec that failed (a slow flush cut short), or else from a look
// at the run of its own (probeRun); and how the flush went. It publishes
// nothing: only the stop knows whether it went ahead (stopWithFlush). A
// manual stop goes ahead without the flush and says so; an automatic
// legacy MicroVM stop requires it while the VM's network is closed.
func (m *Manager) endHarness(ctx context.Context, gw *Gateway, b *box, quiesce bool) (harness.DetachedRun, guestFlush) {
	none := harness.DetachedRun{State: sandboxapi.RunNone}
	m.mu.Lock()
	name, harnessName, driver := b.rec.Name, b.rec.Harness, b.rec.Driver
	ready := b.phase == audit.SandboxPhaseReady && !b.creating && !b.deleted && !b.retained
	tamper := b.tamperStop
	m.mu.Unlock()
	if !ready {
		return none, guestFlush{}
	}
	flush := stopLosesWrites(driver)
	quiesce = quiesce && flush
	spec, ok := harness.Get(harnessName)
	if !ok {
		if flush {
			return none, m.flushSandbox(ctx, gw, name, quiesce)
		}
		return none, guestFlush{confirmed: true}
	}
	ticks := int(harnessExitWait / (100 * time.Millisecond))
	// A tamper stop does not look at the run: its run directory is the
	// workload's, whose files can hold an open (a lease), and the stop keeps
	// no log of it anyway (keepRunLog).
	runs := harness.RunDir
	if tamper {
		runs = ""
	}
	script, budget, timeout := endHarnessScript, harnessExitBudget, harnessExitWait+3*time.Second
	argv := []string{"/bin/sh", "-c", "", "defenseclaw-end-harness", spec.InstallRoot(), strconv.Itoa(ticks), runs}
	switch {
	case quiesce:
		script = quiesceFunc + quiesceTrap + script
		budget, timeout = budget+flushWait+quiesceWait, timeout+flushWait+quiesceWait
		argv = append(argv, "/proc", strconv.Itoa(quiesceTicks))
	case flush:
		script, budget, timeout = flushTrap+script, budget+flushWait, timeout+flushWait
	}
	argv[2] = script
	execCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	// What the script printed before a failure still counts: a flush that
	// the exec's timeout cut short comes after the run's lines, and the
	// processes quiesce paused before it must run again if the VM does.
	streamed := &headBuffer{limit: harnessEndOutput}
	res, err := m.ownExec(execCtx, gw, name, argv,
		openshell.ExecOptions{Timeout: timeout, Attempts: 1, MaxOutputBytes: harnessEndOutput, Stdout: streamed})
	if err != nil {
		m.logf("sandbox %s: ask the harness to exit before the stop: %v", name, err)
		end := parseHarnessEnd(streamed.Bytes())
		run := end.Run
		if end.Harness == "" && run.State == sandboxapi.RunNone && !tamper {
			// The script did not get as far as saying whether there is a
			// run: ask on its own, so a run the stop ends is still marked
			// and its log kept.
			run = m.probeRun(ctx, gw, name)
		}
		if flush {
			// The flush matters more than the harness's goodbye: once more,
			// on its own.
			fl := m.flushSandbox(ctx, gw, name, quiesce)
			for _, pid := range end.Frozen {
				fl.frozen = addGuestPID(fl.frozen, pid)
			}
			return run, fl
		}
		return run, guestFlush{confirmed: true}
	}
	end := parseHarnessEnd(res.Stdout)
	if end.Harness == "running" {
		m.logf("sandbox %s: the harness did not exit within %s; stopping the sandbox under it", name, harnessExitWait)
	}
	fl := guestFlush{confirmed: true, frozen: end.Frozen}
	switch {
	case flush && !end.Synced:
		fl.confirmed, fl.err = false, fmt.Errorf("sync(1) did not finish (the sandbox answered %q)", answered(res.Stdout))
	case quiesce && !end.Quiesced:
		fl.confirmed, fl.err = false, fmt.Errorf("its processes could not all be paused for the flush (the sandbox answered %q)", answered(res.Stdout))
	}
	if fl.err != nil {
		m.logf("sandbox %s: flush its disk before the stop: %v", name, fl.err)
	}
	return end.Run, fl
}

// harnessEndOutput bounds what the exec of endHarnessScript keeps of its
// output: a few short lines, and a line for each guest process quiesce
// paused.
const harnessEndOutput = 64 << 10

// probeRun looks at a ready sandbox's latest detached run on its own
// (runProbeScript), for a stop whose endHarnessScript exec failed first.
func (m *Manager) probeRun(ctx context.Context, gw *Gateway, name string) harness.DetachedRun {
	ctx, cancel := context.WithTimeout(ctx, runProbeWait+5*time.Second)
	defer cancel()
	res, err := m.ownExec(ctx, gw, name, []string{"/bin/sh", "-c", runProbeScript, "defenseclaw-run-probe", harness.RunDir},
		openshell.ExecOptions{Timeout: runProbeWait, Attempts: 1, MaxOutputBytes: harnessEndOutput})
	if err != nil {
		m.logf("sandbox %s: look at its detached run before the stop: %v", name, err)
		return harness.DetachedRun{State: sandboxapi.RunNone}
	}
	return harness.ParseRun(res.Stdout)
}

// headBuffer keeps the first limit bytes written to it.
type headBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *headBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *headBuffer) Bytes() []byte { return b.buf.Bytes() }

// flushSandbox runs sync(1) in a ready sandbox before a stop its driver
// does not flush, after pausing the guest's processes with quiesce
// (quiesceFlushScript), and says how that went. The stop publishes the
// loss once OpenShell takes it (flushFailed).
func (m *Manager) flushSandbox(ctx context.Context, gw *Gateway, name string, quiesce bool) guestFlush {
	if !quiesce {
		ctx, cancel := context.WithTimeout(ctx, flushWait+5*time.Second)
		defer cancel()
		res, err := m.ownExec(ctx, gw, name, []string{"/bin/sync"}, openshell.ExecOptions{Timeout: flushWait, Attempts: 1, MaxOutputBytes: 256})
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("sync(1) exited with status %d", res.ExitCode)
		}
		if err != nil {
			m.logf("sandbox %s: flush its disk before the stop: %v", name, err)
		}
		return guestFlush{confirmed: err == nil, err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, flushWait+quiesceWait+5*time.Second)
	defer cancel()
	streamed := &headBuffer{limit: harnessEndOutput}
	res, err := m.ownExec(ctx, gw, name, []string{"/bin/sh", "-c", quiesceFlushScript, "defenseclaw-flush", "/proc", strconv.Itoa(quiesceTicks)},
		openshell.ExecOptions{Timeout: flushWait + quiesceWait, Attempts: 1, MaxOutputBytes: harnessEndOutput, Stdout: streamed})
	out := streamed.Bytes()
	if err == nil {
		out = res.Stdout
	}
	end := parseHarnessEnd(out)
	fl := guestFlush{frozen: end.Frozen}
	switch {
	case err != nil:
		fl.err = err
	case !end.Quiesced:
		fl.err = fmt.Errorf("its processes could not all be paused for the flush (the sandbox answered %q)", answered(out))
	case !end.Synced || res.ExitCode != 0:
		fl.err = fmt.Errorf("sync(1) did not finish (the sandbox answered %q)", answered(out))
	default:
		fl.confirmed = true
	}
	if fl.err != nil {
		m.logf("sandbox %s: flush its disk before the stop: %v", name, fl.err)
	}
	return fl
}

// thawGuest lets the guest processes quiesce paused run again, in a VM
// whose stop did not go ahead. A thaw that fails leaves them paused: the
// VM loses nothing, and its next stop flushes what they wrote.
func (m *Manager) thawGuest(ctx context.Context, gw *Gateway, name string, pids []string) {
	ctx, cancel := detached(ctx, thawWait+5*time.Second)
	defer cancel()
	argv := append([]string{"/bin/sh", "-c", thawScript, "defenseclaw-thaw"}, pids...)
	if _, err := m.ownExec(ctx, gw, name, argv, openshell.ExecOptions{Timeout: thawWait, Attempts: 1, MaxOutputBytes: 256}); err != nil {
		m.logf("sandbox %s: let its %d paused processes run again: %v", name, len(pids), err)
	}
}

// flushFailed says a stop went ahead without the flush: what the workload
// wrote since the last one may come back empty. Only a stop OpenShell
// took calls it: a stop that was refused or not made lost nothing.
func (m *Manager) flushFailed(name string, err error) {
	msg := "sandbox " + name + ": its disk could not be flushed before the stop; files written since the last flush may come back empty"
	m.logf("%s: %v", msg, err)
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "stop_unflushed", Message: msg})
}
