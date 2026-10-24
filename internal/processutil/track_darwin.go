// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package processutil

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	trackDarwinArg0 = "defenseclaw-tracked-run"
	trackDarwinEnv  = "DEFENSECLAW_TRACKED_RUN_SUPERVISOR"
	// containExitTerminated: the supervisor was told to end (cancellation or
	// the death of the gateway) and ended everything.
	containExitTerminated = 124
	// containExitNotStarted: the command could not start.
	containExitNotStarted = 127
	// trackReportFD is where the supervisor reports each process it adopts
	// and, last, whether it ended them all.
	trackReportFD = 3
	// darwinStopped is SSTOP in <sys/proc.h>.
	darwinStopped = 4
)

// trackSweepBudget bounds the final kill: every tracked process must be
// gone within it, or the run is not contained.
var trackSweepBudget = 2 * time.Second

// trackWaitDelay bounds the wait for the command's streams after the
// supervisor has exited, when the caller set no WaitDelay.
const trackWaitDelay = 5 * time.Second

// trackPoll bounds each kqueue wait. The process table is read after every
// wait, so a fork whose notification was missed is still found.
const trackPoll = 100 * time.Millisecond

func init() {
	if len(os.Args) < 5 || os.Args[0] != trackDarwinArg0 || os.Args[3] != "--" ||
		os.Getenv(trackDarwinEnv) != "1" {
		return
	}
	budget, err := time.ParseDuration(os.Args[1])
	if err != nil || budget < 0 {
		os.Exit(containExitNotContained)
	}
	os.Exit(superviseTracked(os.Args[2], os.Args[4:], budget))
}

// runTracked starts a supervisor, a short-lived copy of this binary in a
// process group of its own, which starts the command and follows it. The
// supervisor, not the gateway, owns the tree: it sees the gateway die
// through kqueue and ends the tree then too. It reports each process it
// adopts, so if it dies itself the gateway ends them.
func runTracked(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunTracked: already started")
	}
	if len(cmd.ExtraFiles) > 0 {
		return errors.New("processutil: RunTracked: ExtraFiles are not passed to the command")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: locate process supervisor: %v", ErrNotContained, err)
	}
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("%w: supervisor report pipe: %v", ErrNotContained, err)
	}
	defer reportRead.Close()
	target := cmd.Path
	cmd.Path = self
	cmd.Args = append([]string{trackDarwinArg0, trackSweepBudget.String(), target, "--"}, cmd.Args...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, trackDarwinEnv), trackDarwinEnv+"=1")
	cmd.ExtraFiles = []*os.File{reportWrite}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Its own group: a kill of the gateway's group (launchd stopping the
	// job) leaves the supervisor alive to end the tree.
	cmd.SysProcAttr.Setpgid = true
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = trackWaitDelay
	}
	err = cmd.Start()
	_ = reportWrite.Close()
	if err != nil {
		return err
	}
	reports := make(chan trackReport, 1)
	go func() { reports <- readTrackReport(reportRead) }()
	// Wait for the supervisor without reaping it and before cmd.Wait: the
	// tree may hold the command's streams, and Wait would wait for them.
	if !waitExitedUnreaped(cmd.Process.Pid) {
		_ = cmd.Process.Kill()
	}
	report := <-reports
	if !report.done {
		// The supervisor died (killed or crashed) before it ended the tree.
		_ = report.tracker().killAll(trackSweepBudget)
		_ = cmd.Wait()
		return fmt.Errorf("%w: supervisor of %s ended without ending its tree", ErrNotContained, target)
	}
	err = cmd.Wait()
	if !report.contained {
		return fmt.Errorf("%w: %s", ErrNotContained, target)
	}
	return err
}

// trackReport is what the supervisor wrote: "proc <pid> <sec> <usec>" for
// each process it adopted, then "done 1" when it ended every one of them or
// "done 0" when it could not.
type trackReport struct {
	procs     map[int32]unix.Timeval
	done      bool
	contained bool
}

func readTrackReport(r io.Reader) trackReport {
	report := trackReport{procs: map[int32]unix.Timeval{}}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch {
		case len(fields) == 4 && fields[0] == "proc":
			pid, err1 := strconv.ParseInt(fields[1], 10, 32)
			sec, err2 := strconv.ParseInt(fields[2], 10, 64)
			usec, err3 := strconv.ParseInt(fields[3], 10, 32)
			if err1 == nil && err2 == nil && err3 == nil && pid > 1 {
				report.procs[int32(pid)] = unix.Timeval{Sec: sec, Usec: int32(usec)}
			}
		case len(fields) == 2 && fields[0] == "done":
			report.done, report.contained = true, fields[1] == "1"
		}
	}
	if scanner.Err() != nil {
		report.done = false
	}
	return report
}

// tracker follows the reported processes again, from the gateway.
func (r trackReport) tracker() *processTracker {
	t := &processTracker{kq: -1, procs: map[int32]unix.Timeval{}, ids: map[int32]bool{}}
	for pid, start := range r.procs {
		t.procs[pid] = start
		t.ids[pid] = true
	}
	return t
}

func superviseTracked(target string, argv []string, budget time.Duration) int {
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	report := os.NewFile(trackReportFD, "supervisor report")
	if report == nil {
		return containExitNotContained
	}
	unix.CloseOnExec(trackReportFD)
	done := func(contained bool, code int) int {
		flag := "0"
		if contained {
			flag = "1"
		}
		_, _ = fmt.Fprintf(report, "done %s\n", flag)
		_ = report.Close()
		return code
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return done(false, containExitNotContained)
	}
	defer unix.Close(kq)
	gateway := os.Getppid()
	if gateway == 1 || watchProcess(kq, gateway, unix.NOTE_EXIT) != nil || os.Getppid() != gateway {
		// The gateway died before its death could be watched. Nothing ran.
		return done(true, containExitTerminated)
	}
	lifeRead, lifeWrite, err := os.Pipe()
	if err != nil {
		return done(false, containExitNotContained)
	}
	defer lifeRead.Close()
	child := exec.Command(target)
	child.Args = argv
	child.Env = withoutEnv(os.Environ(), trackDarwinEnv)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	// The lifeline every descendant inherits unless it closes it.
	child.ExtraFiles = []*os.File{lifeWrite}
	// A session of its own: only the command's descendants can be in it or
	// in its groups.
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return done(true, containExitNotStarted)
	}
	_ = lifeWrite.Close()
	leader := child.Process.Pid
	tracker := &processTracker{
		kq:     kq,
		leader: leader,
		procs:  map[int32]unix.Timeval{},
		ids:    map[int32]bool{int32(leader): true},
		report: func(pid int32, start unix.Timeval) {
			_, _ = fmt.Fprintf(report, "proc %d %d %d\n", pid, start.Sec, start.Usec)
		},
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", leader)
	if err != nil || info.Proc.P_pid != int32(leader) {
		_ = unix.Kill(-leader, unix.SIGKILL)
		_ = child.Wait()
		return done(false, containExitNotContained)
	}
	tracker.adopt(info, int(info.Eproc.Pgid), leader)
	// Only the command and what it started hold its streams now, so the
	// gateway's pipes close when they are gone.
	releaseStdio()
	terminated, followed := tracker.follow(gateway, terms)
	if !tracker.killAll(budget) || !followed {
		// The leader may be one this process cannot kill; do not wait for it.
		return done(false, containExitNotContained)
	}
	waitErr := child.Wait()
	select {
	case <-terms:
		terminated = true
	default:
	}
	if terminated {
		return done(true, containExitTerminated)
	}
	if !lifelineClosed(lifeRead, lifelineWait) {
		// Something the command started holds the lifeline but was not
		// followed: it outlived the kill.
		return done(false, containExitNotContained)
	}
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		return done(true, 0)
	case errors.As(waitErr, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return done(true, 128+int(status.Signal()))
		}
		return done(true, exitErr.ExitCode())
	default:
		return done(false, containExitNotContained)
	}
}

// processTracker follows a command's process tree on macOS, which has no
// subreaper, cgroup or parent-death signal. Every tracked process is watched
// with kqueue NOTE_FORK and NOTE_EXIT; each notification, and each poll,
// reads the process table and adopts every process that is a child of a
// running tracked process or is in a group or session a tracked process
// belongs to or leads. Only the command's descendants can join its session
// and groups. A group or session id is forgotten once nothing uses it, so a
// reused PID cannot bring an unrelated process in, and a tracked PID is
// only killed while its start time matches.
type processTracker struct {
	kq     int
	leader int
	// procs maps a tracked PID to its start time.
	procs map[int32]unix.Timeval
	// ids holds the groups and sessions of tracked processes and the PIDs
	// of tracked processes, which lead any group or session they create.
	ids map[int32]bool
	// table is the last process table read: PID to entry.
	table map[int32]*unix.KinfoProc
	// report is told about each adopted process.
	report func(pid int32, start unix.Timeval)
}

// watchProcess registers EVFILT_PROC fflags for pid. ESRCH means the
// process is gone; callers that need it alive check.
func watchProcess(kq, pid int, fflags uint32) error {
	change := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD,
		Fflags: fflags,
	}
	for {
		_, err := unix.Kevent(kq, []unix.Kevent_t{change}, nil, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// follow tracks the tree until the leader exits, the gateway dies or the
// supervisor is told to end. followed is false when the process table could
// not be read.
func (t *processTracker) follow(gateway int, terms <-chan os.Signal) (terminated, followed bool) {
	events := make([]unix.Kevent_t, 32)
	poll := unix.NsecToTimespec(trackPoll.Nanoseconds())
	for {
		n, err := unix.Kevent(t.kq, nil, events, &poll)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return terminated, false
		}
		for i := 0; i < n; i++ {
			if events[i].Fflags&unix.NOTE_EXIT != 0 && int(events[i].Ident) == gateway {
				terminated = true
			}
		}
		if _, err := t.sweep(); err != nil {
			return terminated, false
		}
		select {
		case <-terms:
			terminated = true
		default:
		}
		if os.Getppid() != gateway {
			terminated = true
		}
		if terminated || !t.running(int32(t.leader)) {
			return terminated, true
		}
	}
}

// killAll stops every tracked process, reads the table again until a read
// adopts nothing new and every tracked process is stopped, and only then
// kills them. A stopped process cannot fork, so no parent dies with a child
// the tracker has not seen. It reports whether none is left running.
func (t *processTracker) killAll(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		adopted, err := t.sweep()
		if err == nil {
			running := t.runningPIDs()
			if len(running) == 0 {
				return true
			}
			stopped := !adopted
			for _, pid := range running {
				if t.table[pid].Proc.P_stat != darwinStopped {
					stopped = false
					_ = unix.Kill(int(pid), unix.SIGSTOP)
				}
			}
			if stopped {
				for _, pid := range running {
					_ = unix.Kill(int(pid), unix.SIGKILL)
				}
			}
		} else if t.leader > 0 {
			// The leader is this process's unreaped child, so its group
			// cannot have been reused.
			_ = unix.Kill(-t.leader, unix.SIGKILL)
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// running reports whether pid is tracked and, in the last table read, the
// same process and not a zombie.
func (t *processTracker) running(pid int32) bool {
	start, ok := t.procs[pid]
	p := t.table[pid]
	return ok && p != nil && p.Proc.P_starttime == start && p.Proc.P_stat != darwinZombie
}

func (t *processTracker) runningPIDs() []int32 {
	var pids []int32
	for pid := range t.procs {
		if t.running(pid) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (t *processTracker) adopt(p *unix.KinfoProc, pgid, sid int) {
	pid := p.Proc.P_pid
	t.procs[pid] = p.Proc.P_starttime
	t.ids[pid], t.ids[int32(pgid)] = true, true
	if sid > 0 {
		t.ids[int32(sid)] = true
	}
	if t.kq >= 0 {
		_ = watchProcess(t.kq, int(pid), unix.NOTE_EXIT|unix.NOTE_FORK)
	}
	if t.report != nil {
		t.report(pid, p.Proc.P_starttime)
	}
}

// sweep reads the process table and adopts what belongs to the tree. It
// reports whether it adopted a process.
func (t *processTracker) sweep() (bool, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return false, err
	}
	t.table = make(map[int32]*unix.KinfoProc, len(procs))
	inUse := make(map[int32]bool, len(procs))
	for i := range procs {
		t.table[procs[i].Proc.P_pid] = &procs[i]
		inUse[procs[i].Eproc.Pgid] = true
	}
	// An id no group uses and no running tracked process leads or is in can
	// be reused by an unrelated process; forget it.
	for pid := range t.procs {
		if t.running(pid) {
			inUse[pid] = true
			if sid, err := unix.Getsid(int(pid)); err == nil {
				inUse[int32(sid)] = true
			}
		}
	}
	for id := range t.ids {
		if !inUse[id] {
			delete(t.ids, id)
		}
	}
	adopted := false
	for again := true; again; {
		again = false
		for i := range procs {
			p := &procs[i]
			pid := p.Proc.P_pid
			if p.Proc.P_stat == darwinZombie || t.running(pid) || int(pid) == os.Getpid() {
				continue
			}
			sid := -1
			if !t.running(p.Eproc.Ppid) && !t.ids[p.Eproc.Pgid] {
				s, err := unix.Getsid(int(pid))
				if err != nil || !t.ids[int32(s)] {
					continue
				}
				sid = s
			} else if s, err := unix.Getsid(int(pid)); err == nil {
				sid = s
			}
			t.adopt(p, int(p.Eproc.Pgid), sid)
			adopted, again = true, true
		}
	}
	return adopted, nil
}

func releaseStdio() {
	null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	for fd := 0; fd <= 2; fd++ {
		_ = unix.Dup2(null, fd)
	}
	_ = unix.Close(null)
}
