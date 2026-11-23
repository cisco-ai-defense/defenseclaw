// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// treeResume and treeTerminate are the two calls StartTree makes through the
// OS that a test replaces to make them fail (GAP-1017).
var (
	treeResume    = resumeCapturedProcessByHandle
	treeTerminate = windows.TerminateJobObject
)

// Tree is a started command held in a kill-on-close Job Object with every
// process it starts. It is the Start half of RunTree for a caller that waits
// on the command itself (a long-running server).
type Tree struct {
	mu      sync.Mutex
	job     windows.Handle   // 0 once Close ran
	members []windows.Handle // wait handles opened before the job ended its processes
	ended   bool             // the job was told to terminate its processes
}

// StartTree starts cmd inside a new kill-on-close Job Object. The command is
// created suspended, assigned to the job and only then resumed, so it cannot
// start a process outside the job. If this process ends without Close (a
// crash, TerminateProcess), Windows closes the job handle and ends the tree.
// cmd must not have been started; the caller still calls cmd.Wait, then
// Close. An error from cmd.Start is returned as is; when the job cannot hold
// or resume the command, it is killed and waited for before StartTree
// returns.
func StartTree(cmd *exec.Cmd) (*Tree, error) {
	job, err := createCapturedProcessJob(false)
	if err != nil {
		return nil, err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	var assignErr error
	if withErr := cmd.Process.WithHandle(func(handle uintptr) {
		assignErr = windows.AssignProcessToJobObject(job, windows.Handle(handle))
	}); withErr != nil {
		assignErr = withErr
	}
	if assignErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		return nil, fmt.Errorf("assign the process to its kill-on-close job: %w", assignErr)
	}
	// One call through the process handle, not RunTree's system-wide thread
	// snapshot: a bridge opens on every shim start, and the snapshot cost
	// milliseconds. Either way each thread is resumed once.
	var resumeErr error
	if withErr := cmd.Process.WithHandle(func(handle uintptr) {
		resumeErr = treeResume(windows.Handle(handle))
	}); withErr != nil {
		resumeErr = withErr
	}
	if resumeErr != nil {
		// As runTree does: end the job, then the direct process by its own
		// handle, so a failed job terminate cannot leave it suspended and
		// block cmd.Wait.
		_ = treeTerminate(job, 1)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		return nil, resumeErr
	}
	return &Tree{job: job}, nil
}

// Kill ends every process in the tree at once. It returns before they have
// exited; after Close it does nothing.
func (t *Tree) Kill() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job != 0 {
		t.end()
	}
}

// Close ends whatever the command left running, waits (bounded) until those
// processes have exited and releases the job. Call it once cmd.Wait has
// returned; later calls do nothing.
func (t *Tree) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job == 0 {
		return
	}
	t.end()
	if t.ended {
		t.waitGone(time.Now().Add(capturedTreeExitWait))
	}
	for _, h := range t.members {
		windows.CloseHandle(h)
	}
	t.members = nil
	windows.CloseHandle(t.job)
	t.job = 0
}

// end terminates the job's processes once. The members are opened first: a
// terminated process leaves the job's list and its active count before it has
// exited, so Close, which runs after Kill, would find nothing to wait on and
// the presence record would go while the last process was still exiting
// (GAP-1016). The caller holds t.mu.
func (t *Tree) end() {
	if t.ended {
		return
	}
	t.members = append(t.members, openJobMembers(t.job)...)
	t.ended = treeTerminate(t.job, 1) == nil
}

// waitGone waits until every member opened by end has exited and the job has
// no active process, which also covers one that started after the members
// were listed. It stops at deadline: a member with pending I/O in a driver can
// stay unsignalled indefinitely.
func (t *Tree) waitGone(deadline time.Time) {
	for _, h := range t.members {
		_, _ = windows.WaitForSingleObject(h, uint32(max(time.Until(deadline), 0).Milliseconds()))
	}
	for time.Now().Before(deadline) {
		var info jobAccounting
		if err := windows.QueryInformationJobObject(t.job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil || info.ActiveProcesses == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// jobAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, which
// golang.org/x/sys/windows does not define.
type jobAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// openJobMembers opens a wait handle to every process now in job.
func openJobMembers(job windows.Handle) []windows.Handle {
	ids, err := capturedJobProcessIDs(job)
	if err != nil {
		return nil
	}
	var hs []windows.Handle
	for _, id := range ids {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(id))
		if err != nil {
			continue // already gone
		}
		// A listed ID can be reused once its process exits; keep only a
		// process that is still a member of this job.
		var member int32
		if ok, _, _ := procIsProcessInJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&member))); ok == 0 || member == 0 {
			windows.CloseHandle(h)
			continue
		}
		hs = append(hs, h)
	}
	return hs
}
