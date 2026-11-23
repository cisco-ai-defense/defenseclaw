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

// Tree is a started command held in a kill-on-close Job Object with every
// process it starts. It is the Start half of RunTree for a caller that waits
// on the command itself (a long-running server).
type Tree struct {
	mu  sync.Mutex
	job windows.Handle // 0 once Close ran
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
		resumeErr = resumeCapturedProcessByHandle(windows.Handle(handle))
	}); withErr != nil {
		resumeErr = withErr
	}
	if resumeErr != nil {
		_ = windows.TerminateJobObject(job, 1)
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
		_ = windows.TerminateJobObject(t.job, 1)
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
	// The members are opened before the job ends them: a terminated process
	// can leave the job's list before it has exited, so a list taken after
	// TerminateJobObject can miss one that still runs.
	members := openJobMembers(t.job)
	if windows.TerminateJobObject(t.job, 1) == nil {
		deadline := time.Now().Add(capturedTreeExitWait)
		for _, h := range members {
			_, _ = windows.WaitForSingleObject(h, uint32(max(time.Until(deadline), 0).Milliseconds()))
		}
	}
	for _, h := range members {
		windows.CloseHandle(h)
	}
	windows.CloseHandle(t.job)
	t.job = 0
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
