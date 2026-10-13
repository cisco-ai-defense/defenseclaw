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

//go:build windows

package processutil

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureCapturedCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
	cmd.SysProcAttr.HideWindow = true
}

const capturedTreeWaitDelay = 2 * time.Second

// capturedTreeExitWait bounds the wait for terminated job members to finish
// kernel teardown. Teardown normally takes milliseconds; the bound only keeps
// a member that never becomes signalled from hanging the caller.
const capturedTreeExitWait = 10 * time.Second

func capturedJobLimitFlags(allowManagedBreakaway bool) uint32 {
	flags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if allowManagedBreakaway {
		flags |= windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	}
	return flags
}

func createCapturedProcessJob(allowManagedBreakaway bool) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create captured-process job: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = capturedJobLimitFlags(allowManagedBreakaway)
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("configure captured-process job: %w", err)
	}
	return job, nil
}

func resumeCapturedProcess(pid uint32) error {
	// syscall.StartProcess closes PROCESS_INFORMATION.hThread before returning,
	// so recover the sole CREATE_SUSPENDED primary thread by PID. The snapshot
	// retry is bounded and occurs before any child instruction can execute.
	deadline := time.Now().Add(capturedTreeWaitDelay)
	for {
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
		if err != nil {
			return fmt.Errorf("snapshot captured-process threads: %w", err)
		}
		var entry windows.ThreadEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Thread32First(snapshot, &entry)
		for err == nil {
			if entry.OwnerProcessID == pid {
				thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
				if openErr == nil {
					previous, resumeErr := windows.ResumeThread(thread)
					windows.CloseHandle(thread)
					windows.CloseHandle(snapshot)
					if resumeErr != nil {
						return fmt.Errorf("resume captured-process primary thread: %w", resumeErr)
					}
					if previous != 1 {
						return fmt.Errorf("captured-process primary thread suspend count was %d, want 1", previous)
					}
					return nil
				}
			}
			err = windows.Thread32Next(snapshot, &entry)
		}
		windows.CloseHandle(snapshot)
		if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return fmt.Errorf("enumerate captured-process threads: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("captured-process primary thread was not visible within %s", capturedTreeWaitDelay)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// capturedJobProcessIDHeader is the fixed head of
// JOBOBJECT_BASIC_PROCESS_ID_LIST; first marks where the ID array starts.
type capturedJobProcessIDHeader struct {
	assigned uint32
	listed   uint32
	first    uintptr
}

// capturedJobProcessIDs lists every process currently assigned to job,
// growing the buffer from NumberOfAssignedProcesses on ERROR_MORE_DATA so a
// large tree is never truncated.
func capturedJobProcessIDs(job windows.Handle) ([]uintptr, error) {
	const word = unsafe.Sizeof(uintptr(0))
	head := int(unsafe.Offsetof(capturedJobProcessIDHeader{}.first) / word)
	capacity := 64
	for {
		buffer := make([]uintptr, head+capacity)
		err := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicProcessIdList,
			uintptr(unsafe.Pointer(&buffer[0])),
			uint32(uintptr(len(buffer))*word),
			nil,
		)
		header := (*capturedJobProcessIDHeader)(unsafe.Pointer(&buffer[0]))
		if err == nil {
			return buffer[head : head+min(int(header.listed), capacity)], nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		capacity = max(2*capacity, int(header.assigned)+16)
	}
}

// waitCapturedJobExited blocks until the processes TerminateJobObject is
// ending have exited. TerminateJobObject only starts termination; a process
// releases its handles before its process object is signalled, so after this
// returns no terminated descendant still holds the captured output pipes and
// cmd.Wait reaches EOF without racing WaitDelay.
//
// Every listed process is already being force-terminated and runs no more
// user code, so only kernel teardown remains. That normally takes
// milliseconds, but a member with pending redirector I/O or an IRP held by a
// filter driver can stay unsignalled indefinitely, so the whole drain shares
// one deadline. On timeout it returns nil and cmd.Wait's WaitDelay bounds
// the rest.
func waitCapturedJobExited(job windows.Handle, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	ids, err := capturedJobProcessIDs(job)
	if err != nil {
		return fmt.Errorf("list captured process tree: %w", err)
	}
	for _, id := range ids {
		process, openErr := windows.OpenProcess(
			windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
			false,
			uint32(id),
		)
		if openErr != nil {
			continue // already gone
		}
		// A listed ID can be reused once its process exits; wait only on a
		// process that is still a member of this job.
		var member int32
		ok, _, _ := procIsProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
		var waitErr error
		timedOut := false
		if ok != 0 && member != 0 {
			remaining := max(time.Until(deadline), 0)
			var result uint32
			result, waitErr = windows.WaitForSingleObject(process, uint32(remaining.Milliseconds()))
			timedOut = waitErr == nil && result == uint32(windows.WAIT_TIMEOUT)
		}
		windows.CloseHandle(process)
		if waitErr != nil {
			return fmt.Errorf("wait for captured process tree exit: %w", waitErr)
		}
		if timedOut {
			return nil // cmd.Wait's WaitDelay bounds the remaining pipe drain
		}
	}
	return nil
}

func combinedOutputTree(cmd *exec.Cmd, allowManagedBreakaway bool) ([]byte, error) {
	if cmd.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	if cmd.Stderr != nil {
		return nil, errors.New("exec: Stderr already set")
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := runTree(cmd, allowManagedBreakaway)
	return output.Bytes(), err
}

// runTree runs cmd, with the streams the caller set, inside a kill-on-close
// Job Object: cancellation, completion and the death of this process end
// every non-breakaway descendant.
func runTree(cmd *exec.Cmd, allowManagedBreakaway bool) error {
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = capturedTreeWaitDelay
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// The initial thread cannot create a descendant until the kill-on-close job
	// owns the direct child. This closes the Start/Assign escape window.
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	job, err := createCapturedProcessJob(allowManagedBreakaway)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)

	originalCancel := cmd.Cancel
	cmd.Cancel = func() error {
		jobErr := windows.TerminateJobObject(job, 1)
		var processErr error
		if originalCancel != nil {
			processErr = originalCancel()
		} else if cmd.Process != nil {
			processErr = cmd.Process.Kill()
		}
		if jobErr != nil {
			return errors.Join(jobErr, processErr)
		}
		return processErr
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	var jobAssignErr error
	assignErr := cmd.Process.WithHandle(func(handle uintptr) {
		jobAssignErr = windows.AssignProcessToJobObject(job, windows.Handle(handle))
	})
	if assignErr == nil {
		assignErr = jobAssignErr
	}
	if assignErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("assign captured process to kill-on-close job: %w", assignErr)
	}
	if err := resumeCapturedProcess(uint32(cmd.Process.Pid)); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}

	// Wait for the direct process handle rather than cmd.Wait so inherited pipe
	// handles cannot delay tree cleanup. cmd.Wait can finish copying output once
	// terminating the job closes every non-breakaway descendant's handles.
	var directWaitErr error
	handleErr := cmd.Process.WithHandle(func(handle uintptr) {
		result, err := windows.WaitForSingleObject(windows.Handle(handle), windows.INFINITE)
		if err != nil {
			directWaitErr = err
			return
		}
		if result != windows.WAIT_OBJECT_0 {
			directWaitErr = fmt.Errorf("unexpected wait result %#x", result)
		}
	})
	if handleErr != nil {
		directWaitErr = errors.Join(directWaitErr, handleErr)
	}

	// Reap descendants that did not exit with the direct command. A managed
	// daemon can survive only by explicitly breaking away from the permitted job.
	jobErr := windows.TerminateJobObject(job, 1)
	if jobErr == nil {
		jobErr = waitCapturedJobExited(job, capturedTreeExitWait)
	}
	waitErr := cmd.Wait()
	if directWaitErr != nil {
		directWaitErr = fmt.Errorf("wait for captured process exit: %w", directWaitErr)
	}
	if jobErr != nil {
		jobErr = fmt.Errorf("terminate captured process tree: %w", jobErr)
	}
	if directWaitErr == nil && jobErr == nil {
		return waitErr
	}
	return errors.Join(waitErr, directWaitErr, jobErr)
}
