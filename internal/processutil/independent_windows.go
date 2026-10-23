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
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrChildBoundToJob reports that a child StartIndependent would start
// could not be proven to outlive the enclosing process job.
var ErrChildBoundToJob = errors.New("the child cannot be proven to outlive the enclosing process job")

// independentHost is what StartIndependent asks of Windows; tests replace it.
type independentHost struct {
	// jobLimits reads the limit flags of the job this process is in.
	jobLimits func() (uint32, error)
	// inJob reports whether process pid (0: this process) is in any job.
	inJob func(pid int) (bool, error)
	// probe creates path suspended with flags, reports whether that process
	// is in any job and ends it. The probe runs none of its code.
	probe func(path string, flags uint32) (bool, error)
	start func(*exec.Cmd) error
	stop  func(*exec.Cmd)
}

var windowsIndependentHost = independentHost{
	jobLimits: currentJobLimits,
	inJob:     processInAnyJob,
	probe:     probeIndependentJob,
	start:     (*exec.Cmd).Start,
	stop: func(cmd *exec.Cmd) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	},
}

// StartIndependent starts cmd detached (its own process group, no console)
// so that it outlives this process and a supervisor that closes this
// process's job: a recovery helper that must run if this process is killed.
// It sets cmd.SysProcAttr.CreationFlags.
//
//   - Outside any job nothing more is needed.
//   - In a job whose limits this process can read, the child breaks away
//     when the job allows it. A job that kills its members on close and
//     lets none go silently is refused (ErrChildBoundToJob) before
//     anything starts.
//   - When the job query fails otherwise (Access is denied for the
//     LocalSystem process of a one-shot scheduled task, GAP-0960; natively
//     that process is in no job), IsProcessInJob, which needs no access to
//     a job, decides. In no job nothing more is needed. In a job, suspended
//     probes of cmd's program, which run none of its code, find how a child
//     leaves it before cmd starts: first without CREATE_BREAKAWAY_FROM_JOB
//     (a job that lets its children go silently refuses that flag when it
//     does not also allow breakaway), then with it. A job neither probe
//     leaves starts nothing, and a started child that is still in a job is
//     stopped. Both are ErrChildBoundToJob, returned before the caller
//     changes anything.
func StartIndependent(cmd *exec.Cmd) error {
	return startIndependent(cmd, windowsIndependentHost)
}

func startIndependent(cmd *exec.Cmd, host independentHost) error {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	limits, queryErr := host.jobLimits()
	prove := false
	switch {
	case errors.Is(queryErr, windows.ERROR_INVALID_HANDLE):
		// This process is in no job.
	case queryErr == nil:
		if limits&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0 {
			flags |= windows.CREATE_BREAKAWAY_FROM_JOB
		} else if limits&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 &&
			limits&windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK == 0 {
			return fmt.Errorf("%w: the job kills its processes when it closes and allows no breakaway", ErrChildBoundToJob)
		}
	default:
		member, err := host.inJob(0)
		if err != nil {
			return fmt.Errorf("inspect the enclosing process job: %w", errors.Join(queryErr, err))
		}
		if member {
			if flags, err = independentFlagsByProbe(cmd, host, flags, queryErr); err != nil {
				return err
			}
			prove = true
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = flags
	if err := host.start(cmd); err != nil {
		if prove && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("%w: the job cannot be inspected (%v) and refuses breakaway", ErrChildBoundToJob, queryErr)
		}
		return err
	}
	if !prove {
		return nil
	}
	member, err := host.inJob(cmd.Process.Pid)
	if err == nil && !member {
		return nil
	}
	host.stop(cmd)
	if err != nil {
		return fmt.Errorf("%w: the started child's job could not be checked: %v", ErrChildBoundToJob, err)
	}
	return fmt.Errorf("%w: the started child is still in a job that cannot be inspected (%v)", ErrChildBoundToJob, queryErr)
}

// independentFlagsByProbe returns the creation flags with which a child of
// cmd's program is in no job, base first and then with
// CREATE_BREAKAWAY_FROM_JOB, or ErrChildBoundToJob when neither leaves the
// job. Nothing of cmd starts here.
func independentFlagsByProbe(cmd *exec.Cmd, host independentHost, base uint32, queryErr error) (uint32, error) {
	if cmd.Err != nil {
		return 0, cmd.Err
	}
	for _, flags := range []uint32{base, base | windows.CREATE_BREAKAWAY_FROM_JOB} {
		member, err := host.probe(cmd.Path, flags)
		switch {
		case err == nil && !member:
			return flags, nil
		case err == nil:
			// The child would stay in the job: try the next flags.
		case flags&windows.CREATE_BREAKAWAY_FROM_JOB != 0 && errors.Is(err, windows.ERROR_ACCESS_DENIED):
			// The job refuses the breakaway.
		default:
			return 0, fmt.Errorf("probe the enclosing process job: %w", err)
		}
	}
	return 0, fmt.Errorf("%w: the job cannot be inspected (%v), keeps its children and refuses breakaway", ErrChildBoundToJob, queryErr)
}

// probeIndependentJob creates path suspended with flags, reports whether
// that process is in any job and ends it before it runs any code.
func probeIndependentJob(path string, flags uint32) (bool, error) {
	application, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.EscapeArg(path))
	if err != nil {
		return false, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var info windows.ProcessInformation
	if err := windows.CreateProcess(application, commandLine, nil, nil, false,
		flags|windows.CREATE_SUSPENDED, nil, nil, &startup, &info); err != nil {
		return false, err
	}
	defer func() {
		_ = windows.TerminateProcess(info.Process, 1)
		_, _ = windows.WaitForSingleObject(info.Process, 5000)
		_ = windows.CloseHandle(info.Thread)
		_ = windows.CloseHandle(info.Process)
	}()
	return isProcessInAnyJob(info.Process)
}

func currentJobLimits() (uint32, error) {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.BasicLimitInformation.LimitFlags, err
}

// processInAnyJob asks IsProcessInJob with no job handle, which needs only
// PROCESS_QUERY_LIMITED_INFORMATION on the process, not access to its job.
func processInAnyJob(pid int) (bool, error) {
	process := windows.CurrentProcess()
	if pid != 0 {
		opened, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return false, err
		}
		defer windows.CloseHandle(opened)
		process = opened
	}
	return isProcessInAnyJob(process)
}

func isProcessInAnyJob(process windows.Handle) (bool, error) {
	var member int32
	ok, _, callErr := procIsProcessInJob.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&member)))
	if ok == 0 {
		return false, callErr
	}
	return member != 0, nil
}
