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
// would end with the enclosing process job: the job kills its processes when
// it closes and lets none break away.
var ErrChildBoundToJob = errors.New("the child cannot outlive the enclosing process job")

// independentHost is what StartIndependent asks of Windows; tests replace it.
type independentHost struct {
	// jobLimits reads the limit flags of the job this process is in.
	jobLimits func() (uint32, error)
	// inJob reports whether this process is in any job.
	inJob func() (bool, error)
	// breakawayAccepted reports whether the enclosing job lets path start
	// with CREATE_BREAKAWAY_FROM_JOB.
	breakawayAccepted func(path string) bool
	start             func(*exec.Cmd) error
}

var windowsIndependentHost = independentHost{
	jobLimits:         currentJobLimits,
	inJob:             func() (bool, error) { return processInAnyJob(0) },
	breakawayAccepted: breakawayAccepted,
	start:             (*exec.Cmd).Start,
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
//   - A job whose limits cannot be read (Access is denied for the
//     LocalSystem process of a one-shot scheduled task, GAP-0960) is
//     unknown, not refused: the caller has recorded what the helper would
//     finish. IsProcessInJob, which needs no access to the job, says
//     whether there is one. In no job nothing more is needed. In a job, or
//     when that is unknown too, the child breaks away when the job accepts
//     the flag, and otherwise starts in the job.
func StartIndependent(cmd *exec.Cmd) error {
	return startIndependent(cmd, windowsIndependentHost)
}

func startIndependent(cmd *exec.Cmd, host independentHost) error {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	limits, queryErr := host.jobLimits()
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
		if member, err := host.inJob(); (err != nil || member) && host.breakawayAccepted(cmd.Path) {
			flags |= windows.CREATE_BREAKAWAY_FROM_JOB
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = flags
	return host.start(cmd)
}

// breakawayAccepted starts path suspended with CREATE_BREAKAWAY_FROM_JOB and
// ends it before it runs: a job that allows no breakaway refuses the flag
// when the process is created (Access is denied). cmd itself cannot be
// started twice once its pipes are made, so the job is asked first. The
// probe inherits no handle (three empty standard handles).
func breakawayAccepted(path string) bool {
	_, handle, err := syscall.StartProcess(path, []string{path}, &syscall.ProcAttr{
		Files: []uintptr{0, 0, 0},
		Sys: &syscall.SysProcAttr{
			CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_BREAKAWAY_FROM_JOB |
				windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		},
	})
	if err != nil {
		return false
	}
	process := windows.Handle(handle)
	_ = windows.TerminateProcess(process, 1)
	_ = windows.CloseHandle(process)
	return true
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
	var member int32
	ok, _, callErr := procIsProcessInJob.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&member)))
	if ok == 0 {
		return false, callErr
	}
	return member != 0, nil
}
