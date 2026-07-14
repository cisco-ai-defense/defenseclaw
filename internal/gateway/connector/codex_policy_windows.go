// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func codexSystemRequirementsPath() (string, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(programData, "OpenAI", "Codex", "requirements.toml"), nil
}

// startCodexAppServerTree starts the inspector suspended, assigns it to a
// kill-on-close Job Object, and resumes it only after assignment. This closes
// the cmd/npm-wrapper race where the direct process could otherwise create an
// escaping node/native descendant before DefenseClaw obtained tree ownership.
func startCodexAppServerTree(cmd *exec.Cmd) (func(), error) {
	return startCodexAppServerTreeObserved(cmd, nil)
}

func startCodexAppServerTreeObserved(cmd *exec.Cmd, afterStart func() error) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create app-server job: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("configure app-server job: %w", err)
	}

	originalCancel := cmd.Cancel
	cmd.Cancel = func() error {
		jobErr := windows.TerminateJobObject(job, 1)
		var processErr error
		if originalCancel != nil {
			processErr = originalCancel()
		} else if cmd.Process != nil {
			processErr = cmd.Process.Kill()
		}
		if jobErr != nil && !errors.Is(jobErr, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(jobErr, windows.ERROR_INVALID_HANDLE) {
			return errors.Join(jobErr, processErr)
		}
		return processErr
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	failStarted := func(primary error) (func(), error) {
		_ = windows.TerminateJobObject(job, 1)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		return nil, primary
	}
	if afterStart != nil {
		if err := afterStart(); err != nil {
			return failStarted(fmt.Errorf("observe suspended app-server process: %w", err))
		}
	}
	var assignJobErr error
	assignErr := cmd.Process.WithHandle(func(handle uintptr) {
		assignJobErr = windows.AssignProcessToJobObject(job, windows.Handle(handle))
	})
	if assignErr == nil {
		assignErr = assignJobErr
	}
	if assignErr != nil {
		return failStarted(fmt.Errorf("assign app-server process to job: %w", assignErr))
	}
	if err := resumeSuspendedCodexProcess(cmd.Process.Pid); err != nil {
		return failStarted(fmt.Errorf("resume assigned app-server process: %w", err))
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			_ = windows.TerminateJobObject(job, 1)
			// Closing the kill-on-close job before Wait is the final tree-wide
			// guarantee even if explicit termination was denied or raced exit.
			_ = windows.CloseHandle(job)
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		})
	}, nil
}

func resumeSuspendedCodexProcess(pid int) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("snapshot process threads: %w", err)
	}
	defer windows.CloseHandle(snapshot) //nolint:errcheck

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return fmt.Errorf("enumerate process threads: %w", err)
	}
	for {
		if entry.OwnerProcessID == uint32(pid) {
			thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return fmt.Errorf("open suspended primary thread %d: %w", entry.ThreadID, err)
			}
			previous, resumeErr := windows.ResumeThread(thread)
			closeErr := windows.CloseHandle(thread)
			if resumeErr != nil {
				return fmt.Errorf("resume primary thread %d: %w", entry.ThreadID, resumeErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close primary thread %d: %w", entry.ThreadID, closeErr)
			}
			if previous != 1 {
				return fmt.Errorf("primary thread %d had unexpected suspend count %d (want 1)", entry.ThreadID, previous)
			}
			return nil
		}
		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return fmt.Errorf("enumerate process threads: %w", err)
		}
	}
	return fmt.Errorf("primary thread for process %d was not found", pid)
}
