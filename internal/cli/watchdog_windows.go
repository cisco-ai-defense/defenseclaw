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

//go:build windows

package cli

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// watchdogShutdownSignals returns the OS signals that stop the foreground
// watchdog loop. Windows supports interrupt/terminate delivery through os/signal.
func watchdogShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// watchdogStartDir keeps the current working directory on Windows. "/" is not
// a stable process directory across Windows shells and drives.
func watchdogStartDir() string {
	return ""
}

// watchdogSysProcAttr returns a SysProcAttr for Windows. Setsid is a Unix
// concept; on Windows we return a zero-value struct which lets os.StartProcess
// use default process creation flags.
func watchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func watchdogProcessAlive(pid int, _ *os.Process) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

func watchdogTerminate(proc *os.Process) error {
	return proc.Kill()
}

func watchdogKill(proc *os.Process) error {
	return proc.Kill()
}
