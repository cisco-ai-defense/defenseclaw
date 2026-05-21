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

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// watchdogShutdownSignals returns the OS signals that stop the foreground
// watchdog loop.
func watchdogShutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}

// watchdogStartDir returns the detached watchdog working directory.
func watchdogStartDir() string {
	return "/"
}

// watchdogSysProcAttr returns a SysProcAttr that starts the watchdog child in
// a new session (Setsid), detaching it from the parent's controlling terminal.
func watchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func watchdogProcessAlive(_ int, proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

func watchdogTerminate(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

func watchdogKill(proc *os.Process) error {
	return proc.Signal(syscall.SIGKILL)
}
